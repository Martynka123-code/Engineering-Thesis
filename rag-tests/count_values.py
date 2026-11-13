"""Step 4: counting values for each unicast group and for the whole capture.

Input: the full table in the schema (steps 1-2) and the list of groups (step 3).
Output: a dictionary with these parts:

    "capture"   values for the whole capture (always computed, once)
    "groups"    list of values, one set per unicast group
    "skipped"   skipped groups (broadcast and unknown), for the message only
    "status"    "attack"        there is at least one unicast group
                "clean"         no groups at all (clean traffic)
                "only_skipped"  there are groups, but only skipped ones

Rules for filling in the fields:

    - number (including 0)   the counter could be computed
    - "not applicable"       the field needs a reference point that does not exist
    - "unknown"              data traffic after the attack, when the capture is cut off at the end

PMF (whether the network protects management frames) - computed once, for the
whole capture (a capture contains one network), in this order:

    1. there is a protected management frame 10 / 12 / 13     -> "yes"
    2. there is a management frame 0 / 2 / 5 / 8 with mfpc = 1 -> "yes"
    3. there are 0 / 2 / 5 / 8 frames with mfpc, all mfpc = 0  -> "no"
    4. none of the above                                       -> "undetermined"

Unprotected management frames never give "no": in a network with PMF, genuine
broadcast frames (BIP) and the attacker's frames are unprotected too.

Time: all time conditions are differences between two ts values from the same
table. pcap has ts from frame.time_epoch, CSV from frame.time_relative; in both
cases the start of the capture is the smallest ts and the end is the largest.

Running from the terminal (the whole file is read):

    python count_values.py "capture.pcap"
    python count_values.py dataset_file.csv
"""

import argparse

import pandas as pd

from export_rag_files import print_summary, table_as_text
from group_frames import (
    BROADCAST_ADDRESS,
    KIND_UNICAST,
    group_frames,
    load_table,
    print_groups,
)

TYPE_MANAGEMENT = 0
TYPE_DATA = 2

SUBTYPE_DISASSOCIATION = 10
SUBTYPE_DEAUTHENTICATION = 12
SUBTYPE_ACTION = 13

# Frames protected under PMF - a protected frame of this subtype proves PMF.
PMF_PROTECTED_SUBTYPES = [SUBTYPE_DISASSOCIATION, SUBTYPE_DEAUTHENTICATION, SUBTYPE_ACTION]

# Frames carrying an RSN element with the MFPC bit.
SUBTYPE_ASSOCIATION_REQUEST = 0
SUBTYPE_REASSOCIATION_REQUEST = 2
SUBTYPE_PROBE_RESPONSE = 5
SUBTYPE_BEACON = 8
RSN_SUBTYPES = [SUBTYPE_ASSOCIATION_REQUEST, SUBTYPE_REASSOCIATION_REQUEST,
                SUBTYPE_PROBE_RESPONSE, SUBTYPE_BEACON]

# Capture truncation threshold: a floating-point number in seconds.
# The boundary is closed: gap < 1.0 s  -> capture cut off, and gap >= 1.0 s -> observation window sufficient
TRUNCATION_THRESHOLD_S = 1.0

TIME_DIGITS = 6

NOT_APPLICABLE = "not applicable"
UNKNOWN = "unknown"

PMF_YES = "yes"
PMF_NO = "no"
PMF_UNDETERMINED = "undetermined"


# Conditions on frames (each returns a true / false column)
def is_true(condition):
    """Turns "unknown" (an empty cell) into false."""
    return condition.fillna(False).astype(bool)


def management_mask(frames, subtypes):
    """Management frames (type 0) of one of the given subtypes."""
    return is_true((frames["type"] == TYPE_MANAGEMENT) & frames["subtype"].isin(subtypes))


def attack_deauth_mask(frames):
    """Unprotected deauth frame: type 0, subtype 12, protected 0.

    Part of the signature condition (see signature_mask).
    """
    return is_true(management_mask(frames, [SUBTYPE_DEAUTHENTICATION]) & (frames["protected"] == 0))


def signature_mask(frames):
    """Signature frame: an unprotected deauth whose da is not broadcast.

    All "before the attack" and "after the attack" values in count_group are
    measured from the first / last signature frame.
    """
    return is_true(attack_deauth_mask(frames) & (frames["da"] != BROADCAST_ADDRESS))


def protected_deauth_mask(frames):
    """Protected deauth frame: type 0, subtype 12, protected 1."""
    return is_true(management_mask(frames, [SUBTYPE_DEAUTHENTICATION]) & (frames["protected"] == 1))


def involves_address(frames, address):
    """Frames in which the address appears in sa or da."""
    return is_true((frames["sa"] == address) | (frames["da"] == address))


# Values for the whole capture
def count_capture(table):
    """Values computed once, on the whole table."""
    start = table["ts"].min()
    end = table["ts"].max()

    # PMF, evidence 1: protected 10 / 12 / 13 frames.
    # Such a frame cannot be sent without the keys, so the network definitely has PMF.
    protected_count = int((management_mask(table, PMF_PROTECTED_SUBTYPES) & is_true(table["protected"] == 1)).sum())

    # PMF, evidence 2: MFPC bit in 0 / 2 / 5 / 8 frames (RSN element).
    # An empty mfpc (no RSN element or no column) is not evidence.
    rsn_frames = management_mask(table, RSN_SUBTYPES)
    mfpc_yes_count = int((rsn_frames & is_true(table["mfpc"] == 1)).sum())
    mfpc_no_count = int((rsn_frames & is_true(table["mfpc"] == 0)).sum())

    if protected_count > 0 or mfpc_yes_count > 0:
        pmf = PMF_YES
    elif mfpc_no_count > 0:
        pmf = PMF_NO            # the network itself announces it does not support PMF
    else:
        pmf = PMF_UNDETERMINED

    return {
        "frames": len(table),
        "start": start,
        "end": end,
        "duration": end - start,
        "pmf": pmf,
        "pmf_protected_frames": protected_count,
        "pmf_mfpc_yes_frames": mfpc_yes_count,
        "pmf_mfpc_no_frames": mfpc_no_count,
    }


# Values for a single group
def counts_in_order(values):
    """[(value, count)] in order of first appearance, without empty values."""
    result = {}
    for value in values:
        if pd.isna(value):
            continue
        result[value] = result.get(value, 0) + 1
    return list(result.items())


def count_group(table, group, capture):
    """Values for a single unicast group."""
    frames = table.loc[group["rows"]]
    client = group["other_side"]

    signature = frames[signature_mask(frames)]

    # # Episodes: distinct (sa, da) pairs among signature frames, with direction
    episode_pairs = sorted(set(zip(signature["sa"], signature["da"])))

    # Time window of the group ("Time window" line on the card): first and last
    # deauth / disassoc frame of the group by ts - including protected deauth and disassoc.
    first_row = frames["ts"].idxmin()
    last_row = frames["ts"].idxmax()

    values = {
        "bssid": group["bssid"],
        "client": client,
        "deauth_frames": int(management_mask(frames, [SUBTYPE_DEAUTHENTICATION]).sum()),
        "disassoc_frames": int(management_mask(frames, [SUBTYPE_DISASSOCIATION]).sum()),
        "first_ts": frames["ts"].min(),
        "last_ts": frames["ts"].max(),
        "first_frame": int(first_row) + 1,
        "last_frame": int(last_row) + 1,
        "window_s": frames["ts"].max() - frames["ts"].min(),
        "first_clock": frames.loc[first_row, "clock"],
        "last_clock": frames.loc[last_row, "clock"],
        "senders": counts_in_order(frames["sa"]),
        "reason_codes": counts_in_order(frames["reason"]),
        "signature_frames": len(signature),
        "protected_frames": int(protected_deauth_mask(frames).sum()),
        "episodes": len(episode_pairs),
        "episode_pairs": episode_pairs,
    }

    # First and last SIGNATURE frame - reference points for "before the attack"
    # and "after the attack" (SA Query, data traffic, truncation). This is not the
    # card window: the card window (first_ts / last_ts) covers all frames of the group.
    if signature.empty:
        values["attack_first_ts"] = NOT_APPLICABLE
        values["attack_last_ts"] = NOT_APPLICABLE
        values["attack_first_frame"] = NOT_APPLICABLE
        values["attack_last_frame"] = NOT_APPLICABLE
    else:
        first_signature_row = signature["ts"].idxmin()
        last_signature_row = signature["ts"].idxmax()
        values["attack_first_ts"] = signature["ts"].min()
        values["attack_last_ts"] = signature["ts"].max()
        values["attack_first_frame"] = int(first_signature_row) + 1
        values["attack_last_frame"] = int(last_signature_row) + 1

    # Without a signature frame there is no attack, so there is no reference point
    # ("before the attack" / "after the attack") - all these fields: "not applicable".
    if signature.empty:
        values["sa_query_after_attack"] = NOT_APPLICABLE
        values["gap_start_s"] = NOT_APPLICABLE
        values["gap_end_s"] = NOT_APPLICABLE
        values["truncated_start"] = NOT_APPLICABLE
        values["truncated_end"] = NOT_APPLICABLE
        values["data_after_attack"] = NOT_APPLICABLE
        return values

    first_signature = values["attack_first_ts"]
    last_signature = values["attack_last_ts"]

    # SA Query: counted from the FIRST signature frame (as in the guide),
    # because the station responds with an SA Query exchange right after the
    # first forged frame, often before the attacker sends more.
    sa_query = (management_mask(table, [SUBTYPE_ACTION])
                & is_true(table["protected"] == 1)
                & is_true(table["ts"] > first_signature)
                & involves_address(table, client))
    values["sa_query_after_attack"] = int(sa_query.sum())

    # Gaps in seconds, rounded to microseconds:
    #   gap_start_s = first signature frame - start of the capture
    #   gap_end_s   = end of the capture - last signature frame
    # The card shows them for TRUNCATION and for UNKNOWN.
    values["gap_start_s"] = round(float(first_signature - capture["start"]), TIME_DIGITS)
    values["gap_end_s"] = round(float(capture["end"] - last_signature), TIME_DIGITS)

    # Closed 1 s boundary: < 1.0 -> cut off, >= 1.0 -> window sufficient.
    # bool(...) turns the comparison result into a plain True / False.
    values["truncated_start"] = bool(values["gap_start_s"] < TRUNCATION_THRESHOLD_S)
    values["truncated_end"] = bool(values["gap_end_s"] < TRUNCATION_THRESHOLD_S)

    # The post-attack observation window starts right after the LAST signature frame
    if values["truncated_end"]:
        # Less than 1 s of observation: lack of traffic is not proof of a successful attack.
        values["data_after_attack"] = UNKNOWN
    else:
        data = (is_true(table["type"] == TYPE_DATA)
                & is_true(table["ts"] >= last_signature)
                & involves_address(table, client))
        values["data_after_attack"] = int(data.sum())

    return values


def clean_traffic_values():
    """Values for a capture without any group: counters 0, the rest "not applicable"."""
    return {
        "bssid": NOT_APPLICABLE,
        "client": NOT_APPLICABLE,
        "deauth_frames": 0,
        "disassoc_frames": 0,
        "first_ts": NOT_APPLICABLE,
        "last_ts": NOT_APPLICABLE,
        "first_frame": NOT_APPLICABLE,
        "last_frame": NOT_APPLICABLE,
        "window_s": NOT_APPLICABLE,
        "first_clock": NOT_APPLICABLE,
        "last_clock": NOT_APPLICABLE,
        "gap_start_s": NOT_APPLICABLE,
        "gap_end_s": NOT_APPLICABLE,
        "senders": NOT_APPLICABLE,
        "reason_codes": NOT_APPLICABLE,
        "signature_frames": 0,
        "attack_first_ts": NOT_APPLICABLE,
        "attack_last_ts": NOT_APPLICABLE,
        "attack_first_frame": NOT_APPLICABLE,
        "attack_last_frame": NOT_APPLICABLE,
        "protected_frames": 0,
        "episodes": 0,
        "episode_pairs": [],
        "sa_query_after_attack": NOT_APPLICABLE,
        "truncated_start": NOT_APPLICABLE,
        "truncated_end": NOT_APPLICABLE,
        "data_after_attack": NOT_APPLICABLE,
    }


# Counting for the whole capture
def count_values(table, groups):
    """Step 4 as a whole: capture values and values for each unicast group."""
    capture = count_capture(table)
    counted = [group for group in groups if group["kind"] == KIND_UNICAST]
    skipped = [group for group in groups if group["kind"] != KIND_UNICAST]

    if counted:
        status = "attack"
        group_values = [count_group(table, group, capture) for group in counted]
    elif skipped:
        status = "only_skipped"
        group_values = []
    else:
        status = "clean"
        group_values = [clean_traffic_values()]

    return {
        "capture": capture,
        "groups": group_values,
        "skipped": skipped,
        "status": status,
    }


# Printout
def as_text(value):
    """Value for printing: yes / no instead of True / False, time with 6 decimal places."""
    if value is True:
        return "tak"
    if value is False:
        return "nie"
    if isinstance(value, float):
        return f"{value:.6f}"
    if isinstance(value, list):
        if not value:
            return "-"
        return ", ".join(f"{item} x{count}" for item, count in value)
    return str(value)


def frame_text(number, ts):
    """Frame for printing: its number in the capture and its ts, e.g. 'no. 1, ts 1608306602.330434'."""
    if number == NOT_APPLICABLE:
        return NOT_APPLICABLE
    return f"nr {number}, ts {ts:.6f}"


def print_values(result):
    """Prints the result of step 4: first the eight values from the document, then the rest."""
    capture = result["capture"]

    for group in result["skipped"]:
        print(f"skipped group {group['kind']} bssid={group['bssid']} "
              f"({len(group['rows'])} frames)")

    if result["status"] == "only_skipped":
        print("the file contains only skipped groups - no values for the card")
        return
    if result["status"] == "clean":
        print("no deauth / disassoc frames - clean traffic")

    pmf_detail = (f"{capture['pmf']} (protected 10/12/13 frames: "
                  f"{capture['pmf_protected_frames']}, 0/2/5/8 frames with mfpc=1: "
                  f"{capture['pmf_mfpc_yes_frames']}, with mfpc=0: "
                  f"{capture['pmf_mfpc_no_frames']})")

    for number, values in enumerate(result["groups"], start=1):
        print()
        if result["status"] == "attack":
            print(f"group {number}: bssid={values['bssid']} client={values['client']}")
        print("  values from the document (step 4):")
        document_values = [
            ("signature frames", values["signature_frames"]),
            ("protected frames", values["protected_frames"]),
            ("network uses PMF", pmf_detail),
            ("episodes", values["episodes"]),
            ("SA Query after attack", values["sa_query_after_attack"]),
            ("data traffic after attack", values["data_after_attack"]),
            ("capture cut off at the end", values["truncated_end"]),
            ("capture cut off at the start", values["truncated_start"]),
        ]
        for label, value in document_values:
            print(f"    {label:<30}{as_text(value)}")
        for sa, da in values["episode_pairs"]:
            print(f"      episode: {sa} -> {da}")

        print("  other values for the card:")
        other_values = [
            ("deauthentication frames", values["deauth_frames"]),
            ("disassociation frames", values["disassoc_frames"]),
            ("first signature frame",
             frame_text(values["attack_first_frame"], values["attack_first_ts"])),
            ("last signature frame",
             frame_text(values["attack_last_frame"], values["attack_last_ts"])),
            ("first group frame", frame_text(values["first_frame"], values["first_ts"])),
            ("last group frame", frame_text(values["last_frame"], values["last_ts"])),
            ("senders", values["senders"]),
            ("reason codes", values["reason_codes"]),
            ("frames in capture", capture["frames"]),
            ("capture duration", f"{capture['duration']:.6f} s"),
        ]
        for label, value in other_values:
            print(f"    {label:<30}{as_text(value)}")


# Steps 1-4 together
def run_pipeline(path, verbose=True):
    """Runs steps 1-4 and returns everything step 5 needs.

    Returned dictionary:
        "table"    full table in the schema (steps 1-2)
        "groups"   list of groups (step 3)
        "values"   counting result (step 4): capture, groups, skipped, status

    Step 5 will call this function and receive all three at once.
    """
    # Steps 1-2 Whole file: a row limit would shift the end of the capture.
    table = load_table(path, max_rows=None)
    if verbose:
        print("=" * 30, "STEP 1-2: export and conversion", "=" * 30)
        print_summary(table)
        print(table_as_text(table))

    # Step 3.
    groups = group_frames(table)
    if verbose:
        print()
        print("=" * 30, "STEP 3: grouping", "=" * 30)
        print_groups(table, groups)

    # Step 4 Receives the same, untouched table and the list of groups.
    values = count_values(table, groups)
    if verbose:
        print()
        print("=" * 30, "STEP 4: counting", "=" * 30)
        print_values(values)

    return {"table": table, "groups": groups, "values": values}


def main():
    parser = argparse.ArgumentParser(
        description="Steps 1-4: loading, grouping and counting values.")
    parser.add_argument("file", help=" .pcap / .pcapng / .cap albo .csv")
    args = parser.parse_args()
    run_pipeline(args.file)


if __name__ == "__main__":
    main()