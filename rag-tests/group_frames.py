"""Step 3: grouping deauthentication / disassociation frames.

Input: a table in the schema from export_rag_files.py (load_pcap or load_csv).
Output: a list of groups. Each group is one future evidence card.

Rule from the document:

    Select deauthentication and disassociation frames.
    Assign each one to a group (bssid, other_side), where the other side is:
      1. if da is the broadcast address         -> the broadcast address
      2. otherwise, if da != bssid              -> da
      3. otherwise, if sa != bssid              -> sa

Mapping to our table and cases the document does not describe:

    - "subtype 12 or 10" from the document means here: type = 0 and subtype = 12 or 10
      (subtype 12 alone is also used by the CTS control frame, which is not deauth).
    - A group is a (bssid, other side) pair, so without a bssid no point of the
      rule is applied: a frame with an empty bssid always goes to an "unknown" group.
    - An empty address cannot be compared, so a rule point that needs it does
      not apply: points 1 and 2 need da, point 3 needs sa.
    - A frame for which no point applied goes to an "unknown" group for its
      bssid. This happens in four situations:
        * bssid is empty,
        * da is empty, and sa is empty or equal to bssid,
        * sa is empty, and da is equal to bssid,
        * sa = da = bssid.
      An empty sa or an empty da alone is not enough: if the other of these
      addresses differs from bssid, that one is the other side.
    - A capture without any deauth / disassoc frame produces no group:
      the result is an empty list. The card for such a capture is created by later steps.

A group does not split frames by time or by the protected field.

Running from the terminal (the whole file is read). The printout has two parts:
first the export and conversion result (steps 1-2), then the groups (step 3).

    python group_frames.py "capture.pcap"
    python group_frames.py dataset_file.csv
    python group_frames.py file.csv --max-rows 1000     # only the first 1000 packets
"""

import argparse
from pathlib import Path

import pandas as pd

from export_rag_files import load_csv, load_pcap, print_summary, table_as_text

BROADCAST_ADDRESS = "ff:ff:ff:ff:ff:ff"

TYPE_MANAGEMENT = 0
SUBTYPE_DISASSOCIATION = 10
SUBTYPE_DEAUTHENTICATION = 12

KIND_UNICAST = "unicast"        # ordinary pair: access point and a single station
KIND_BROADCAST = "broadcast"    # frames sent to the broadcast address
KIND_UNKNOWN = "unknown"        # the other side could not be determined


# Loading the file (steps 1-2)
def load_table(path, max_rows=None):
    """Loads a pcap or CSV and returns the full table in the schema.

    This is the same table that export_rag_files.py creates. The following steps
    (grouping, counting) receive it in full.
    """
    path = Path(path)
    if path.suffix.lower() in {".pcap", ".pcapng", ".cap"}:
        return load_pcap(path, max_rows=max_rows)
    return load_csv(path, max_rows=max_rows)


# Selecting frames
def select_deauth_frames(table):
    """Returns only the rows with deauthentication and disassociation frames.

    Row numbers stay the same as in the full table.
    """
    is_management = table["type"] == TYPE_MANAGEMENT
    is_deauth_or_disassoc = table["subtype"].isin(
        [SUBTYPE_DISASSOCIATION, SUBTYPE_DEAUTHENTICATION])
    selected = (is_management & is_deauth_or_disassoc).fillna(False)
    return table[selected.astype(bool)]


# Other side
def address_or_none(value):
    """Returns the address, or None if the cell is empty."""
    if value is None or pd.isna(value):
        return None
    return value


def find_other_side(sa, da, bssid):
    """Determines the other side for a single frame.

    Returns two things: the other side's address (or None) and the number of
    the rule point that applied (1, 2, 3, or 0 if none applied).
    """
    sa = address_or_none(sa)
    da = address_or_none(da)
    bssid = address_or_none(bssid)

    # Without a bssid, a (bssid, other side) pair cannot be built
    if bssid is None:
        return None, 0

    # Point 1: frame sent to the broadcast address
    if da == BROADCAST_ADDRESS:
        return BROADCAST_ADDRESS, 1

    # Point 2: the receiver is not the access point, so it is the other side
    if da is not None and da != bssid:
        return da, 2

    # Point 3: the sender is not the access point, so it is the other side
    if sa is not None and sa != bssid:
        return sa, 3

    # No point applied
    return None, 0


def group_kind(rule):
    """Group kind based on the rule point number."""
    if rule == 1:
        return KIND_BROADCAST
    if rule == 0:
        return KIND_UNKNOWN
    return KIND_UNICAST


# Grouping
def group_frames(table):
    """Splits deauth / disassoc frames into (bssid, other side) groups.

    Returns a list of groups in order of first appearance. If the table has no
    deauth / disassoc frame, the list is empty. Each group is a dictionary:

        "bssid"        access point address or None
        "other_side"   other side's address or None
        "kind"         "unicast", "broadcast" or "unknown"
        "rows"         row numbers of the full table belonging to the group
        "rules"        for each row, the number of the rule point that applied

    The full table is not modified. Frames of a group: table.loc[group["rows"]].
    """
    groups = {}   # key: (bssid, other side, kind) -> group

    for row_number, frame in select_deauth_frames(table).iterrows():
        bssid = address_or_none(frame["bssid"])
        other_side, rule = find_other_side(frame["sa"], frame["da"], frame["bssid"])
        kind = group_kind(rule)

        key = (bssid, other_side, kind)
        if key not in groups:
            groups[key] = {
                "bssid": bssid,
                "other_side": other_side,
                "kind": kind,
                "rows": [],
                "rules": [],
            }
        groups[key]["rows"].append(row_number)
        groups[key]["rules"].append(rule)

    return list(groups.values())


# Checking the result
def print_groups(table, groups):
    """Prints the groups and the frames assigned to them."""
    selected = select_deauth_frames(table)
    grouped = sum(len(group["rows"]) for group in groups)
    print(f"packets in table: {len(table)}")
    print(f"deauth / disassoc frames: {len(selected)}")
    print(f"frames assigned to groups: {grouped}")
    print(f"groups: {len(groups)}")
    if not groups:
        print("no deauth / disassoc frames - no group was created")

    for number, group in enumerate(groups, start=1):
        print()
        print(f"group {number}: kind={group['kind']} "
              f"bssid={group['bssid']} other_side={group['other_side']} "
              f"frames={len(group['rows'])}")
        frames = table.loc[group["rows"]].copy()
        frames.insert(0, "rule", group["rules"])
        print(table_as_text(frames))


# Running from the terminal
def main():
    parser = argparse.ArgumentParser(
        description="Groups deauth / disassoc frames from a pcap or CSV file.")
    parser.add_argument("file", help="plik .pcap / .pcapng / .cap albo .csv")
    parser.add_argument(
        "--max-rows", type=int, default=0,
        help="how many first packets to load (default 0 = whole file)")
    args = parser.parse_args()

    max_rows = args.max_rows or None

    # Steps 1-2: export and conversion. The table variable holds the full table until the program ends and is passed in full to the following steps.
    table = load_table(args.file, max_rows=max_rows)
    print("=" * 30, "KROK 1-2: export and conversion", "=" * 30)
    print_summary(table)
    print(table_as_text(table))

    # Step 3: grouping. The full table is not modified.
    groups = group_frames(table)
    print()
    print("=" * 30, "KROK 3: grouping", "=" * 30)
    print_groups(table, groups)


if __name__ == "__main__":
    main()