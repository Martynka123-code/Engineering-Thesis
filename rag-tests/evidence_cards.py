"""Step 5: evidence cards.

Input: the result of steps 1-4 (run_pipeline from count_values.py).
Output: one card per unicast group, or one clean-traffic card.
Each card is text (str); cards are printed and saved to the cards folder
next to the .py files, one .txt file per card.

Step 5 computes nothing - it only formats the values computed in step 4.

Card rules (from the document and agreed decisions):
    - fixed layout and line order, regardless of the capture
    - no assessment, facts only
    - every time with a unit and 3 decimal places, e.g. 0.157 s
    - TRUNCATION line only when truncation actually occurred
    - every address checked against a pattern; bad address -> <invalid address>
    - every reason code checked; not an integer -> <invalid code>
    - time window: first and last deauth / disassoc frame of the group
    - "not applicable" from step 4 -> n/a, "unknown" -> UNKNOWN
    - time of day in the time window copied from the data (pcap: frame.time_utc,
      CSV: frame.time); no time of day -> seconds from the start of the capture

Running from the terminal (the whole file is read):

    python evidence_cards.py "capture.pcap"
    python evidence_cards.py dataset_file.csv
"""

import argparse
import re
from pathlib import Path

import pandas as pd

from count_values import (
    NOT_APPLICABLE,
    PMF_NO,
    PMF_UNDETERMINED,
    PMF_YES,
    UNKNOWN,
    run_pipeline,
)


CARDS_DIR = Path(__file__).resolve().parent / "cards"

MAC_PATTERN = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
INVALID_ADDRESS = "<invalid address>"
INVALID_REASON = "<invalid code>"

CARD_NOT_APPLICABLE = "n/a"

PMF_LINES = {
    PMF_YES: "yes",
    PMF_NO: ("NO - the network advertises no PMF support (MFPC = 0); "
             "the signature does not apply"),
    PMF_UNDETERMINED: ("UNDETERMINED - no protected management frames and no frames "
                       "advertising MFPC (subtype 0, 2, 5 or 8); "
                       "the signature cannot be applied"),
}

TRUNCATION_THRESHOLD_TEXT = "1 s"


# Formatting single values
def is_missing(value):
    """True for "not applicable" from step 4 and for an empty value."""
    if isinstance(value, str):
        return value == NOT_APPLICABLE
    if isinstance(value, (list, tuple)):
        return False                       # lista (np. nadawcy) to wartość, nie brak
    return value is None or pd.isna(value)


def safe_address(value):
    """Address for the card: a valid MAC or a placeholder message.

    A capture is written by anyone on the network, the attacker included, and the
    card goes straight into the prompt - so nothing that is not an address gets onto the card.
    """
    if is_missing(value):
        return CARD_NOT_APPLICABLE
    if isinstance(value, str) and MAC_PATTERN.match(value.lower()):
        return value.lower()
    return INVALID_ADDRESS


def safe_capture_name(path):
    """Capture name for the header: file name without extension,
    only letters, digits, dot, hyphen and underscore."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", Path(path).stem)


def seconds(value):
    """Time with a unit: 0.157 -> '0.157 s'."""
    return f"{value:.3f} s"


def clock(clock_value, relative):
    """Point in the time window: time of day from the data, otherwise seconds from the start.

    clock_value   time of day as text HH:MM:SS.mmm (clock field) or empty
    relative      seconds from the start of the capture (ts - start)
    """
    if is_missing(clock_value):
        return f"t+{relative:.3f} s"
    return clock_value


def safe_reason(value):
    """Reason code for the card: an integer or a placeholder message.

    A column with empty cells is sometimes float (7.0), and the value comes
    from the capture - only an integer gets onto the card.
    """
    try:
        number = float(value)
    except (TypeError, ValueError):
        return INVALID_REASON
    if not number.is_integer():
        return INVALID_REASON
    return str(int(number))


def counted_list(pairs, formatter=str):
    """[(value, count)] -> 'value x3, value x2'.

     formatter   function turning a value into text (safe_address, safe_reason)
     """
    if is_missing(pairs) or not pairs:
        return CARD_NOT_APPLICABLE
    return ", ".join(f"{formatter(value)} x{count}" for value, count in pairs)


def number_or_na(value):
    """Counter for the card: a number or n/a."""
    return CARD_NOT_APPLICABLE if is_missing(value) else str(value)


def time_window_line(values, capture):
    """Time window line, as in the guide.

     Group window: from the first to the last deauth / disassoc frame of the group
     (first_ts / last_ts from step 4). Clean traffic (no group) -> n/a.
     """
    if is_missing(values["first_ts"]):
        return f"Time window: {CARD_NOT_APPLICABLE}"
    start = clock(values["first_clock"], values["first_ts"] - capture["start"])
    end = clock(values["last_clock"], values["last_ts"] - capture["start"])
    return f"Time window: {start} - {end} ({seconds(values['window_s'])})"


# A single card
def build_card(capture_name, values, capture):
    """Builds the text of a single card.

    capture_name   capture name for the header (str)
    values         value set of one group or of clean traffic (dict from step 4)
    capture        values for the whole capture (dict from step 4)

    Returns: str - the whole card, lines separated by newline characters.
    """
    lines = [
        f"[EVIDENCE CARD] capture={capture_name} "
        f"bssid={safe_address(values['bssid'])} client={safe_address(values['client'])}",
        "",
        time_window_line(values, capture),
    ]

    if is_missing(values["first_ts"]):
        lines.append(f"Recipient: {CARD_NOT_APPLICABLE}")
    else:
        lines.append(f"Recipient: unicast ({safe_address(values['client'])})")

    lines += [
        f"Deauthentication frames: {values['deauth_frames']}",
        f"Disassociation frames: {values['disassoc_frames']}",
        f"Frame sender: {counted_list(values['senders'], formatter=safe_address)}",
        f"Reason codes: {counted_list(values['reason_codes'], formatter=safe_reason)}",
        "",
        f"Network protects management frames (PMF): {PMF_LINES[capture['pmf']]}",
        f"Unprotected unicast deauth frames (signature match): {values['signature_frames']}",
        f"Protected deauth frames (genuine, sent by the real AP): {values['protected_frames']}",
        f"Distinct attack episodes (sender/recipient pairs): {values['episodes']}",
    ]
    for sa, da in values["episode_pairs"]:
        lines.append(f"  - {safe_address(sa)} -> {safe_address(da)}")

    lines.append("SA Query frames after the first signature-match frame: "
                 f"{number_or_na(values['sa_query_after_attack'])}")

    # Anchor from step 4: the last SIGNATURE frame, not the last deauth frame
    # (a protected deauth after the attack does not shift the "after the attack" window).
    data = values["data_after_attack"]
    if data == UNKNOWN:
        data_text = (f"UNKNOWN - the capture ends {seconds(values['gap_end_s'])} "
                     "after the last signature-match frame")
    else:
        data_text = number_or_na(data)
    lines.append("Data frames involving the client after the last signature-match frame: "
                 f"{data_text}")

    lines += [
        "",
        f"Capture extent: {capture['frames']} frames over {seconds(capture['duration'])}",
    ]

    if values["truncated_start"] is True:
        lines.append(f"TRUNCATION: the capture starts {seconds(values['gap_start_s'])} "
                     "before the first signature-match frame "
                     f"(threshold {TRUNCATION_THRESHOLD_TEXT})")
    if values["truncated_end"] is True:
        lines.append(f"TRUNCATION: the capture ends {seconds(values['gap_end_s'])} "
                     "after the last signature-match frame "
                     f"(threshold {TRUNCATION_THRESHOLD_TEXT})")

    return "\n".join(lines)


# All cards of a capture
def build_cards(path, values):
    """Cards for the whole capture.

    path     path to the file (for the name in the header)
    values   result of count_values (dict: capture, groups, skipped, status)

    Returns: list[str] - one card per value set in values["groups"].
    With status "only_skipped" the list is empty (groups outside the thesis scope).
    """
    name = safe_capture_name(path)
    return [build_card(name, group_values, values["capture"])
            for group_values in values["groups"]]


def save_cards(cards, path, directory=CARDS_DIR):
    """Saves cards to <name>_card<N>.txt files; returns a list of paths.

    The folder is created if it does not exist. Files with the same name are overwritten.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    name = safe_capture_name(path)
    saved = []
    for number, card in enumerate(cards, start=1):
        card_path = directory / f"{name}_card{number}.txt"
        card_path.write_text(card + "\n", encoding="utf-8")
        saved.append(card_path)
    return saved


def run_cards(path, verbose=True, save=True):
    """Steps 1-5. Returns the dictionary from run_pipeline extended with "cards" (list[str])."""
    result = run_pipeline(path, verbose=verbose)
    cards = build_cards(path, result["values"])
    result["cards"] = cards

    if verbose:
        print()
        print("=" * 30, "STEP 5: evidence cards", "=" * 30)
        if not cards:
            print("no cards - the file contains only out-of-scope groups (broadcast / unknown)")
        for card in cards:
            print()
            print(card)

    if save and cards:
        saved = save_cards(cards, path)
        result["card_files"] = saved
        if verbose:
            print()
            for card_path in saved:
                print(f"saved: {card_path}")

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Steps 1-5: from pcap / CSV file to evidence card.")
    parser.add_argument("file", help="plik .pcap / .pcapng / .cap albo .csv")
    args = parser.parse_args()
    run_cards(args.file)


if __name__ == "__main__":
    main()