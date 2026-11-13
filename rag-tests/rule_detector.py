"""Stage 2 of the guide: rule-based detector - a verdict without a model.

Input: the values computed in step 4 (count_values) - the same numbers that are on the card.
Output: a verdict in the contract's terms (VERDICT, OUTCOME, VICTIM) and the path of
questions that led to it.

The detector computes nothing - it only decides. Five questions from the "Decision
order" diagram, in this order, without thresholds or weights:

    1. Recipient = broadcast?          yes -> no attack (broadcast variant, out of scope)
    2. Network uses PMF?               no  -> insufficient evidence (without PMF the signature decides nothing)
    3. Unprotected deauth frames?      no  -> no attack (protected frames are genuine)
    4. SA Query exchange after attack? yes -> attack, attack blocked
    5. Known behaviour after attack?   no  -> attack, outcome unknown (capture cut off)
       yes, client traffic continues   -> attack, attack blocked   (agreed with the supervisor)
       yes, client traffic stopped     -> attack, successful

Seven possible results. Questions 1-2 reject cases that are not this attack,
question 3 decides whether there was an attack, questions 4-5 only its outcome.

Result for the whole capture with several groups (several clients):
    attack if any group gives an attack; otherwise insufficient evidence if
    any group came out that way; otherwise no attack.

Running from the terminal (the whole file is read):

    python rule_detector.py "capture.pcap"
    python rule_detector.py dataset_file.csv
"""

import argparse

from count_values import PMF_YES, UNKNOWN
from evidence_cards import run_cards
from group_frames import KIND_BROADCAST

VERDICT_ATTACK = "attack"
VERDICT_NO_ATTACK = "no attack"
VERDICT_INSUFFICIENT = "insufficient evidence"

OUTCOME_SUCCESSFUL = "successful"
OUTCOME_BLOCKED = "the attack was blocked"
OUTCOME_UNKNOWN = "unknown"
OUTCOME_NOT_APPLICABLE = "n/a"

NO_VICTIM = "none"

# Decision for a single group (a single client)
def decision(verdict, outcome, victim, decided_by, path):
    """Detector result as a dictionary.

    decided_by   number of the question that decided (1-5)
    path         list of (question, answer) pairs - the path taken through the diagram
    """
    return {"verdict": verdict, "outcome": outcome, "victim": victim,
            "decided_by": decided_by, "path": path}


def decide_group(values, capture):
    """Questions 2-5 for a single unicast group or for the clean-traffic card.

    values    value set of one group from step 4 (or of clean traffic)
    capture   values for the whole capture from step 4 (pmf is needed)
    """
    client = values["client"]
    path = [("1. recipient = broadcast?", "no (unicast group or clean traffic)")]

    # 2. Network uses PMF? Without PMF the signature decides nothing
    if capture["pmf"] != PMF_YES:
        path.append(("2. network uses PMF?", f"no ({capture['pmf']})"))
        return decision(VERDICT_INSUFFICIENT, OUTCOME_NOT_APPLICABLE, NO_VICTIM, 2, path)
    path.append(("2. network uses PMF?", "yes"))

    # 3. Unprotected deauth frames? Only a signature frame counts
    signature = values["signature_frames"]
    if signature == 0:
        path.append(("3. unprotected deauth frames?",
                     f"no (signature frames: 0, protected deauth: {values['protected_frames']})"))
        return decision(VERDICT_NO_ATTACK, OUTCOME_NOT_APPLICABLE, NO_VICTIM, 3, path)
    path.append(("3. unprotected deauth frames?", f"yes (signature frames: {signature})"))

    # 4. SA Query exchange after the attack (from the first signature frame)?
    sa_query = values["sa_query_after_attack"]
    if sa_query > 0:
        path.append(("4. SA Query after attack?", f"yes ({sa_query})"))
        return decision(VERDICT_ATTACK, OUTCOME_BLOCKED, client, 4, path)
    path.append(("4. SA Query after attack?", "no (0)"))

    # 5. Known behaviour after the attack (from the last signature frame)?
    data = values["data_after_attack"]
    if data == UNKNOWN:
        path.append(("5. known behaviour after attack?",
                     f"no (the capture ends {values['gap_end_s']:.3f} s after the attack)"))
        return decision(VERDICT_ATTACK, OUTCOME_UNKNOWN, client, 5, path)
    if data > 0:
        path.append(("5. known behaviour after attack?", f"yes - client traffic continues ({data} data frames)"))
        return decision(VERDICT_ATTACK, OUTCOME_BLOCKED, client, 5, path)
    path.append(("5. known behaviour after attack?", "yes - client traffic stopped (0 data frames)"))
    return decision(VERDICT_ATTACK, OUTCOME_SUCCESSFUL, client, 5, path)


# Decision for the whole capture
def decide_capture(values):
    """Verdict for the whole capture.

    values   result of count_values: capture, groups, skipped, status

    Returns: dict - {"verdict": str, "groups": list[dict], "path": list}
             "groups" - decisions for consecutive groups (empty when there are only skipped groups)
             "path"   - path of question 1, when it decided for the whole capture
    """
    # 1. Recipient = broadcast? The file contains only skipped groups (no cards)
    if values["status"] == "only_skipped":
        kinds = {group["kind"] for group in values["skipped"]}
        if KIND_BROADCAST in kinds:
            path = [("1. recipient = broadcast?", "yes (only broadcast / unknown groups)")]
            return {"verdict": VERDICT_NO_ATTACK, "groups": [], "path": path}
        path = [("1. recipient = broadcast?", "no - only unknown groups (missing addresses)")]
        return {"verdict": VERDICT_INSUFFICIENT, "groups": [], "path": path}

    # Unicast groups or one clean-traffic set: questions 2-5 for each
    groups = [decide_group(group_values, values["capture"]) for group_values in values["groups"]]
    verdicts = {group["verdict"] for group in groups}
    if VERDICT_ATTACK in verdicts:
        verdict = VERDICT_ATTACK
    elif VERDICT_INSUFFICIENT in verdicts:
        verdict = VERDICT_INSUFFICIENT
    else:
        verdict = VERDICT_NO_ATTACK
    return {"verdict": verdict, "groups": groups, "path": []}


# Printout and running
def decision_lines(result):
    """Question path and verdict of each group plus the capture verdict - as a list of lines."""
    lines = [f"  {question:<35}{answer}" for question, answer in result["path"]]
    for number, group in enumerate(result["groups"], start=1):
        lines.append(f"  group {number}:")
        for question, answer in group["path"]:
            lines.append(f"    {question:<35}{answer}")
        lines.append(f"    VERDICT: {group['verdict']}   OUTCOME: {group['outcome']}   VICTIM: {group['victim']}")
    lines += ["", f"  CAPTURE VERDICT: {result['verdict']}"]
    return lines


def print_decision(result):
    """Prints the question path and verdict of each group plus the capture verdict."""
    for line in decision_lines(result):
        print(line)


def run_detector(path, verbose=True, save=True):
    """Steps 1-5 and the rule-based detector. Returns the run_cards result extended with "detector"."""
    result = run_cards(path, verbose=verbose, save=save)
    result["detector"] = decide_capture(result["values"])
    if verbose:
        print()
        print("=" * 30, "RULE-BASED DETECTOR", "=" * 30)
        print_decision(result["detector"])
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Stage 2: rule-based detector - verdict from the card values, no model.")
    parser.add_argument("file", help=".pcap / .pcapng / .cap or .csv file")
    args = parser.parse_args()
    run_detector(args.file)


if __name__ == "__main__":
    main()