"""Step 7: index of knowledge base fragments and lexical search (BM25).

Input: .md files from the knowledge directory (next to the .py files) and a question in English.
Output: the k fragments that best match the question, best first.

Splitting into fragments (as in the guide):
    - cut before every line starting with "## " (two hashes and a space)
    - fragment 0 = everything before the first "## " (title and introduction)
    - fragments 1, 2, ... = consecutive sections with the title prepended
    - number of fragments in a file = number of "## " lines + 1

Each fragment remembers three things: text, file name and section number.

The index is built on every program run, directly from the files, and exists
only in memory. Nothing is saved to disk - a change in a document takes effect
immediately on the next run.

Requires the library:  pip install rank-bm25

Running from the terminal:

    python search_knowledge.py "Was the attack blocked?"
    python search_knowledge.py "Was the attack blocked?" --k 7
    python search_knowledge.py "Was the attack blocked?" --show-text
    python search_knowledge.py --list
"""

import argparse
import re
from pathlib import Path

from rank_bm25 import BM25Okapi


KNOWLEDGE_DIR = Path(__file__).resolve().parent / "knowledge"

K = 4

SECTION_MARK = "## "


def tokens(text):
    """Text -> list of words: lowercase, only letters and digits, everything else is dropped.

    'What does wlan.fc.subtype = 13 mean?'
    -> ['what', 'does', 'wlan', 'fc', 'subtype', '13', 'mean']
    """
    return re.findall(r"[a-z0-9]+", text.lower())


# Fragments
def split_document(text, file_name):
    """One document -> list of fragments.

    text        the whole content of the .md file
    file_name   file name, stored with every fragment

    Returns: list[dict] - {"text": str, "file": str, "section": int}.
    """
    lines = text.splitlines()
    if not lines:
        raise ValueError(f"{file_name}: pusty plik")
    title = lines[0].strip()   # the first line is the title "# ..."

    # Lines split into parts: a new part starts at every "## " line
    parts = [[]]
    for line in lines:
        if line.startswith(SECTION_MARK):
            parts.append([])
        parts[-1].append(line)

    fragments = []
    for number, part in enumerate(parts):
        body = "\n".join(part).strip()
        if number > 0:
            # The section goes into the prompt alone, without neighbours - so we prepend the title
            body = title + "\n\n" + body
        fragments.append({"text": body, "file": file_name, "section": number})
    return fragments


def load_fragments(directory=KNOWLEDGE_DIR):
    """Loads all .md files from the directory and cuts them into fragments.

    Files are read in name order (01-..., 02-...), so fragment numbers and order
    are the same on every run.

    Returns: list[dict] - fragments of all files in order.
    """
    directory = Path(directory)
    paths = sorted(directory.glob("*.md"))
    if not paths:
        raise FileNotFoundError(f"No .md files in directory {directory}")

    fragments = []
    for path in paths:
        # utf-8-sig: like utf-8, but removes the invisible BOM character from the start of the file
        text = path.read_text(encoding="utf-8-sig")
        fragments += split_document(text, path.name)
    return fragments


def heading(fragment):
    """Fragment heading for printing: the title for section 0, the "## ..." line for the rest."""
    for line in fragment["text"].splitlines():
        if fragment["section"] == 0 or line.startswith(SECTION_MARK):
            return line.strip()
    return ""


# Indeks and search
def build_index(fragments):
    """BM25 index from the list of fragments - in memory, not saved to disk.

    The library computes once here: the words and length of each fragment, the
    average length, and the rarity weight (IDF) of each word.
    """
    return BM25Okapi([tokens(fragment["text"]) for fragment in fragments])


def search(question, fragments, index, k=K):
    """The k fragments that best match the question, best first.

    Returns: list[tuple] - [(BM25 score, fragment), ...]. Always k items
    (or all fragments, if there are fewer) - there is no cut-off threshold.
    On a tie, the fragment earlier in the list wins.
    """
    scores = index.get_scores(tokens(question))           # jedna liczba na fragment
    order = sorted(range(len(fragments)), key=lambda i: -scores[i])
    return [(float(scores[i]), fragments[i]) for i in order[:k]]


def load_knowledge(directory=KNOWLEDGE_DIR):
    """Fragments and index together - called once per program run.

    Returns: dict - {"fragments": list[dict], "index": BM25Okapi}.
    """
    fragments = load_fragments(directory)
    return {"fragments": fragments, "index": build_index(fragments)}


# Printout
def print_results(question, results, fragments, show_text=False):
    """Prints the question, its tokens and the returned fragments."""
    files = sorted({fragment["file"] for fragment in fragments})
    print(f"question: {question}")
    print(f"tokens:   {tokens(question)}")
    print(f"index:    fragments: {len(fragments)}, files: {len(files)}")
    print()
    for place, (score, fragment) in enumerate(results, start=1):
        print(f"{place:>3}. {score:7.3f}  {fragment['file']:<26}"
              f"section {fragment['section']}  {heading(fragment)}")
        if show_text:
            print()
            for line in fragment["text"].splitlines():
                print(f"        {line}")
            print()


def print_fragments(fragments):
    """Prints all fragments: file, section number, word count, heading."""
    print(f"{'file':<26}{'section':>8}{'words':>7}  heading")
    for fragment in fragments:
        print(f"{fragment['file']:<26}{fragment['section']:>8}"
              f"{len(fragment['text'].split()):>7}  {heading(fragment)}")
    print()
    counts = {}
    for fragment in fragments:
        counts[fragment["file"]] = counts.get(fragment["file"], 0) + 1
    for file_name, count in counts.items():
        print(f"{file_name:<26}fragments: {count}")
    print(f"total fragments: {len(fragments)}, files: {len(counts)}")


def main():
    parser = argparse.ArgumentParser(
        description="Step 7: lexical search (BM25) in the knowledge base.")
    parser.add_argument("question", nargs="?", help="question in English, in quotes")
    parser.add_argument("--k", type=int, default=K,
                        help=f"how many fragments to return (default {K})")
    parser.add_argument("--show-text", action="store_true",
                        help="also print the full text of the returned fragments")
    parser.add_argument("--list", action="store_true",
                        help="print all knowledge base fragments and exit")
    parser.add_argument("--dir", default=KNOWLEDGE_DIR,
                        help="knowledge base directory (default: knowledge next to this file)")
    args = parser.parse_args()

    # The index is rebuilt on every run, directly from the files.
    knowledge = load_knowledge(args.dir)

    if args.list:
        print_fragments(knowledge["fragments"])
        return
    if not args.question:
        parser.error("give a question or use --list")

    results = search(args.question, knowledge["fragments"], knowledge["index"], args.k)
    print_results(args.question, results, knowledge["fragments"], args.show_text)


if __name__ == "__main__":
    main()