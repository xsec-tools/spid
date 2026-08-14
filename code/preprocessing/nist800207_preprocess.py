"""
nist_800207_preprocess.py
=========================
Preprocesses the raw pdftotext output of NIST SP 800-207 (Zero Trust
Architecture) into a sentence-level CSV ready for the CE classification
pipeline (02_run_ce_pipeline.py).

Unlike NIST SP 800-53, this document has no control catalogue structure.
It is continuous discursive prose. The approach is therefore:
  1. Extract body lines between section 1 Introduction and the References
     section, stripping page noise.
  2. Detect section and subsection headings to track current section metadata.
  3. Accumulate paragraph buffers and flush to sentence-level units on blank
     lines or noise lines, attaching current section metadata to each unit.

OUTPUT SCHEMA
-------------
unit_id         -- unique identifier, e.g. SP207-U00001
text            -- cleaned sentence text
section_id      -- e.g. 2.1, 3.3.1
section_name    -- e.g. Tenets of Zero Trust
word_count      -- integer

Usage:
    python nist_800207_preprocess.py \
        --input_txt  data/NIST_SP_800-207.txt \
        --output_csv data/input/segmented_units/nist800207_558_units.csv

    # Override body boundaries if needed:
    python nist_800207_preprocess.py \
        --input_txt  data/NIST_SP_800-207.txt \
        --output_csv data/input/segmented_units/nist800207_558_units.csv \
        --body_start 353 \
        --body_end   2336

Dependencies:
    pip install nltk
    python -c "import nltk; nltk.download('punkt_tab')"
"""

import re
import csv
import os
import argparse
from collections import Counter

try:
    import nltk
    from nltk.tokenize import sent_tokenize
    try:
        sent_tokenize("test.")
    except LookupError:
        nltk.download("punkt",     quiet=True)
        nltk.download("punkt_tab", quiet=True)
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants (measured empirically from NIST_SP_800-207.txt)
# ---------------------------------------------------------------------------
BODY_INDENT    = 93   # Standard body text indent
BODY_TOLERANCE = 5    # Accept indent 88-98 as body
BLOCK_INDENT   = 100  # Indented blockquote/definition text

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Section heading: "2     Zero Trust Basics" or "3.1.1   ZTA Using Enhanced..."
SECTION_HEADING_RE = re.compile(r"^(\d+(?:\.\d+)*)\s{2,}(.+)$")

# Lines to drop unconditionally (also act as paragraph breaks)
DROP_PATTERNS = [
    re.compile(r"This publication is available free of charge from:", re.IGNORECASE),
    re.compile(r"NIST SP 800-207\s", re.IGNORECASE),
    re.compile(r"ZERO TRUST ARCH", re.IGNORECASE),
    re.compile(r"^https?://"),
    re.compile(r"^\d+\s*$"),                    # standalone page numbers
    re.compile(r"^Figure \d+:"),                # figure captions
    re.compile(r"^Table B-\d+:"),               # table captions
    re.compile(r"^\[\w[\w\-]*\d*\]\s+\w"),      # reference entries e.g. [ACT-IAC]
    re.compile(r"^C O M P U T E R"),            # cover page
]

FOOTNOTE_RE = re.compile(r"^\d{1,2}\s+https?://|^\d{1,2}\s+[A-Z][a-z]")

# Sections to exclude from output entirely
EXCLUDE_SECTIONS = {
    "1.2",   # Structure of This Document (document map only)
    "A",     # Acronyms appendix
    "B", "B.1", "B.2", "B.2.1", "B.2.2",
    "B.3", "B.3.3", "B.3.4",
    "B.4", "B.4.5", "B.4.6", "B.4.7", "B.5",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def measure_indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def should_drop(text: str) -> bool:
    for pat in DROP_PATTERNS:
        if pat.search(text):
            return True
    return bool(FOOTNOTE_RE.match(text))


def is_section_heading(text: str):
    """Return (section_id, section_name) or None."""
    m = SECTION_HEADING_RE.match(text)
    if not m:
        return None
    sec_id   = m.group(1).strip()
    sec_name = m.group(2).strip()
    if sec_name.startswith("http") or sec_name.startswith("Any mention"):
        return None
    if not any(len(w) >= 3 for w in sec_name.split()):
        return None
    return sec_id, sec_name


def clean_text(text: str) -> str:
    # Remove inline citation markers like [FIPS199], [SP800-37]
    text = re.sub(r"\[[A-Z][A-Z0-9\-]+\d*\]", "", text)
    # Fix hyphenated line-break artifacts (de- \n perimeterization)
    text = re.sub(r"-\s+", "", text)
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def split_sentences(text: str) -> list:
    if NLTK_AVAILABLE:
        try:
            return [s.strip() for s in sent_tokenize(text) if s.strip()]
        except Exception:
            pass
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+(?=[A-Z])", text) if s.strip()]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_800207(raw_lines: list, body_start: int, body_end: int,
                 min_words: int, max_words: int) -> tuple:
    """
    Parse NIST SP 800-207 body text into sentence-level units.
    Returns (units, stats).
    """
    body = raw_lines[body_start - 1 : body_end - 1]

    current_section_id   = "1"
    current_section_name = "Introduction"
    para_buffer          = []
    units                = []
    unit_counter         = 1

    stats = {
        "sections_found":      0,
        "paragraphs_flushed":  0,
        "sentences_extracted": 0,
        "units_too_short":     0,
        "units_excluded":      0,
        "units_emitted":       0,
    }

    def flush_para():
        nonlocal unit_counter
        if not para_buffer:
            return

        joined = clean_text(" ".join(para_buffer))
        para_buffer.clear()

        if not joined:
            return

        if current_section_id in EXCLUDE_SECTIONS:
            stats["units_excluded"] += 1
            return

        stats["paragraphs_flushed"] += 1

        for sent in split_sentences(joined):
            sent = clean_text(sent)
            wc   = len(sent.split())
            stats["sentences_extracted"] += 1

            if wc < min_words:
                stats["units_too_short"] += 1
                continue

            units.append({
                "unit_id":      f"SP207-U{unit_counter:05d}",
                "text":         sent,
                "section_id":   current_section_id,
                "section_name": current_section_name,
                "word_count":   wc,
            })
            unit_counter += 1
            stats["units_emitted"] += 1

    for raw in body:
        stripped = raw.strip()

        # Blank line — paragraph break
        if not stripped:
            flush_para()
            continue

        # Noise lines act as paragraph breaks
        if should_drop(stripped):
            flush_para()
            continue

        # Determine indent
        indent = measure_indent(raw.rstrip())

        # Accept body indent (93±5) and blockquote indent (100)
        is_body  = abs(indent - BODY_INDENT) <= BODY_TOLERANCE
        is_block = indent == BLOCK_INDENT
        if not (is_body or is_block):
            flush_para()
            continue

        # Section heading check (only at body indent, not blockquote)
        if is_body:
            heading = is_section_heading(stripped)
            if heading:
                flush_para()
                current_section_id, current_section_name = heading
                stats["sections_found"] += 1
                continue

        para_buffer.append(stripped)

    flush_para()
    return units, stats


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Preprocess NIST SP 800-207 into sentence-level units for CE pipeline."
    )
    parser.add_argument("--input_txt",  required=True,
                        help="Path to raw pdftotext -layout output of NIST SP 800-207")
    parser.add_argument("--output_csv", required=True,
                        help="Path for output CSV")
    parser.add_argument("--body_start", type=int, default=353,
                        help="1-indexed line where body content begins (default: 353)")
    parser.add_argument("--body_end",   type=int, default=2336,
                        help="1-indexed line where References section begins (default: 2336)")
    parser.add_argument("--min_words",  type=int, default=8,
                        help="Minimum words per unit (default: 8)")
    parser.add_argument("--max_words",  type=int, default=150,
                        help="Units longer than this are flagged in stats but still emitted "
                             "(default: 150)")
    args = parser.parse_args()

    print(f"Reading {args.input_txt} ...")
    with open(args.input_txt, encoding="utf-8", errors="replace") as f:
        raw_lines = f.readlines()
    print(f"  Total lines in file: {len(raw_lines)}")
    print(f"  Processing lines {args.body_start}-{args.body_end}")

    units, stats = parse_800207(
        raw_lines,
        body_start=args.body_start,
        body_end=args.body_end,
        min_words=args.min_words,
        max_words=args.max_words,
    )

    os.makedirs(os.path.dirname(os.path.abspath(args.output_csv)), exist_ok=True)

    fieldnames = ["unit_id", "text", "section_id", "section_name", "word_count"]

    with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(units)

    long_count     = sum(1 for u in units if int(u["word_count"]) > args.max_words)
    section_counts = Counter(u["section_id"] for u in units)

    print(f"\nPreprocessing complete")
    print(f"  Sections found:            {stats['sections_found']}")
    print(f"  Paragraphs flushed:        {stats['paragraphs_flushed']}")
    print(f"  Sentences extracted:       {stats['sentences_extracted']}")
    print(f"  Units dropped (<{args.min_words}w):      {stats['units_too_short']}")
    print(f"  Units excluded (appendix): {stats['units_excluded']}")
    print(f"  Units flagged (>{args.max_words}w):     {long_count} (still emitted)")
    print(f"  Units emitted:             {stats['units_emitted']}")
    print(f"\n  Units by section:")
    for sec_id, count in sorted(section_counts.items(),
                                key=lambda x: [int(p) for p in x[0].split(".")
                                               if p.isdigit()]):
        name = next(u["section_name"] for u in units if u["section_id"] == sec_id)
        print(f"    {sec_id:<8s} {count:4d}  {name}")
    print(f"\nSaved: {args.output_csv}")


if __name__ == "__main__":
    main()