"""
nist_preprocess.py
==================
Preprocesses the raw pdftotext output of NIST SP 800-53r5 into a
sentence-level CSV ready for the CE classification pipeline
(02_run_ce_pipeline.py).

OUTPUT SCHEMA
-------------
unit_id         -- unique identifier, e.g. NIST-U00001
text            -- cleaned sentence text
control_id      -- e.g. AC-1, SA-8
control_name    -- e.g. ACCESS ENFORCEMENT
section_type    -- one of four values (see below)
enhancement_id  -- e.g. AC-3(3); empty string for base control units
word_count      -- integer

SECTION TYPES
-------------
All four section types are emitted. This allows downstream analysis to
report principle detection rates broken down by section type, which
avoids the methodological problem of pre-filtering for content likely to
contain principle reasoning.

  base_discussion        Discussion: paragraphs for base controls.
                         Rich normative prose; expected highest hit rate.

  enhancement_discussion Discussion: paragraphs for control enhancements.
                         Also normative prose; similar content to base_discussion.

  control_statement      Prescriptive bullet text of base controls.
                         Contains [Assignment: ...] parameter slots that leave
                         gaps after stripping. Expected very low hit rate.

  enhancement_statement  Prescriptive bullet text of enhancements.
                         Same characteristics as control_statement.

NOTE ON PARAMETER STRIPPING
----------------------------
[Assignment: organization-defined ...] and [Selection: ...] blocks are
removed from all units. In discussion units this produces clean text with
no residual noise. In statement units the parameters sometimes span
multiple wrapped lines; the closing bracket is never seen, so a small
number of statement units retain partial parameter text (e.g. "within ."
or "disseminate to :"). These units are still emitted so the full corpus
is preserved, but they are unlikely to contain principle reasoning and
the section_type tag allows them to be identified.

DOCUMENT STRUCTURE
------------------
The pdftotext -layout output uses consistent indentation throughout
Chapter 3. Indentation was measured empirically from the source file:

  indent=0        Watermark line ("This publication is available free...")
  indent=94-95    Page headers, separator lines, "CHAPTER THREE PAGE N",
                  and control ID lines (e.g. "AC-1  POLICY AND PROCEDURES")
  indent=103      Base control body: Control:, Discussion:, Related Controls:,
                  Control Enhancements:, enhancement header lines "(N) NAME"
  indent=110      Enhancement body: Discussion:, statement lines, Related Controls:

Lines excluded regardless of indent:
  - Watermark ("This publication is available free of charge from:")
  - Page header ("NIST SP 800-53, REV. 5  SECURITY AND PRIVACY...")
  - Separator lines (underscores)
  - "CHAPTER THREE  PAGE N"
  - "Related Controls: ..."
  - "References: ..."
  - "Control Enhancements: ..."
  - "[Withdrawn: ...]"
  - "Quick link to ..."
  - Section headings ("3.1 ACCESS CONTROL")

Usage:
    python nist_preprocess.py \\
        --input_txt  NIST_SP_800-53r5.txt \\
        --output_csv nist_units.csv

    # Override line boundaries if using a different pdftotext extraction:
    python nist_preprocess.py \\
        --input_txt  NIST_SP_800-53r5.txt \\
        --output_csv nist_units.csv \\
        --chapter3_start 2352 \\
        --chapter3_end   22614

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
# Indentation thresholds (measured empirically from NIST_SP_800-53r5.txt)
# ---------------------------------------------------------------------------
INDENT_CONTROL_ID = 94    # "AC-1    POLICY AND PROCEDURES"
INDENT_BASE_BODY  = 103   # base control Discussion:, Control:, enhancement headers
INDENT_ENH_BODY   = 110   # enhancement Discussion: and statement lines
INDENT_TOLERANCE  = 3     # lines within +/- this of a threshold are assigned to it

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Control ID line: "AC-1   POLICY AND PROCEDURES"
CONTROL_ID_RE = re.compile(r"^([A-Z]{1,3}-\d+(?:\.\d+)?)\s{2,}(.+)$")

# Enhancement header: "(3) ACCESS ENFORCEMENT | MANDATORY ACCESS CONTROL"
ENHANCEMENT_HEADER_RE = re.compile(r"^\((\d+)\)\s+(.+)$")

# Lines to drop unconditionally
DROP_PATTERNS = [
    re.compile(r"This publication is available free of charge from:", re.IGNORECASE),
    re.compile(r"NIST SP 800-53,\s*REV\.\s*5\s+SECURITY AND PRIVACY",  re.IGNORECASE),
    re.compile(r"^_{5,}"),
    re.compile(r"CHAPTER THREE\s+(PAGE\s+\d+)?$"),
    re.compile(r"^Related Controls:",    re.IGNORECASE),
    re.compile(r"^References:",          re.IGNORECASE),
    re.compile(r"^Control Enhancements:", re.IGNORECASE),
    re.compile(r"^\[Withdrawn:",         re.IGNORECASE),
    re.compile(r"^Quick link to",        re.IGNORECASE),
    re.compile(r"^https?://"),
    # Section headings e.g. "3.1 ACCESS CONTROL", "3.18 SYSTEM AND COMMUNICATIONS"
    re.compile(r"^\d+\.\d+\s+[A-Z]{2,}"),
]

DISCUSSION_PREFIX_RE = re.compile(r"^Discussion:\s*",  re.IGNORECASE)
CONTROL_PREFIX_RE    = re.compile(r"^Control:\s*",     re.IGNORECASE)

# Parameter blocks to strip. Two passes: closed brackets first, then
# unclosed (parameter wrapped to next line, closing bracket never reached).
PARAM_PATTERNS = [
    re.compile(r"\[Assignment:[^\]]*\]"),
    re.compile(r"\[Selection[^\]]*\]"),
    re.compile(r"\[Assignment:[^\[]*$"),
    re.compile(r"\[Selection[^\[]*$"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def measure_indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def classify_indent(indent: int) -> str:
    if abs(indent - INDENT_CONTROL_ID) <= INDENT_TOLERANCE:
        return "control_id"
    if abs(indent - INDENT_BASE_BODY) <= INDENT_TOLERANCE:
        return "base_body"
    if abs(indent - INDENT_ENH_BODY) <= INDENT_TOLERANCE:
        return "enh_body"
    if indent == 0:
        return "zero"
    return "other"


def should_drop(text: str) -> bool:
    for pat in DROP_PATTERNS:
        if pat.search(text):
            return True
    return False


def clean_text(text: str) -> str:
    for pat in PARAM_PATTERNS:
        text = pat.sub("", text)
    text = re.sub(r"\[\s*\]", "", text)   # dangling empty brackets
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

def parse_nist(raw_lines: list, chapter3_start: int, chapter3_end: int,
               min_words: int, max_words: int) -> tuple:
    """
    Parse Chapter 3 of NIST SP 800-53r5 into structured sentence-level units.
    Returns (units, stats).
    """
    body = raw_lines[chapter3_start - 1 : chapter3_end - 1]

    # ------------------------------------------------------------------
    # Pass 1: assign each line a structural level, drop noise lines
    # ------------------------------------------------------------------
    classified = []  # list of (level, stripped_content)

    for raw in body:
        content = raw.rstrip()
        stripped = content.strip()
        if not stripped:
            continue
        indent = measure_indent(content)
        level  = classify_indent(indent)
        if level in ("zero", "other"):
            continue
        if should_drop(stripped):
            continue
        classified.append((level, stripped))

    # ------------------------------------------------------------------
    # Pass 2: state machine groups lines into section blocks, emits units
    # ------------------------------------------------------------------
    current_control_id   = ""
    current_control_name = ""
    current_enh_num      = ""
    current_section      = ""

    section_buffer: list = []
    units        = []
    unit_counter = 1

    stats = {
        "controls_found":      0,
        "enhancements_found":  0,
        "sentences_extracted": 0,
        "units_too_short":     0,
        "units_emitted":       0,
    }

    def flush_buffer():
        nonlocal unit_counter
        if not section_buffer or not current_section:
            section_buffer.clear()
            return

        joined = clean_text(" ".join(section_buffer))
        section_buffer.clear()

        if not joined:
            return

        for sent in split_sentences(joined):
            sent = clean_text(sent)
            wc   = len(sent.split())
            stats["sentences_extracted"] += 1

            if wc < min_words:
                stats["units_too_short"] += 1
                continue

            enh_id = (f"{current_control_id}({current_enh_num})"
                      if current_enh_num else "")

            units.append({
                "unit_id":        f"NIST-U{unit_counter:05d}",
                "text":           sent,
                "control_id":     current_control_id,
                "control_name":   current_control_name,
                "section_type":   current_section,
                "enhancement_id": enh_id,
                "word_count":     wc,
            })
            unit_counter += 1
            stats["units_emitted"] += 1

    for level, content in classified:

        # --------------------------------------------------------------
        # Control ID line (indent ~94)
        # --------------------------------------------------------------
        if level == "control_id":
            m = CONTROL_ID_RE.match(content)
            if m:
                flush_buffer()
                current_control_id   = m.group(1).strip()
                current_control_name = m.group(2).strip()
                current_enh_num      = ""
                current_section      = ""
                stats["controls_found"] += 1
            continue

        # --------------------------------------------------------------
        # Base body lines (indent ~103)
        # --------------------------------------------------------------
        if level == "base_body":

            # Enhancement header: "(3) ACCESS ENFORCEMENT | ..."
            enh_m = ENHANCEMENT_HEADER_RE.match(content)
            if enh_m:
                flush_buffer()
                current_enh_num = enh_m.group(1)
                current_section = "enhancement_statement"
                stats["enhancements_found"] += 1
                continue

            # Discussion: label
            if DISCUSSION_PREFIX_RE.match(content):
                flush_buffer()
                current_section = (
                    "enhancement_discussion" if current_enh_num
                    else "base_discussion"
                )
                remainder = DISCUSSION_PREFIX_RE.sub("", content).strip()
                if remainder:
                    section_buffer.append(remainder)
                continue

            # Control: label — opens base control statement, resets enhancement
            if CONTROL_PREFIX_RE.match(content):
                flush_buffer()
                current_section = "control_statement"
                current_enh_num = ""
                remainder = CONTROL_PREFIX_RE.sub("", content).strip()
                if remainder:
                    section_buffer.append(remainder)
                continue

            # Continuation of current section
            section_buffer.append(content)
            continue

        # --------------------------------------------------------------
        # Enhancement body lines (indent ~110)
        # --------------------------------------------------------------
        if level == "enh_body":

            if DISCUSSION_PREFIX_RE.match(content):
                flush_buffer()
                current_section = "enhancement_discussion"
                remainder = DISCUSSION_PREFIX_RE.sub("", content).strip()
                if remainder:
                    section_buffer.append(remainder)
                continue

            section_buffer.append(content)
            continue

    flush_buffer()
    return units, stats


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Preprocess NIST SP 800-53r5 into sentence-level units for CE pipeline."
    )
    parser.add_argument("--input_txt",      required=True,
                        help="Path to raw pdftotext -layout output of NIST SP 800-53r5")
    parser.add_argument("--output_csv",     required=True,
                        help="Path for output CSV")
    parser.add_argument("--chapter3_start", type=int, default=2352,
                        help="1-indexed line where Chapter 3 content begins (default: 2352)")
    parser.add_argument("--chapter3_end",   type=int, default=22614,
                        help="1-indexed line where Chapter 3 ends (default: 22614)")
    parser.add_argument("--min_words",      type=int, default=8,
                        help="Minimum words per unit; shorter units are dropped (default: 8)")
    parser.add_argument("--max_words",      type=int, default=150,
                        help="Units longer than this are flagged in stats but still emitted "
                             "(default: 150)")
    args = parser.parse_args()

    print(f"Reading {args.input_txt} ...")
    with open(args.input_txt, encoding="utf-8", errors="replace") as f:
        raw_lines = f.readlines()
    print(f"  Total lines in file: {len(raw_lines)}")
    print(f"  Processing lines {args.chapter3_start}–{args.chapter3_end} (Chapter 3)")

    units, stats = parse_nist(
        raw_lines,
        chapter3_start=args.chapter3_start,
        chapter3_end=args.chapter3_end,
        min_words=args.min_words,
        max_words=args.max_words,
    )

    os.makedirs(os.path.dirname(os.path.abspath(args.output_csv)), exist_ok=True)

    fieldnames = ["unit_id", "text", "control_id", "control_name",
                  "section_type", "enhancement_id", "word_count"]

    with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(units)

    long_count    = sum(1 for u in units if int(u["word_count"]) > args.max_words)
    section_counts = Counter(u["section_type"] for u in units)

    print(f"\nPreprocessing complete")
    print(f"  Controls found:          {stats['controls_found']}")
    print(f"  Enhancements found:      {stats['enhancements_found']}")
    print(f"  Sentences extracted:     {stats['sentences_extracted']}")
    print(f"  Units dropped (<{args.min_words}w):    {stats['units_too_short']}")
    print(f"  Units flagged (>{args.max_words}w):   {long_count} (still emitted)")
    print(f"  Units emitted:           {stats['units_emitted']}")
    print(f"\n  Units by section_type:")
    for stype in ["base_discussion", "enhancement_discussion",
                  "control_statement", "enhancement_statement"]:
        print(f"    {stype:<30s} {section_counts.get(stype, 0):5d}")
    print(f"\nSaved: {args.output_csv}")


if __name__ == "__main__":
    main()