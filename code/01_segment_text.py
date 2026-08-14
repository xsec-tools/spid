"""
01_segment_text.py  (v2)
========================
Preprocesses raw text documents into sentence-level units ready for CE
classification. v2 adds improved handling for:
  - Section headings fused to first sentence (PDF extraction artefact)
  - Short continuation/fragment sentences merged with predecessor
  - Page headers/footers interleaved in body text
  - Reference/bibliography entries
  - Inline citation markers
  - Sentence fragments that should be merged with neighbours

Usage:
    python 01_segment_text.py \
        --input_file path/to/raw_text.txt \
        --output_csv path/to/sentences.csv \
        --source_id AC \
        --min_words 8 \
        --max_words 150

Dependencies: nltk
    pip install nltk
    python -c "import nltk; nltk.download('punkt')"
"""

import csv
import os
import re
import argparse

try:
    import nltk
    from nltk.tokenize import sent_tokenize
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False
    print("WARNING: nltk not available. Falling back to regex sentence splitting.")

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

PAGE_HEADER_RE = re.compile(
    r"KA\s+\w[\w\s]+\|\s+\w+\s+\d{4}\s+Page\s+\d+",
    re.IGNORECASE
)

SECTION_HEADING_RE = re.compile(
    r"^\d+(\.\d+)*\s+[A-Z][A-Za-z\s\-:,]{2,60}$"
)

REFERENCE_RE = re.compile(
    r"^\[\d+\]\s+\w|^Available:\s+https?://|^https?://|"
    r"^\[Online\]\.|^doi:|^pp\.\s+\d|^\d{4},\s+pp\."
)

# Abbreviation/glossary entries: "DHIES Diffie-Hellman Integrated..."
ABBREV_RE = re.compile(r"^[A-Z]{2,8}\s+[A-Z][a-zA-Z\s\-]+\.$")

PAGE_NUM_RE = re.compile(r"^\s*\d+\s*$")

FORM_FEED_RE = re.compile(r"\f")

FUSED_HEADING_RE = re.compile(
    r"^(\d+(\.\d+)*\s+[A-Z][A-Za-z\s\-:,]{2,60})\n(.+)",
    re.MULTILINE
)

FRAGMENT_STARTERS = re.compile(
    r"^(Rather,|However,|Therefore,|Thus,|Hence,|"
    r"Moreover,|Furthermore,|Additionally,|Also,|"
    r"Instead,|Nevertheless,|Nonetheless,|"
    r"For example,|For instance,|In particular,|"
    r"That is,|i\.e\.,|e\.g\.,|"
    r"As (a result|such|noted|mentioned|discussed|described|shown|above|below),|"
    r"In (this|the) (case|context|sense|way|section|chapter),|"
    r"It (is|was|has|should|must|can|could|will|would) (noted|worth|important))",
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Cleaning functions
# ---------------------------------------------------------------------------

def clean_raw_text(text):
    text = FORM_FEED_RE.sub("\n\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"-\n\s*([a-z])", r"\1", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def split_paragraphs(text):
    return [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]


def is_page_header(text):
    return bool(PAGE_HEADER_RE.search(text))


def is_reference_entry(text):
    return bool(REFERENCE_RE.match(text.strip()))


def is_abbreviation_entry(text):
    """Detect glossary/abbreviation entries like 'AES Advanced Encryption Standard.'"""
    return bool(ABBREV_RE.match(text.strip()))

def is_page_number(text):
    return bool(PAGE_NUM_RE.match(text.strip()))


def is_heading_only(text):
    lines = text.strip().split("\n")
    if len(lines) == 1:
        return bool(SECTION_HEADING_RE.match(text.strip()))
    return False


def extract_fused_heading(text):
    match = FUSED_HEADING_RE.match(text.strip())
    if match:
        return match.group(1).strip(), match.group(3).strip()
    heading_inline = re.match(
        r"^(\d+(\.\d+)*\s+[A-Z][A-Za-z\s\-:]{2,40})\s{2,}([A-Z].+)",
        text.strip()
    )
    if heading_inline:
        return heading_inline.group(1).strip(), heading_inline.group(3).strip()
    return None, text


def split_sentences(text):
    if NLTK_AVAILABLE:
        try:
            return [s.strip() for s in sent_tokenize(text) if s.strip()]
        except Exception:
            pass
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+(?=[A-Z])", text) if s.strip()]


def merge_fragments(sentences, min_words):
    if not sentences:
        return sentences
    merged = [sentences[0]]
    for sent in sentences[1:]:
        word_count = len(sent.split())
        is_fragment = (
            word_count < min_words or
            bool(FRAGMENT_STARTERS.match(sent))
        )
        if is_fragment and merged:
            merged[-1] = merged[-1].rstrip() + " " + sent.strip()
        else:
            merged.append(sent)
    return merged


def clean_sentence(text):
    text = re.sub(r"\n+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# ---------------------------------------------------------------------------
# Main segmentation
# ---------------------------------------------------------------------------

def segment_document(text, source_id, min_words=8, max_words=150):
    text = clean_raw_text(text)
    paragraphs = split_paragraphs(text)

    units = []
    stats = {
        "paragraphs_total":     len(paragraphs),
        "paragraphs_skipped":   0,
        "headings_extracted":   0,
        "fragments_merged":     0,
        "units_too_short":      0,
        "units_too_long":       0,
        "references_dropped":   0,
        "page_headers_dropped": 0,
    }

    unit_counter = 1

    for para_idx, para in enumerate(paragraphs):
        para_id = f"{source_id}-P{para_idx+1:03d}"

        if is_page_header(para):
            stats["page_headers_dropped"] += 1
            stats["paragraphs_skipped"] += 1
            continue

        if is_page_number(para):
            stats["paragraphs_skipped"] += 1
            continue

        if is_reference_entry(para):
            stats["references_dropped"] += 1
            stats["paragraphs_skipped"] += 1
            continue

        if is_abbreviation_entry(para):
            stats["paragraphs_skipped"] += 1
            continue

        if is_heading_only(para):
            stats["paragraphs_skipped"] += 1
            continue

        heading, content = extract_fused_heading(para)
        if heading:
            stats["headings_extracted"] += 1

        sentences = split_sentences(content)

        before_merge = len(sentences)
        sentences = merge_fragments(sentences, min_words=min_words)
        stats["fragments_merged"] += before_merge - len(sentences)

        for sent in sentences:
            sent = clean_sentence(sent)
            word_count = len(sent.split())

            if is_reference_entry(sent):
                stats["references_dropped"] += 1
                continue

            if is_page_header(sent):
                stats["page_headers_dropped"] += 1
                continue

            if word_count < min_words:
                stats["units_too_short"] += 1
                continue

            if word_count > max_words:
                stats["units_too_long"] += 1

            unit_id = f"{source_id}-U{unit_counter:04d}"
            units.append({
                "unit_id":           unit_id,
                "text":              sent,
                "source_para_id":    para_id,
                "ka":                source_id,
                "parent_id":         "",
                "word_count":        word_count,
                "extraction_method": "Automatic",
            })
            unit_counter += 1

    return units, stats


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", required=True)
    parser.add_argument("--output_csv", required=True)
    parser.add_argument("--source_id",  required=True)
    parser.add_argument("--min_words",  type=int, default=8)
    parser.add_argument("--max_words",  type=int, default=150)
    args = parser.parse_args()

    print(f"Reading {args.input_file}...")
    with open(args.input_file, "r", encoding="utf-8") as f:
        raw_text = f.read()

    print("Segmenting...")
    units, stats = segment_document(
        raw_text,
        source_id=args.source_id,
        min_words=args.min_words,
        max_words=args.max_words,
    )

    print(f"\nSegmentation complete:")
    print(f"  Paragraphs total:     {stats['paragraphs_total']}")
    print(f"  Paragraphs skipped:   {stats['paragraphs_skipped']}")
    print(f"  Page headers dropped: {stats['page_headers_dropped']}")
    print(f"  References dropped:   {stats['references_dropped']}")
    print(f"  Headings extracted:   {stats['headings_extracted']}")
    print(f"  Fragments merged:     {stats['fragments_merged']}")
    print(f"  Units too short:      {stats['units_too_short']}")
    print(f"  Units too long:       {stats['units_too_long']}")
    print(f"  Final units:          {len(units)}")

    os.makedirs(os.path.dirname(os.path.abspath(args.output_csv)), exist_ok=True)
    fieldnames = ["unit_id", "text", "source_para_id", "ka",
                  "parent_id", "word_count", "extraction_method"]

    with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(units)

    print(f"\nSaved: {args.output_csv}")


if __name__ == "__main__":
    main()