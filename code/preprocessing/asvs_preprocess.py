"""
preprocessing/asvs_preprocess.py
==================
Preprocesses the OWASP ASVS 5.0 CSV into a unit-level CSV ready for the
CE classification pipeline (02_run_ce_pipeline.py or equivalent).

Each requirement description is treated as a single unit. No sentence
splitting is performed: ASVS descriptions are self-contained single
sentences and splitting would produce fragments.

OUTPUT SCHEMA
-------------
unit_id         -- unique identifier, e.g. ASVS-U00001
text            -- requirement description text
req_id          -- e.g. V1.1.1
chapter_id      -- e.g. V1
chapter_name    -- e.g. Encoding and Sanitization
section_id      -- e.g. V1.2
section_name    -- e.g. Injection Prevention
level           -- 1, 2, or 3
word_count      -- integer

Usage:
    python preprocessing/asvs_preprocess.py \\
        --input_csv  data/OWASP_Application_Security_Verification_Standard_5_0_0_en.csv \\
        --output_csv data/input/segmented_units/asvs_344_units.csv \\
        [--min_words 8]
"""

import csv
import os
import re
import argparse
from collections import Counter


def clean_text(text: str) -> str:
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def main():
    parser = argparse.ArgumentParser(
        description="Preprocess OWASP ASVS 5.0 CSV into unit-level CSV for CE pipeline."
    )
    parser.add_argument("--input_csv",  required=True,
                        help="Path to OWASP ASVS CSV file")
    parser.add_argument("--output_csv", required=True,
                        help="Path for output CSV")
    parser.add_argument("--min_words",  type=int, default=8,
                        help="Minimum words per unit; shorter units are dropped (default: 8)")
    args = parser.parse_args()

    print(f"Reading {args.input_csv} ...")
    with open(args.input_csv, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    print(f"  Rows loaded: {len(rows)}")

    units       = []
    unit_counter = 1
    dropped     = 0

    for row in rows:
        text = clean_text(row["req_description"])
        wc   = len(text.split())

        if wc < args.min_words:
            dropped += 1
            continue

        units.append({
            "unit_id":      f"ASVS-U{unit_counter:05d}",
            "text":         text,
            "req_id":       row["req_id"].strip(),
            "chapter_id":   row["chapter_id"].strip(),
            "chapter_name": row["chapter_name"].strip(),
            "section_id":   row["section_id"].strip(),
            "section_name": row["section_name"].strip(),
            "level":        row["L"].strip(),
            "word_count":   wc,
        })
        unit_counter += 1

    os.makedirs(os.path.dirname(os.path.abspath(args.output_csv)), exist_ok=True)

    fieldnames = ["unit_id", "text", "req_id", "chapter_id", "chapter_name",
                  "section_id", "section_name", "level", "word_count"]

    with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(units)

    chapter_counts = Counter(u["chapter_name"] for u in units)
    level_counts   = Counter(u["level"] for u in units)

    print(f"\nPreprocessing complete")
    print(f"  Units emitted:        {len(units)}")
    print(f"  Units dropped (<{args.min_words}w): {dropped}")
    print(f"\n  Units by chapter:")
    for chapter, n in sorted(chapter_counts.items(), key=lambda x: -x[1]):
        print(f"    {n:3d}  {chapter}")
    print(f"\n  Units by level:")
    for level, n in sorted(level_counts.items()):
        print(f"    L{level}: {n}")
    print(f"\nSaved: {args.output_csv}")


if __name__ == "__main__":
    main()