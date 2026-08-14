"""
02_run_ce_pipeline.py
=====================
Claims-Evidence (CE) classification for SPID.

Labels each sentence-level unit of a text corpus as Claim or Evidence using the
fine-tuned RoBERTa-base classifier. The CE label records how reasoning is
distributed within an explanation. It does not filter which units the principle
detector sees. Every classified unit is passed downstream.

This script is corpus-agnostic. It reads any CSV, provided you name the column
holding the text. It supports two input shapes:

  Segmenting mode (default)
      One row per document, comment or answer. Each row is split into
      sentence-level units with NLTK before classification. Use this for
      community Q&A text such as Security Stack Exchange, Server Fault or
      Stack Overflow.

  Pre-segmented mode (--no-segment)
      One row per unit, already segmented by a preprocessing script such as
      01_segment_text.py. Use this for standards documents such as NIST 800-53,
      NIST 800-207 or OWASP ASVS.

All columns from the input CSV are preserved in the output.

Usage:

    # Community Q&A, one comment per row
    python 02_run_ce_pipeline.py \
        --input_csv  data/input/sse_500_anonymised.csv \
        --model_dir  models/ce_classifier \
        --output_csv results/sse_ce_units.csv \
        --text_col   Comment \
        --label_col  "Evidence of Security Principle" \
        --summary    results/sse_ce_summary.csv

    # Pre-segmented standards text, one unit per row
    python 02_run_ce_pipeline.py \
        --input_csv  data/input/segmented_units/nist80053_5085_units.csv \
        --model_dir  models/ce_classifier \
        --output_csv results/nist_ce_units.csv \
        --no-segment \
        --text_col   text \
        --group_by   control_id \
        --summary    results/nist_ce_summary.csv

Output CSV:
    All input columns, plus
        unit_id         sequential index within the group
        text            the unit text
        ce_label        Claim or Evidence
        raw_label       the model's original prediction before Argument collapse
        confidence      softmax probability of the predicted class
        low_confidence  True when confidence falls below --confidence_threshold
        prob_claim, prob_argument, prob_evidence

Note on the Argument class. The classifier retains the three CyBOK classes for
compatibility with the training data. Bridging Argument sentences are rare in
security text, so Argument predictions are collapsed into whichever of Claim or
Evidence the model scored higher. The original prediction is kept in raw_label.
Whether a unit argues for a design principle is a separate question, decided by
Stage 1 of the principle detector, not by the CE label.
"""

import argparse
import csv
import logging
import os
import sys
from collections import defaultdict

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# Order must match the label ids the classifier was trained with.
LABELS = ["Claim", "Argument", "Evidence"]

MIN_FRAGMENT_WORDS = 5


def require_column(rows, column, flag_name, input_path):
    """Exit with a readable message when a named column is absent."""
    if column is None:
        return
    if not rows:
        logger.error(f"{input_path} contains no data rows.")
        sys.exit(1)
    if column not in rows[0]:
        available = ", ".join(rows[0].keys())
        logger.error(
            f"Column '{column}' given by {flag_name} was not found in {input_path}.\n"
            f"Available columns: {available}"
        )
        sys.exit(1)


def segment_text(text):
    """Split a document into sentences, merging very short fragments."""
    from nltk.tokenize import sent_tokenize

    try:
        sentences = sent_tokenize(text)
    except LookupError:
        import nltk

        nltk.download("punkt", quiet=True)
        nltk.download("punkt_tab", quiet=True)
        sentences = sent_tokenize(text)

    merged = []
    for sentence in sentences:
        sentence = sentence.strip()
        if not sentence:
            continue
        if merged and len(sentence.split()) < MIN_FRAGMENT_WORDS:
            merged[-1] = merged[-1] + " " + sentence
        else:
            merged.append(sentence)
    return merged


def classify(texts, model, tokenizer, device, batch_size, threshold):
    """Classify a list of unit texts. Returns one result dict per text."""
    results = []
    for start in range(0, len(texts), batch_size):
        batch = texts[start:start + batch_size]
        encoded = tokenizer(
            batch,
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt",
        ).to(device)

        with torch.no_grad():
            logits = model(**encoded).logits
            probs = torch.softmax(logits, dim=-1)
            preds = torch.argmax(probs, dim=-1)

        for i, (pred, prob) in enumerate(zip(preds, probs)):
            raw_label = LABELS[pred.item()]
            confidence = prob[pred.item()].item()
            prob_claim = prob[0].item()
            prob_evidence = prob[2].item()

            # Collapse Argument into the more probable of Claim or Evidence.
            if raw_label == "Argument":
                ce_label = "Claim" if prob_claim >= prob_evidence else "Evidence"
            else:
                ce_label = raw_label

            results.append({
                "text": batch[i],
                "ce_label": ce_label,
                "raw_label": raw_label,
                "confidence": round(confidence, 4),
                "low_confidence": confidence < threshold,
                "prob_claim": round(prob_claim, 4),
                "prob_argument": round(prob[1].item(), 4),
                "prob_evidence": round(prob_evidence, 4),
            })
    return results


def summarise(group_key, group_by_col, units):
    """Structural summary for one group of units."""
    n_units = len(units)
    n_claims = sum(1 for u in units if u["ce_label"] == "Claim")
    n_evidence = sum(1 for u in units if u["ce_label"] == "Evidence")
    n_low = sum(1 for u in units if u["low_confidence"])
    mean_conf = sum(u["confidence"] for u in units) / n_units if n_units else 0.0

    return {
        "group_key": group_key,
        "group_by_col": group_by_col,
        "n_units": n_units,
        "n_claims": n_claims,
        "n_evidence": n_evidence,
        "evidence_ratio": round(n_evidence / n_units, 3) if n_units else 0.0,
        "n_low_confidence": n_low,
        "mean_confidence": round(mean_conf, 3),
    }


def write_csv(path, fieldnames, rows):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(
        description="Corpus-agnostic CE classification for SPID."
    )
    parser.add_argument("--input_csv", required=True,
                        help="Input CSV. One row per document, or one row per "
                             "unit when --no-segment is set.")
    parser.add_argument("--model_dir", required=True,
                        help="Directory holding the fine-tuned CE classifier.")
    parser.add_argument("--output_csv", required=True,
                        help="Per-unit output CSV.")
    parser.add_argument("--summary", default=None,
                        help="Optional per-group summary CSV.")
    parser.add_argument("--text_col", default="text",
                        help="Column holding the text. Default 'text'.")
    parser.add_argument("--label_col", default=None,
                        help="Optional existing label column to carry through, "
                             "for example a corpus annotation. Purely passed "
                             "through and never used by the classifier.")
    parser.add_argument("--group_by", default=None,
                        help="Column to group units by for the summary. In "
                             "segmenting mode this defaults to the source row.")
    parser.add_argument("--segment", dest="segment", action="store_true",
                        help="Segment each row into sentences. This is the default.")
    parser.add_argument("--no-segment", dest="segment", action="store_false",
                        help="Treat each input row as an already-segmented unit.")
    parser.set_defaults(segment=True)
    parser.add_argument("--batch_size", type=int, default=32)
    parser.add_argument("--encoding", default="utf-8",
                        help="Input file encoding. Default 'utf-8'.")
    parser.add_argument("--confidence_threshold", type=float, default=0.6,
                        help="Units scoring below this are flagged in the "
                             "low_confidence column. They keep their label and "
                             "are still passed downstream. Default 0.6.")
    args = parser.parse_args()

    with open(args.input_csv, encoding=args.encoding, newline="") as handle:
        input_rows = list(csv.DictReader(handle))
    logger.info(f"Loaded {len(input_rows)} rows from {args.input_csv}")

    require_column(input_rows, args.text_col, "--text_col", args.input_csv)
    require_column(input_rows, args.label_col, "--label_col", args.input_csv)
    require_column(input_rows, args.group_by, "--group_by", args.input_csv)

    input_cols = list(input_rows[0].keys())

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Loading CE classifier from {args.model_dir} on {device}")
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(args.model_dir)
    model.to(device)
    model.eval()

    # Build the flat list of units, remembering which input row each came from.
    unit_texts = []
    unit_sources = []

    if args.segment:
        for row_idx, row in enumerate(input_rows):
            text = (row.get(args.text_col) or "").strip()
            if not text:
                continue
            for sentence in segment_text(text):
                unit_texts.append(sentence)
                unit_sources.append(row_idx)
        logger.info(
            f"Segmented {len(input_rows)} rows into {len(unit_texts)} units"
        )
    else:
        for row_idx, row in enumerate(input_rows):
            text = (row.get(args.text_col) or "").strip()
            if not text:
                continue
            unit_texts.append(text)
            unit_sources.append(row_idx)
        logger.info(f"Read {len(unit_texts)} pre-segmented units")

    if not unit_texts:
        logger.error(
            f"No usable text found in column '{args.text_col}'. "
            "Check --text_col and --encoding."
        )
        sys.exit(1)

    classified = classify(
        unit_texts, model, tokenizer, device,
        args.batch_size, args.confidence_threshold,
    )

    # Attach the originating row's metadata to each unit.
    for unit, row_idx in zip(classified, unit_sources):
        source = input_rows[row_idx]
        for key, value in source.items():
            if key != args.text_col:
                unit.setdefault(key, value)
        unit["source_row"] = row_idx

    # Group for summary and for unit numbering.
    group_col = args.group_by if args.group_by else "source_row"
    groups = defaultdict(list)
    for unit in classified:
        groups[unit[group_col]].append(unit)

    all_units = []
    summaries = []
    for group_key, group_units in groups.items():
        for position, unit in enumerate(group_units):
            unit["unit_id"] = position
        summaries.append(summarise(group_key, group_col, group_units))
        all_units.extend(group_units)

    passthrough = [c for c in input_cols if c != args.text_col]
    ce_cols = ["source_row", "unit_id", "text", "ce_label", "raw_label",
               "confidence", "low_confidence",
               "prob_claim", "prob_argument", "prob_evidence"]
    write_csv(args.output_csv, ce_cols + passthrough, all_units)
    logger.info(f"Wrote {len(all_units)} units to {args.output_csv}")

    if args.summary:
        summary_cols = ["group_key", "group_by_col", "n_units", "n_claims",
                        "n_evidence", "evidence_ratio", "n_low_confidence",
                        "mean_confidence"]
        write_csv(args.summary, summary_cols, summaries)
        logger.info(f"Wrote {len(summaries)} group summaries to {args.summary}")

    total_claims = sum(s["n_claims"] for s in summaries)
    total_evidence = sum(s["n_evidence"] for s in summaries)
    total_low = sum(s["n_low_confidence"] for s in summaries)

    print("\n" + "=" * 60)
    print(f"CE PIPELINE SUMMARY, grouped by {group_col}")
    print("=" * 60)
    print(f"  Units classified: {len(all_units)}")
    print(f"  Groups:           {len(summaries)}")
    print(f"  Claim:            {total_claims}")
    print(f"  Evidence:         {total_evidence}")
    pct = 100 * total_low / len(all_units) if all_units else 0
    print(f"  Low confidence:   {total_low} ({pct:.2f}% below "
          f"{args.confidence_threshold})")


if __name__ == "__main__":
    main()
