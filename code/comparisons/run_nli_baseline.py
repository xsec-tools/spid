"""
run_nli_baseline.py
====================
Zero-shot NLI baseline for principle-grounded reasoning detection.

Two-step zero-shot classification, with NO staging, NO chain-of-thought,
and NO few-shot examples:

  Step 1 — Presence: is the text making a normative security design
           argument at all? (entailment-style binary decision)
  Step 2 — Principle: if Step 1 is positive, which of the twelve Basin
           principles does the text's argument most resemble?

This is intended as an architecturally independent comparator to the
three-stage LLM pipeline (03_run_principle_pipeline.py). It uses a
general-purpose pretrained NLI/zero-shot model with no task-specific
fine-tuning, no chain-of-thought prompting, and no in-context examples —
only the bare principle definitions, used to construct hypothesis labels.

Usage:
    python run_nli_baseline.py \\
        --input_csv  data/evaluation/evaluation_ground_truth_v2.csv \\
        --output_csv results/nli_baseline_detections.csv \\
        --model_name MoritzLaurer/deberta-v3-large-zeroshot-v2 \\
        [--presence_threshold 0.5] \\
        [--batch_size 16] \\
        [--resume] \\
        [--limit 10]

Input CSV:
  Must have a 'text' column. Other columns (principle, principle_normalised,
  response_type, persona, question_id) are preserved if present.

Output CSV:
  Input columns preserved, plus:
    presence_label       — "YES" or "NO"
    presence_score       — entailment score for the positive presence label
    detected_principle   — top-scoring principle name, or "NONE" if presence is NO
    principle_score      — top-scoring principle's score (NaN if presence is NO)
    all_principle_scores — semicolon-separated "principle:score" for all 12
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Hypothesis labels
#
# Presence labels frame the binary decision as an entailment task: does the
# text entail a normative design argument, or merely describe / instruct
# without one?
#
# Principle hypotheses are built from the bare one-line definitions only —
# no discriminating rules, no examples. This keeps the baseline independent
# of the taxonomy engineering done for the staged pipeline's prompts.
# ---------------------------------------------------------------------------

PRESENCE_POSITIVE = (
    "this text argues that a specific security design choice causes a "
    "better security outcome"
)
PRESENCE_NEGATIVE = (
    "this text describes, instructs, or discusses security without arguing "
    "that a specific design choice causes a better security outcome"
)
PRESENCE_LABELS = [PRESENCE_POSITIVE, PRESENCE_NEGATIVE]


PRINCIPLE_ONE_LINERS = {
    "Simplicity":
        "security mechanisms should be kept as simple as possible, since "
        "simpler designs have fewer flaws and are easier to verify",
    "Open Design":
        "the security of a system should not depend on the secrecy of its "
        "protection mechanisms",
    "Compartmentalisation":
        "resources should be organised into isolated groups, so that "
        "compromise of one group does not spread to others",
    "Minimum Exposure":
        "the attack surface a system presents to an adversary should be "
        "minimised by reducing exposed interfaces and information",
    "Least Privilege":
        "any user, process, or component should operate with the minimum "
        "privileges necessary to do its job",
    "Minimum Trust and Maximum Trustworthiness":
        "trust placed in a system or component should be minimised, and its "
        "trustworthiness should be verified rather than assumed",
    "Secure Fail-Safe Defaults":
        "a system should default to and return to a secure, access-denying "
        "state whenever it fails or encounters an error",
    "Complete Mediation":
        "every access to every security-relevant object must be checked "
        "every time, with no gaps or cached permissions",
    "No Single Point of Failure":
        "security should rely on multiple independent, redundant "
        "mechanisms rather than a single mechanism",
    "Traceability":
        "security-relevant events should be logged so that incidents can be "
        "detected, investigated, and attributed",
    "Generating Secrets":
        "secrets such as keys, tokens, and passwords should be generated "
        "with high entropy to resist guessing or brute-force attacks",
    "Usability":
        "security mechanisms should be designed to be usable, since "
        "unusable security gets circumvented or misapplied",
}

ALL_PRINCIPLES = list(PRINCIPLE_ONE_LINERS.keys())

PRINCIPLE_LABELS = [
    f"this text argues for the principle that {desc}"
    for desc in PRINCIPLE_ONE_LINERS.values()
]
LABEL_TO_PRINCIPLE = dict(zip(PRINCIPLE_LABELS, ALL_PRINCIPLES))


# ---------------------------------------------------------------------------
# Resume / checkpointing helpers (mirrors 03_run_principle_pipeline.py)
# ---------------------------------------------------------------------------

def load_existing(output_csv: str) -> dict:
    if not os.path.exists(output_csv):
        return {}
    with open(output_csv, encoding="utf-8") as f:
        return {row["row_index"]: row for row in csv.DictReader(f)}


def _write_output(path: str, fieldnames: list, rows: list) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify_presence(classifier, text: str, threshold: float) -> tuple[str, float]:
    """
    Returns (presence_label, presence_score).
    presence_label is 'YES' if the positive hypothesis is top-ranked and its
    score is >= threshold, else 'NO'.
    """
    result = classifier(text, PRESENCE_LABELS, multi_label=False)
    top_label = result["labels"][0]
    top_score = result["scores"][0]

    # Find score for the positive label specifically, regardless of rank
    pos_idx = result["labels"].index(PRESENCE_POSITIVE)
    pos_score = result["scores"][pos_idx]

    if top_label == PRESENCE_POSITIVE and top_score >= threshold:
        return "YES", pos_score
    return "NO", pos_score


def classify_principle(classifier, text: str) -> tuple[str, float, dict]:
    """
    Returns (top_principle, top_score, all_scores_dict).
    """
    result = classifier(text, PRINCIPLE_LABELS, multi_label=False)
    top_label = result["labels"][0]
    top_score = result["scores"][0]
    top_principle = LABEL_TO_PRINCIPLE[top_label]

    all_scores = {
        LABEL_TO_PRINCIPLE[label]: score
        for label, score in zip(result["labels"], result["scores"])
    }
    return top_principle, top_score, all_scores


def process_row(classifier, text: str, threshold: float) -> dict:
    presence_label, presence_score = classify_presence(classifier, text, threshold)

    out = {
        "presence_label": presence_label,
        "presence_score": f"{presence_score:.4f}",
        "detected_principle": "NONE",
        "principle_score": "",
        "all_principle_scores": "",
    }

    if presence_label == "YES":
        top_principle, top_score, all_scores = classify_principle(classifier, text)
        out["detected_principle"] = top_principle
        out["principle_score"] = f"{top_score:.4f}"
        out["all_principle_scores"] = "; ".join(
            f"{p}:{s:.4f}" for p, s in sorted(all_scores.items(), key=lambda x: -x[1])
        )

    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Zero-shot NLI baseline for principle-grounded reasoning detection"
    )
    parser.add_argument("--input_csv", required=True,
                        help="Input CSV with a 'text' column")
    parser.add_argument("--output_csv", required=True,
                        help="Output CSV path")
    parser.add_argument("--model_name",
                        default="MoritzLaurer/deberta-v3-large-zeroshot-v2",
                        help="HF model for zero-shot-classification pipeline")
    parser.add_argument("--presence_threshold", type=float, default=0.5,
                        help="Minimum entailment score for the positive "
                             "presence label to count as YES")
    parser.add_argument("--batch_size", type=int, default=20,
                        help="Checkpoint every N processed rows")
    parser.add_argument("--resume", action="store_true",
                        help="Skip rows already present in the output CSV")
    parser.add_argument("--limit", type=int, default=None,
                        help="Process at most N rows")
    parser.add_argument("--device", type=int, default=0,
                        help="CUDA device index, or -1 for CPU")
    args = parser.parse_args()

    # Import here so --help works without GPU deps installed
    from transformers import pipeline

    # ── Load input ──────────────────────────────────────────────────────────
    with open(args.input_csv, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        input_fieldnames = list(reader.fieldnames)
        raw_rows = list(reader)

    rows = [
        r for r in raw_rows
        if r.get("text", "").strip() and r.get("text", "").strip() != "#ERROR!"
    ]
    logger.info(f"Loaded {len(rows)} valid rows from {args.input_csv}")

    if args.limit:
        rows = rows[: args.limit]
        logger.info(f"Limited to {len(rows)} rows")

    # ── Output schema ────────────────────────────────────────────────────────
    result_fields = [
        "presence_label",
        "presence_score",
        "detected_principle",
        "principle_score",
        "all_principle_scores",
    ]
    output_fieldnames = ["row_index"] + input_fieldnames + result_fields

    # ── Resume ───────────────────────────────────────────────────────────────
    existing = load_existing(args.output_csv) if args.resume else {}
    if existing:
        logger.info(f"Resume: {len(existing)} rows already done")

    # ── Load model ───────────────────────────────────────────────────────────
    logger.info(f"Loading zero-shot classifier: {args.model_name}")
    classifier = pipeline(
        "zero-shot-classification",
        model=args.model_name,
        device=args.device,
    )
    logger.info("Classifier loaded successfully")

    # ── Process ──────────────────────────────────────────────────────────────
    results = []
    n_total = len(rows)
    n_skipped = 0
    n_processed = 0
    t_start = time.time()

    for i, row in enumerate(rows):
        idx = str(i)
        text = row["text"].strip()

        out_row = {"row_index": idx}
        out_row.update(row)

        if idx in existing and existing[idx].get("presence_label", "").strip():
            out_row.update(existing[idx])
            results.append(out_row)
            n_skipped += 1
            continue

        logger.info(f"[{i + 1}/{n_total}] {text[:70]}...")

        try:
            stage_result = process_row(classifier, text, args.presence_threshold)
        except Exception as e:
            logger.error(f"  Error on row {idx}: {e}")
            stage_result = {
                "presence_label": "ERROR",
                "presence_score": "",
                "detected_principle": "ERROR",
                "principle_score": "",
                "all_principle_scores": str(e),
            }

        out_row.update(stage_result)
        results.append(out_row)
        n_processed += 1

        if n_processed % args.batch_size == 0:
            _write_output(args.output_csv, output_fieldnames, results)
            elapsed = time.time() - t_start
            rate = n_processed / elapsed if elapsed > 0 else 0
            remaining = (n_total - i - 1) / rate if rate > 0 else 0
            logger.info(
                f"Checkpoint: {n_processed} processed, {n_skipped} skipped | "
                f"{rate:.2f} rows/s | ETA {remaining / 60:.1f} min"
            )

    _write_output(args.output_csv, output_fieldnames, results)

    elapsed = time.time() - t_start
    logger.info("=" * 60)
    logger.info(
        f"Complete. {n_processed} processed, {n_skipped} skipped. "
        f"Time: {elapsed / 60:.1f} min"
    )

    # ── Summary stats ────────────────────────────────────────────────────────
    yes_count = sum(1 for r in results if r.get("presence_label") == "YES")
    no_count = sum(1 for r in results if r.get("presence_label") == "NO")
    error_count = sum(1 for r in results if r.get("presence_label") == "ERROR")
    logger.info(f"Presence → YES: {yes_count} | NO: {no_count} | ERROR: {error_count}")

    if "response_type" in input_fieldnames:
        for rtype in ("explicit", "implicit", "unrelated"):
            subset = [r for r in results if r.get("response_type") == rtype]
            if not subset:
                continue
            yes_sub = sum(1 for r in subset if r.get("presence_label") == "YES")
            logger.info(
                f"  response_type={rtype}: n={len(subset)}, "
                f"presence YES rate={yes_sub / len(subset):.3f}"
            )

    principle_dist: dict[str, int] = {}
    for r in results:
        p = r.get("detected_principle", "NONE")
        principle_dist[p] = principle_dist.get(p, 0) + 1
    logger.info("Detected principle distribution:")
    for p, cnt in sorted(principle_dist.items(), key=lambda x: -x[1]):
        logger.info(f"  {p}: {cnt}")


if __name__ == "__main__":
    main()