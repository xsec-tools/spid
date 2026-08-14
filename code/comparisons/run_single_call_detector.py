"""
run_single_call_detector.py
=============================
Joint principle detection: evaluates all 12 Basin principles in a single
inference call per text, forcing the model to discriminate between
overlapping concepts.

Compared to the independent detection pipeline (12 calls per text), this:
  - Forces cross-principle discrimination in a single reasoning pass
  - Is 12x faster (180 calls vs 2,160 for the sample)
  - Should produce cleaner single-principle detections on single-principle data
  - May miss genuine multi-principle content (acceptable for synthetic validation)

Usage:
    python run_single_call_detector.py \
        --input_csv  data/input/synthetic_evaluation_set_1798.csv \
        --output_csv results/basin_joint_detections_v2.csv \
        --model_name meta-llama/Meta-Llama-3-70B-Instruct \
        --hf_token   $HF_TOKEN \
        [--batch_size 10] \
        [--max_new_tokens 1024] \
        [--resume] \
        [--limit 10]

Input CSV must have a 'text' column.
Output CSV: input columns + detected_principles + reasoning + principle_count
"""

import argparse
import csv
import os
import re
import sys
import time
import logging
from pathlib import Path

import torch
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Principle definitions (compact, for joint prompt)
# ---------------------------------------------------------------------------
PRINCIPLES = [
    "Simplicity",
    "Open Design",
    "Compartmentalization",
    "Minimum Exposure",
    "Least Privilege",
    "Minimum Trust and Maximum Trustworthiness",
    "Secure Fail-Safe Defaults",
    "Complete Mediation",
    "No Single Point of Failure",
    "Traceability",
    "Generating Secrets",
    "Usability",
]

PRINCIPLE_GUIDE = """
1. SIMPLICITY: Security mechanisms should be kept simple. Simpler designs have fewer flaws and are easier to verify. The text must argue that COMPLEXITY CAUSES security failures or that SIMPLICITY ENABLES assurance. Not just "keep it simple" as general advice — the argument must be that mechanism simplicity itself is the security benefit.

2. OPEN DESIGN: Security should not depend on secrecy of mechanisms (Kerckhoffs' principle). The text must argue that RELYING ON SECRECY OF DESIGN is a vulnerability, or that TRANSPARENCY of mechanisms enables better security through review. Not just "be transparent with users" — the mechanism itself must withstand public scrutiny.

3. COMPARTMENTALIZATION: Resources should be organised into isolated groups to contain compromise. The text must argue that ISOLATING COMPONENTS limits breach impact, prevents lateral movement, or contains damage to a single area. This is about architectural separation into compartments. Merely describing how to group users or organise permissions is NOT Compartmentalization — the text must argue that isolation CONTAINS DAMAGE.

4. MINIMUM EXPOSURE: The attack surface presented to adversaries should be minimised. The text must argue that REDUCING EXTERNAL INTERFACES, limiting disclosed information, or narrowing the window of opportunity prevents attacks. This is about what the adversary can see, reach, or interact with from outside.

5. LEAST PRIVILEGE: Subjects should operate with minimum necessary permissions. The text must argue that RESTRICTING PERMISSIONS of a specific subject reduces damage from compromise. This is about what an individual user/process is PERMITTED to do — not about isolating groups (that's Compartmentalization) or reducing external surface (that's Minimum Exposure).

6. MINIMUM TRUST AND MAXIMUM TRUSTWORTHINESS: Trust in components should be minimised; trustworthiness should be maximised through verification. The text must argue that TRUSTING WITHOUT VERIFICATION is the vulnerability, or that VERIFICATION REPLACES TRUST. The argument must be framed as a trust problem — not just "validate inputs" (which could be several principles).

7. SECURE FAIL-SAFE DEFAULTS: Systems should default to a secure state on failure. The text must argue that DEFAULTING TO DENIAL or a secure state on error/failure PREVENTS exploitation. This is specifically about what happens WHEN SOMETHING GOES WRONG — whitelist over blacklist, deny by default.

8. COMPLETE MEDIATION: Every access to every object must be checked every time. The text must argue that CONSISTENT, REPEATED CHECKING of every access is necessary, or that GAPS IN CHECKING are exploitable. This is about completeness of access control — not just "have access controls" but "check every single time."

9. NO SINGLE POINT OF FAILURE: Redundant security mechanisms should be built (defence in depth). The text must argue that MULTIPLE INDEPENDENT MECHANISMS provide resilience, or that RELYING ON ONE MECHANISM creates fragility. This is about redundancy and backup layers — not about isolating compartments (that's Compartmentalization).

10. TRACEABILITY: Security-relevant events should be logged for detection and accountability. The text must argue that THE ABILITY TO TRACE ACTIONS is what makes a security design effective — that without logging, breaches go undetected or actors cannot be held accountable. Merely describing HOW to set up logging, monitoring, or auditing tools (e.g. "enable audit logging in Exchange", "use a SIEM to aggregate logs") is NOT Traceability — it is practical advice. The text must argue WHY traceability matters for security outcomes.

11. GENERATING SECRETS: Secrets should have maximum entropy to resist guessing. The text must argue that SECRET QUALITY (randomness, unpredictability, entropy) matters for security. This is about the strength of the secrets themselves — not about who can access them (Least Privilege) or whether mechanisms are secret (Open Design).

12. USABILITY: Security mechanisms must be usable or they will be bypassed. The text must argue that UNUSABLE SECURITY gets circumvented or misapplied, harming security outcomes. This is about the human interface — not about mechanism simplicity (that's Simplicity).

CRITICAL DISCRIMINATION RULES:
- DESCRIPTIVE vs NORMATIVE: Texts that describe practical steps ("set up logging", "configure a firewall", "use this tool") without arguing WHY those steps improve security through a specific principle's reasoning contain NO principle. Practical how-to advice is NOT principle reasoning. The text must make an argument about security design, not just describe an action.
- Compartmentalization vs Minimum Exposure: Compartmentalization is about INTERNAL isolation between groups. Minimum Exposure is about reducing EXTERNAL attack surface.
- Compartmentalization vs No Single Point of Failure: Compartmentalization ISOLATES to contain damage. NSPF provides REDUNDANCY so failure of one mechanism doesn't compromise everything.
- Compartmentalization vs Least Privilege: Compartmentalization separates GROUPS of resources. Least Privilege restricts what a SINGLE SUBJECT can do.
- Minimum Trust vs Complete Mediation: Minimum Trust is about not assuming components are trustworthy. Complete Mediation is about checking EVERY access EVERY time.
- Simplicity vs Usability: Simplicity is about INTERNAL mechanism design. Usability is about the HUMAN interface to the mechanism.
- Traceability vs practical logging: Describing how to enable audit logs is NOT Traceability. Traceability requires arguing that the ABILITY TO TRACE is what makes the security design effective.
"""

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = f"""\
You are an expert in cybersecurity principles. Your task is to identify which \
security design principles are present in a given security explanation.

You must select ONLY the principles whose specific reasoning is directly \
expressed in the text. Many texts will contain NO principles at all — they \
may give practical advice, describe procedures, or discuss operational \
concerns without making any security design argument. NONE is the correct \
answer for these texts, and you should expect to answer NONE frequently.

A principle is PRESENT only if the text makes a normative claim: arguing \
WHY a specific design choice improves security through that principle's \
reasoning. Texts that describe WHAT to do, HOW things work, or give \
practical tips WITHOUT arguing why it matters for security do NOT contain \
any principle — answer NONE.

When a principle IS present, identify the BEST, MOST SPECIFIC match. Most \
texts with principles will contain exactly 1. Selecting 2 should be rare \
and only when genuinely distinct principle arguments are both made.

{PRINCIPLE_GUIDE}
"""

USER_PROMPT_TEMPLATE = """\
Security explanation:
"{text}"

Which Basin security design principle(s) are present in this explanation? \
Select ONLY principles whose specific reasoning is directly argued for — \
not principles that are merely tangentially related.

Respond in exactly this format:
<reasoning>
[For each candidate principle, explain in 1-2 sentences why it IS or IS NOT \
the best match. Focus on what makes this text specifically about one principle \
rather than another when concepts overlap.]
</reasoning>
<answer>[comma-separated list of principle names, or NONE]</answer>

Examples of correct answers:
<answer>Compartmentalization</answer>
<answer>Least Privilege, Traceability</answer>
<answer>NONE</answer>
"""

# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------
def load_model(model_name: str, hf_token: str):
    logger.info(f"Loading tokenizer: {model_name}")
    tokenizer = AutoTokenizer.from_pretrained(
        model_name, token=hf_token, padding_side="left",
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    logger.info("Configuring 4-bit quantisation (NF4)")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )

    logger.info(f"Loading model weights: {model_name}")
    model = AutoModelForCausalLM.from_pretrained(
        model_name, token=hf_token,
        quantization_config=bnb_config,
        device_map="auto", torch_dtype=torch.bfloat16,
    )
    model.eval()
    logger.info("Model loaded successfully")
    return tokenizer, model


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------
def build_chat_prompt(tokenizer, system_prompt, user_prompt):
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    return tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True,
    )


def run_inference(prompt, tokenizer, model, max_new_tokens=1024):
    inputs = tokenizer(
        prompt, return_tensors="pt", truncation=True, max_length=4096,
    ).to(model.device)
    input_len = inputs["input_ids"].shape[1]

    with torch.no_grad():
        output_ids = model.generate(
            **inputs, max_new_tokens=max_new_tokens,
            do_sample=False, temperature=1.0,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )
    generated = output_ids[0][input_len:]
    return tokenizer.decode(generated, skip_special_tokens=True).strip()


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------
ANSWER_RE = re.compile(r"<answer>\s*(.*?)\s*</answer>", re.IGNORECASE | re.DOTALL)
REASONING_RE = re.compile(r"<reasoning>(.*?)</reasoning>", re.DOTALL)


def parse_response(response):
    answer_match = ANSWER_RE.search(response)
    reasoning_match = REASONING_RE.search(response)

    reasoning = reasoning_match.group(1).strip() if reasoning_match else response

    if answer_match:
        raw_answer = answer_match.group(1).strip()
        if raw_answer.upper() == "NONE":
            return [], reasoning

        # Parse comma-separated principles, fuzzy match to canonical names
        detected = []
        for part in raw_answer.split(","):
            part = part.strip()
            if not part:
                continue
            # Try exact match first
            if part in PRINCIPLES:
                detected.append(part)
                continue
            # Fuzzy: case-insensitive partial match
            matched = False
            for p in PRINCIPLES:
                if part.lower() in p.lower() or p.lower() in part.lower():
                    detected.append(p)
                    matched = True
                    break
            if not matched:
                logger.warning(f"Could not match principle: '{part}'")

        return detected, reasoning
    else:
        logger.warning(f"Could not parse answer: {response[:100]}")
        return ["ERROR"], response


# ---------------------------------------------------------------------------
# Resume
# ---------------------------------------------------------------------------
def load_existing(output_csv):
    if not os.path.exists(output_csv):
        return {}
    with open(output_csv, encoding="utf-8") as f:
        return {row["row_index"]: row for row in csv.DictReader(f)}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Joint Basin principle detection (all 12 in one call)"
    )
    parser.add_argument("--input_csv", required=True)
    parser.add_argument("--output_csv", required=True)
    parser.add_argument("--model_name", default="meta-llama/Meta-Llama-3-70B-Instruct")
    parser.add_argument("--hf_token", default=os.environ.get("HF_TOKEN", ""))
    parser.add_argument("--batch_size", type=int, default=1)
    parser.add_argument("--max_new_tokens", type=int, default=1024)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    if not args.hf_token:
        logger.error("No HuggingFace token.")
        sys.exit(1)

    # Load input
    with open(args.input_csv, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        input_fieldnames = list(reader.fieldnames)
        raw_rows = list(reader)

    rows = [r for r in raw_rows if r["text"].strip() and r["text"].strip() != "#ERROR!"]
    logger.info(f"Loaded {len(rows)} rows")

    if args.limit:
        rows = rows[:args.limit]
        logger.info(f"Limited to {len(rows)} rows")

    # Output fieldnames
    output_fieldnames = ["row_index"] + input_fieldnames + [
        "detected_principles", "principle_count", "reasoning",
    ]

    # Resume
    existing = load_existing(args.output_csv) if args.resume else {}
    if existing:
        logger.info(f"Resume: {len(existing)} rows found")

    # Load model
    tokenizer, model = load_model(args.model_name, args.hf_token)

    # Process
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

        # Skip if done
        if idx in existing and existing[idx].get("detected_principles", "").strip():
            out_row.update(existing[idx])
            results.append(out_row)
            n_skipped += 1
            continue

        logger.info(f"[{i+1}/{n_total}] {text[:60]}...")

        user_prompt = USER_PROMPT_TEMPLATE.format(text=text)
        prompt = build_chat_prompt(tokenizer, SYSTEM_PROMPT, user_prompt)

        try:
            response = run_inference(
                prompt, tokenizer, model, args.max_new_tokens
            )
            detected, reasoning = parse_response(response)
        except Exception as e:
            logger.error(f"  Error on row {idx}: {e}")
            detected = ["ERROR"]
            reasoning = str(e)

        out_row["detected_principles"] = ", ".join(detected) if detected else "NONE"
        out_row["principle_count"] = len(detected) if detected != ["ERROR"] else -1
        out_row["reasoning"] = reasoning

        logger.info(f"  -> {out_row['detected_principles']} ({out_row['principle_count']})")

        results.append(out_row)
        n_processed += 1

        # Checkpoint
        if n_processed % args.batch_size == 0:
            _write_output(args.output_csv, output_fieldnames, results)
            elapsed = time.time() - t_start
            rate = n_processed / elapsed if elapsed > 0 else 0
            remaining = (n_total - i - 1) / rate if rate > 0 else 0
            logger.info(
                f"Checkpoint: {n_processed} done, {n_skipped} skipped. "
                f"{rate:.2f} rows/s, ETA {remaining/60:.1f} min"
            )

    _write_output(args.output_csv, output_fieldnames, results)

    elapsed = time.time() - t_start
    logger.info("=" * 60)
    logger.info(f"Complete. {n_processed} processed, {n_skipped} skipped. "
                f"Time: {elapsed/60:.1f} min")
    logger.info(f"Total inference calls: {n_processed}")

    # Quick stats
    counts = [int(r.get("principle_count", 0)) for r in results if r.get("principle_count", -1) != -1]
    if counts:
        avg = sum(counts) / len(counts)
        singles = sum(1 for c in counts if c == 1)
        zeros = sum(1 for c in counts if c == 0)
        multis = sum(1 for c in counts if c > 1)
        logger.info(f"Avg principles per text: {avg:.2f}")
        logger.info(f"Single: {singles}, None: {zeros}, Multi: {multis}")


def _write_output(path, fieldnames, rows):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()