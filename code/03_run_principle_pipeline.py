"""
03_run_principle_pipeline.py
==============================
Staged principle detection: three focused inference calls per text.

Stage 1 — Presence:   Is any principle reasoning present at all? (YES / NO)
Stage 2 — Family:     Which broad principle family? (one of 6 families)
Stage 3 — Principle:  Which specific principle within that family? (from 1–3 candidates)

Design rationale:
  - Stage 1 preserves the strong abstention behaviour of the joint detector.
  - Stage 2 narrows the decision space before fine-grained disambiguation.
  - Stage 3 applies targeted per-family discrimination rules from basin_principles.py.
  - Each stage is independently inspectable: failures can be attributed to
    Stage 1 (missed entirely), Stage 2 (wrong family), or Stage 3 (wrong principle).

Compared to the joint detector (comparisons/run_single_call_detector.py):
  - Better recall: each stage has a simpler decision with a smaller option space.
  - Same abstention quality: NONE is a dedicated Stage 1 decision, not competing
    with 12 labels.
  - More interpretable: stage outputs trace exactly where the decision diverged.
  - 3x the inference calls per text (cost acceptable given the recall gain).

Compared to running one independent call per principle (12 calls per text):
  - Better precision: Stage 1 gates the pipeline, preventing spurious detections.
  - Better discrimination: Stage 3 only compares 1–3 closely related principles.
  - 4x fewer calls than independent (3 vs 12 per text).

Usage:
    python 03_run_principle_pipeline.py \\
        --input_csv  data/input/synthetic_evaluation_set_1798.csv \\
        --output_csv results/basin_staged_detections.csv \\
        --model_name meta-llama/Meta-Llama-3-70B-Instruct \\
        --hf_token   $HF_TOKEN \\
        [--batch_size 10] \\
        [--max_new_tokens 512] \\
        [--use_context] \\
        [--context_column question_title] \\
        [--resume] \\
        [--limit 10]

Input CSV:
  Must have a 'text' column.
  Optionally a context column (default: 'question_title') if --use_context is set.

Output CSV:
  Input columns preserved, plus:
    principle_present     — YES or NO (Stage 1 output)
    selected_family       — family name or NONE (Stage 2 output)
    detected_principles   — comma-separated principle name(s) or NONE (Stage 3 output)
    principle_count       — integer count (0 = NONE, -1 = error)
    stage1_reasoning      — extracted reasoning from Stage 1
    stage2_reasoning      — extracted reasoning from Stage 2
    stage3_reasoning      — extracted reasoning from Stage 3
    stage1_raw_response   — full raw model output, Stage 1
    stage2_raw_response   — full raw model output, Stage 2
    stage3_raw_response   — full raw model output, Stage 3
    used_context          — TRUE or FALSE
"""

import argparse
import csv
import os
import re
import sys
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
# Principle → Family mapping
#
# Families group principles that share conceptual territory, so Stage 2
# narrows the Stage 3 decision to closely related concepts only.
# Within each family, Stage 3 must discriminate between similar principles —
# this is where the detailed per-principle rules from basin_principles.py
# are most useful.
# ---------------------------------------------------------------------------

FAMILY_MAP = {
    "Separation and Scope": [
        "Compartmentalisation",
        "Minimum Exposure",
        "Least Privilege",
    ],
    "Trust and Verification": [
        "Minimum Trust and Maximum Trustworthiness",
        "Secure Fail-Safe Defaults",
        "Complete Mediation",
    ],
    "Redundancy and Observability": [
        "No Single Point of Failure",
        "Traceability",
    ],
    "Cryptographic Hygiene": [
        "Generating Secrets",
    ],
    "Design Philosophy": [
        "Simplicity",
        "Open Design",
    ],
    "Human Factors": [
        "Usability",
    ],
}

# Inverse map: principle → family (for validation)
PRINCIPLE_TO_FAMILY = {
    p: fam for fam, principles in FAMILY_MAP.items() for p in principles
}

ALL_PRINCIPLES = list(PRINCIPLE_TO_FAMILY.keys())
ALL_FAMILIES = list(FAMILY_MAP.keys())


# ---------------------------------------------------------------------------
# Stage 1 prompt — Presence detection
#
# Goal: separate "no principle reasoning" from "something principle-like".
# This is a binary decision, so the model can focus entirely on the
# descriptive-normative distinction without having to choose between labels.
# ---------------------------------------------------------------------------

STAGE1_SYSTEM = """\
You are an expert in cybersecurity security design principles. Your task is \
to determine whether a given text contains security design principle reasoning.

WHAT COUNTS AS PRINCIPLE REASONING:
A text contains principle reasoning if it makes a normative claim — arguing \
WHY a specific design or architectural choice improves security. The text \
must go beyond describing WHAT to do or HOW something works. It must argue \
that a specific design property (isolation, minimal access, redundancy, \
simplicity, etc.) IS the reason a system becomes more secure.

WHAT DOES NOT COUNT:
- Practical instructions without a security rationale ("use a password manager")
- Descriptions of how systems work without a normative claim
- Operational or procedural advice that doesn't argue WHY the design matters
- Risk mentions without a design-level argument
- User training or awareness advice

The security design principles you should be sensitive to include:
  Simplicity, Open Design, Compartmentalisation, Minimum Exposure,
  Least Privilege, Minimum Trust and Maximum Trustworthiness,
  Secure Fail-Safe Defaults, Complete Mediation, No Single Point of Failure,
  Traceability, Generating Secrets, Usability.

Err on the side of NO. You should answer YES only when the text makes a \
genuine normative claim connecting a design property to a security outcome. \
Texts that give reasonable practical advice, describe system behaviour, or \
discuss operational concerns without a design-level argument should be NO.
"""

STAGE1_USER_TEMPLATE = """\
{context_block}Security text:
"{text}"

Does this text contain security design principle reasoning — a normative \
claim that a specific design or architectural property causes better security \
outcomes?

Respond in exactly this format:
<reasoning>
[1–3 sentences: is there a normative design argument here, or is this purely \
descriptive / procedural / operational?]
</reasoning>
<answer>YES</answer>  or  <answer>NO</answer>
"""


# ---------------------------------------------------------------------------
# Stage 2 prompt — Family classification
#
# Goal: narrow the decision space before principle-level disambiguation.
# The model picks one family from a short list rather than one of 12 principles.
# ---------------------------------------------------------------------------

STAGE2_SYSTEM = """\
You are an expert in cybersecurity security design principles. A text has \
been flagged as containing security design principle reasoning. Your task is \
to identify which broad family of principles the text's reasoning belongs to.

THE FAMILIES AND WHAT THEY COVER:

1. Separation and Scope
   About isolating components, limiting access, and controlling what is \
exposed. Covers: Compartmentalisation (isolating resource groups to contain \
breach), Minimum Exposure (reducing the attack surface presented externally), \
Least Privilege (restricting what an individual subject can do).
   Key signal: isolation, separation, access restriction, attack surface, \
lateral movement, need-to-know.

2. Trust and Verification
   About how much to trust components and how to check access. Covers: \
Minimum Trust and Maximum Trustworthiness (don't assume components are \
trustworthy; verify), Secure Fail-Safe Defaults (deny by default; fail \
securely), Complete Mediation (check every access every time, not just once).
   Key signal: trust assumptions, verification, defaults, fail-secure, \
access checks, whitelists.

3. Redundancy and Observability
   About resilience and visibility. Covers: No Single Point of Failure \
(multiple independent mechanisms provide resilience), Traceability (log \
events for detection and accountability).
   Key signal: redundancy, defence in depth, logging, audit trails, \
detection, accountability, backup mechanisms.

4. Cryptographic Hygiene
   About the quality and generation of secrets. Covers: Generating Secrets \
(secrets must have high entropy to resist guessing).
   Key signal: randomness, entropy, token generation, key generation, \
unpredictability of secrets.

5. Design Philosophy
   About how security systems are designed and whether their mechanisms \
should be public. Covers: Simplicity (simple mechanisms are more verifiable \
and have fewer flaws), Open Design (security should not depend on design \
secrecy; mechanisms should withstand public scrutiny).
   Key signal: complexity, simplicity, verifiability, obscurity, \
Kerckhoffs' principle, openness of mechanism.

6. Human Factors
   About whether security mechanisms can be used correctly by people. \
Covers: Usability (unusable security gets circumvented, harming outcomes).
   Key signal: user interface, ease of use, circumvention, user errors, \
psychological acceptability.

Pick the single family whose reasoning most closely matches the text's \
security argument. If the text touches multiple families, pick the primary one.
"""

STAGE2_USER_TEMPLATE = """\
{context_block}Security text (confirmed to contain principle reasoning):
"{text}"

Which principle family does this text's reasoning belong to?

Families:
  1. Separation and Scope
  2. Trust and Verification
  3. Redundancy and Observability
  4. Cryptographic Hygiene
  5. Design Philosophy
  6. Human Factors

Respond in exactly this format:
<reasoning>
[2–3 sentences: what is the core security argument in the text, and why does \
it belong to this family rather than another?]
</reasoning>
<answer>[exact family name from the list above]</answer>
"""


# ---------------------------------------------------------------------------
# Stage 3 prompts — Per-family principle discrimination
#
# One system prompt per family. Each prompt contains only the principles
# in that family, with their definitions, discriminating rules, and examples
# drawn from basin_principles.py.
#
# For single-principle families (Cryptographic Hygiene, Human Factors),
# Stage 3 is a confirmation step that still asks the model to verify the
# principle is genuinely present before committing.
# ---------------------------------------------------------------------------

# --- Separation and Scope ---

STAGE3_SEPARATION_SYSTEM = """\
You are an expert in cybersecurity security design principles. A text has \
been identified as containing principle reasoning in the Separation and Scope \
family, which covers three closely related principles:

──────────────────────────────────────────────────────────────────────────────
COMPARTMENTALISATION
──────────────────────────────────────────────────────────────────────────────
DEFINITION: Organising resources into isolated groups so that compromise of
one group does not spread to others. Benefits include limiting breach impact,
preventing lateral movement between zones, and containing operational mishaps.
Basin examples: sensitive applications on separate computers; firewalls
partitioning networks; software encapsulation; separation of code and data.

MUST ARGUE: That isolating or separating RESOURCE GROUPS into compartments
LIMITS the impact of compromise, PREVENTS lateral movement, or CONTAINS
damage. The unit of analysis is a GROUP or ZONE of resources being isolated.

NOT THIS: If the text restricts what a single user or process can do → Least
Privilege. If it reduces what an adversary can see from outside → Minimum
Exposure.

BOUNDARY EXAMPLES:
  PRESENT: "Create two separate security groups for TeamAlice and TeamBob.
    This ensures each team only accesses what they need, minimising lateral
    movement if one group is compromised." → Isolating GROUPS, preventing
    lateral movement = Compartmentalisation.
  ABSENT:  "Ensure users only have access to the resources they need for
    their role." → Restricting a single subject's permissions = Least
    Privilege, not Compartmentalisation.

──────────────────────────────────────────────────────────────────────────────
MINIMUM EXPOSURE
──────────────────────────────────────────────────────────────────────────────
DEFINITION: Minimising the attack surface presented to adversaries — reducing
external interfaces, limiting what information is disclosed, and narrowing
the window of opportunity for attacks.

MUST ARGUE: That REDUCING WHAT IS EXTERNALLY VISIBLE OR REACHABLE prevents
attacks. The perspective is outward-facing: what can an adversary from
OUTSIDE see, reach, or interact with?

NOT THIS: If the text restricts permissions of a named user/process → Least
Privilege. If it isolates groups from each other → Compartmentalisation.

BOUNDARY EXAMPLES:
  PRESENT: "Expose only the necessary endpoints and data. Keep everything
    else locked down. This reduces the attack surface." → Limiting what an
    adversary can reach = Minimum Exposure.
  ABSENT:  "Limit admin access to only what's necessary for their role." →
    Restricting a specific role's privileges = Least Privilege.

──────────────────────────────────────────────────────────────────────────────
LEAST PRIVILEGE
──────────────────────────────────────────────────────────────────────────────
DEFINITION: Any subject (user, process, component) should operate with the
minimum privileges necessary to complete its job. Excess privilege amplifies
the damage from compromise, error, or misuse.

MUST ARGUE: That restricting the PERMISSIONS of a specific SUBJECT to the
minimum necessary REDUCES the impact of compromise. The unit of analysis is
an individual subject's allowed operations.

NOT THIS: If the text isolates groups of resources → Compartmentalisation.
If it reduces what an adversary can see from outside → Minimum Exposure.

BOUNDARY EXAMPLES:
  PRESENT: "Giving users elevated access on their primary accounts is like
    handing them the keys to the kingdom. Keep day-to-day accounts limited
    so compromise doesn't grant broad access." → Restricting individual
    subject privileges = Least Privilege.
  ABSENT:  "Create separate network zones for different teams so a breach
    in one zone doesn't reach the others." → Isolating resource groups =
    Compartmentalisation.

──────────────────────────────────────────────────────────────────────────────
CRITICAL DISCRIMINATION SUMMARY:
  Compartmentalisation → GROUPS of resources are ISOLATED from each other
  Minimum Exposure     → EXTERNAL ATTACK SURFACE is reduced
  Least Privilege      → INDIVIDUAL SUBJECT'S PERMISSIONS are restricted
──────────────────────────────────────────────────────────────────────────────
"""

STAGE3_SEPARATION_USER_TEMPLATE = """\
{context_block}Security text:
"{text}"

This text contains Separation and Scope reasoning. Which specific principle \
is it arguing for?

Options: Compartmentalisation | Minimum Exposure | Least Privilege

Apply the discrimination rules carefully:
- Compartmentalisation: isolating GROUPS of resources to contain breach
- Minimum Exposure: reducing EXTERNAL attack surface
- Least Privilege: restricting an INDIVIDUAL SUBJECT'S permissions

Respond in exactly this format:
<reasoning>
[2–3 sentences: identify the unit of analysis (group/external surface/individual \
subject) and explain which principle this maps to and why the others do not fit.]
</reasoning>
<answer>[one of: Compartmentalisation | Minimum Exposure | Least Privilege]</answer>
"""


# --- Trust and Verification ---

STAGE3_TRUST_SYSTEM = """\
You are an expert in cybersecurity security design principles. A text has \
been identified as containing principle reasoning in the Trust and Verification \
family, which covers three related principles:

──────────────────────────────────────────────────────────────────────────────
MINIMUM TRUST AND MAXIMUM TRUSTWORTHINESS
──────────────────────────────────────────────────────────────────────────────
DEFINITION: Trust placed in components should be minimised; trustworthiness
should be maximised through verification. A trusted component is merely
assumed to behave correctly; a trustworthy component actually does.
Basin emphasis: minimise assumptions when integrating third-party subsystems;
verify rather than assume.

MUST ARGUE: That TRUSTING WITHOUT VERIFICATION is the vulnerability, or that
REPLACING TRUST WITH VERIFICATION is the security strategy. The reasoning
must be framed as a trust problem: what happens when we assume a component
behaves correctly without checking?

NOT THIS: If the text is about checking every access every time → Complete
Mediation. If it's about what happens when something fails → Secure Fail-Safe
Defaults.

──────────────────────────────────────────────────────────────────────────────
SECURE FAIL-SAFE DEFAULTS
──────────────────────────────────────────────────────────────────────────────
DEFINITION: Systems should default to a secure state. On failure, ambiguity,
or error, the system should deny access rather than grant it. Whitelisting
over blacklisting; deny-by-default over permit-by-default.

MUST ARGUE: That defaulting to DENIAL or a SECURE STATE on failure or
ambiguity PREVENTS exploitation. The reasoning is specifically about what
happens WHEN SOMETHING GOES WRONG or when no explicit permission exists.

NOT THIS: If the text is about trusting components → Minimum Trust. If it's
about checking every access → Complete Mediation.

BOUNDARY EXAMPLES:
  PRESENT: "If the authentication service is unreachable, the system should
    deny access by default. Failing open is the vulnerability." → Failing
    securely = Secure Fail-Safe Defaults.
  ABSENT:  "Never assume a third-party library is safe — always verify its
    behaviour." → Trust problem = Minimum Trust.

──────────────────────────────────────────────────────────────────────────────
COMPLETE MEDIATION
──────────────────────────────────────────────────────────────────────────────
DEFINITION: Every access to every object must be authorisation-checked every
time it is made. Caching or skipping checks creates exploitable gaps.

MUST ARGUE: That CONSISTENT, REPEATED CHECKING of every access is necessary,
or that GAPS IN CHECKING (checking once, caching, skipping on subsequent
access) are the vulnerability.

NOT THIS: If the text is about trust assumptions → Minimum Trust. If it's
about default states on failure → Secure Fail-Safe Defaults.

BOUNDARY EXAMPLES:
  PRESENT: "Don't cache permissions. If you check access once and assume it
    stays valid, an attacker who changes their role mid-session will still
    get through." → Every access checked every time = Complete Mediation.
  ABSENT:  "Use a whitelist approach — deny everything not explicitly
    permitted." → Default-deny = Secure Fail-Safe Defaults.

──────────────────────────────────────────────────────────────────────────────
CRITICAL DISCRIMINATION SUMMARY:
  Minimum Trust       → trust ASSUMPTION about a component is the problem
  Secure Fail-Safe    → what happens at FAILURE or ambiguity (default deny)
  Complete Mediation  → EVERY access checked EVERY time (no gaps)
──────────────────────────────────────────────────────────────────────────────
"""

STAGE3_TRUST_USER_TEMPLATE = """\
{context_block}Security text:
"{text}"

This text contains Trust and Verification reasoning. Which specific principle \
is it arguing for?

Options: Minimum Trust and Maximum Trustworthiness | Secure Fail-Safe Defaults \
| Complete Mediation

Apply the discrimination rules:
- Minimum Trust: trusting without verification is the problem
- Secure Fail-Safe Defaults: what happens at failure (default to denial)
- Complete Mediation: every access must be checked every time

Respond in exactly this format:
<reasoning>
[2–3 sentences: what is the core argument — a trust assumption, a failure \
state, or a gap in access checking — and which principle does it map to?]
</reasoning>
<answer>[one of: Minimum Trust and Maximum Trustworthiness | Secure Fail-Safe Defaults | Complete Mediation]</answer>
"""


# --- Redundancy and Observability ---

STAGE3_REDUNDANCY_SYSTEM = """\
You are an expert in cybersecurity security design principles. A text has \
been identified as containing principle reasoning in the Redundancy and \
Observability family, which covers two related principles:

──────────────────────────────────────────────────────────────────────────────
NO SINGLE POINT OF FAILURE
──────────────────────────────────────────────────────────────────────────────
DEFINITION: Security should not depend on a single mechanism. Multiple
independent layers of defence provide resilience: if one fails, others
remain. This is the core of defence-in-depth.

MUST ARGUE: That MULTIPLE INDEPENDENT MECHANISMS provide resilience, or that
RELYING ON ONE MECHANISM creates a fragile single point of failure. The text
must argue for redundancy or layering in security mechanisms.

NOT THIS: Compartmentalisation also involves separation, but it isolates
resource groups to CONTAIN breach. NSPF provides backup mechanisms so that
FAILURE OF ONE does not compromise the whole. If the text is about isolating
zones to limit damage, it is Compartmentalisation. If it argues that multiple
mechanisms together are more robust than one, it is NSPF.

──────────────────────────────────────────────────────────────────────────────
TRACEABILITY
──────────────────────────────────────────────────────────────────────────────
DEFINITION: Security-relevant events must be logged so that breaches can be
detected, investigated, and actors held accountable. Logs are the basis for
after-the-fact forensics and real-time anomaly detection.

MUST ARGUE: That LOGGING ENABLES detection, investigation, or accountability.
The security benefit is recording what happened for later review or alerting.

NOT THIS: Monitoring tools may be mentioned, but if the text is not arguing
that logging provides a security benefit (detection, accountability, forensics),
it is not Traceability. Logging as a general operational practice without a
security rationale does not qualify.

BOUNDARY EXAMPLES:
  PRESENT: "Audit logs are essential. If an account is compromised, logs let
    you reconstruct exactly what the attacker accessed and when." →
    Logging for forensics = Traceability.
  ABSENT:  "Rely on more than one authentication factor. If one is
    compromised, the other still protects you." → Redundant mechanisms =
    No Single Point of Failure.

──────────────────────────────────────────────────────────────────────────────
CRITICAL DISCRIMINATION SUMMARY:
  No Single Point of Failure → multiple MECHANISMS provide RESILIENCE
  Traceability               → LOGGING provides DETECTION / ACCOUNTABILITY
──────────────────────────────────────────────────────────────────────────────
"""

STAGE3_REDUNDANCY_USER_TEMPLATE = """\
{context_block}Security text:
"{text}"

This text contains Redundancy and Observability reasoning. Which specific \
principle is it arguing for?

Options: No Single Point of Failure | Traceability

Apply the discrimination rules:
- No Single Point of Failure: multiple mechanisms for resilience
- Traceability: logging for detection and accountability

Respond in exactly this format:
<reasoning>
[1–2 sentences: is the core argument about redundant mechanisms or about \
logging/detection, and why?]
</reasoning>
<answer>[one of: No Single Point of Failure | Traceability]</answer>
"""


# --- Cryptographic Hygiene (single-principle family, confirmation step) ---

STAGE3_CRYPTO_SYSTEM = """\
You are an expert in cybersecurity security design principles. A text has \
been identified as potentially containing Generating Secrets reasoning.

──────────────────────────────────────────────────────────────────────────────
GENERATING SECRETS
──────────────────────────────────────────────────────────────────────────────
DEFINITION: Secrets must be generated with sufficient randomness (entropy)
to resist guessing or brute-force attacks. This applies to passwords,
tokens, keys, nonces, and any value that must be unpredictable.

MUST ARGUE: That SECRET QUALITY — randomness, unpredictability, entropy —
matters for security. The text must connect how a secret is generated to a
security outcome.

NOT THIS:
  - Who is allowed to access a secret → Least Privilege
  - Whether the algorithm/mechanism is public → Open Design
  - How secrets are stored or transmitted → other principles
  The principle is specifically about the GENERATION of secrets, not their
  management, storage, or access control.

CONFIRM OR REJECT: If the text genuinely argues that high-entropy generation
is the security benefit, confirm Generating Secrets. If on closer inspection
it is about access to secrets or algorithm secrecy, output NONE for this stage.
──────────────────────────────────────────────────────────────────────────────
"""

STAGE3_CRYPTO_USER_TEMPLATE = """\
{context_block}Security text:
"{text}"

Does this text argue that the QUALITY of secret generation (randomness, \
entropy, unpredictability) is the security benefit? Or is it actually about \
something else (access to secrets, algorithm secrecy, key management)?

Respond in exactly this format:
<reasoning>
[1–2 sentences: does the text connect secret generation quality to a security \
outcome, or is it primarily about something else?]
</reasoning>
<answer>Generating Secrets</answer>  or  <answer>NONE</answer>
"""


# --- Design Philosophy ---

STAGE3_DESIGN_SYSTEM = """\
You are an expert in cybersecurity security design principles. A text has \
been identified as containing principle reasoning in the Design Philosophy \
family, which covers two related principles:

──────────────────────────────────────────────────────────────────────────────
SIMPLICITY
──────────────────────────────────────────────────────────────────────────────
DEFINITION: Security mechanisms should be kept simple. Simpler designs have
fewer flaws, are easier to analyse and review, and their trustworthiness is
easier to establish. Connects to Saltzer & Schroeder's Economy of Mechanism.

MUST ARGUE: That SIMPLICITY or reduced COMPLEXITY in security mechanism
design CAUSES better security outcomes — fewer flaws, easier verification,
reduced attack surface, or more manageable security posture.

NOT THIS: If the text argues that security should be easy for users to
understand or use → Usability. Simplicity concerns the INTERNAL complexity of
the mechanism, not the user experience of interacting with it.

──────────────────────────────────────────────────────────────────────────────
OPEN DESIGN
──────────────────────────────────────────────────────────────────────────────
DEFINITION: Security should not depend on secrecy of mechanisms. The system
should be secure even if an adversary knows its design — security should come
from key/secret management, not from keeping the mechanism hidden.
Kerckhoffs' principle is the canonical form.

MUST ARGUE: That RELYING ON SECRECY OF THE DESIGN MECHANISM is a
vulnerability, or that TRANSPARENCY of mechanisms enables better security
(through peer review, reduced secret surface, or resilience to reverse
engineering).

NOT THIS: General transparency in communication with users → not Open Design.
Open Design specifically concerns whether the SECURITY MECHANISM ITSELF relies
on secrecy for its effectiveness. If the argument is about openness in user
communication or change management, it is not Open Design.

──────────────────────────────────────────────────────────────────────────────
CRITICAL DISCRIMINATION SUMMARY:
  Simplicity    → INTERNAL mechanism complexity is the problem/solution
  Open Design   → MECHANISM SECRECY is the problem/solution
──────────────────────────────────────────────────────────────────────────────
"""

STAGE3_DESIGN_USER_TEMPLATE = """\
{context_block}Security text:
"{text}"

This text contains Design Philosophy reasoning. Which specific principle \
is it arguing for?

Options: Simplicity | Open Design

Apply the discrimination rules:
- Simplicity: internal mechanism complexity causes/prevents security failures
- Open Design: mechanism secrecy is the vulnerability/openness is the benefit

Respond in exactly this format:
<reasoning>
[1–2 sentences: is the argument about the internal complexity of the mechanism \
or about whether the mechanism relies on secrecy?]
</reasoning>
<answer>[one of: Simplicity | Open Design]</answer>
"""


# --- Human Factors (single-principle family, confirmation step) ---

STAGE3_HUMAN_SYSTEM = """\
You are an expert in cybersecurity security design principles. A text has \
been identified as potentially containing Usability reasoning.

──────────────────────────────────────────────────────────────────────────────
USABILITY
──────────────────────────────────────────────────────────────────────────────
DEFINITION: Security mechanisms must be designed to be usable. If a mechanism
is too difficult to use, people will circumvent it or apply it incorrectly,
introducing vulnerabilities. Connects to Saltzer & Schroeder's Psychological
Acceptability.

MUST ARGUE: That the USABILITY or EASE OF USE of a security mechanism affects
whether it is used correctly or used at all — and therefore affects security
outcomes. The text should connect human factors to security effectiveness.

NOT THIS: If the text argues for keeping mechanisms internally simple →
Simplicity. Usability concerns whether the HUMAN OPERATOR can correctly use
the mechanism. A mechanism can be internally complex but externally usable,
or internally simple but externally confusing.

CONFIRM OR REJECT: If the text genuinely argues that unusable security gets
circumvented or misapplied, confirm Usability. If it is about mechanism
design simplicity without a human-factors argument, output NONE.
──────────────────────────────────────────────────────────────────────────────
"""

STAGE3_HUMAN_USER_TEMPLATE = """\
{context_block}Security text:
"{text}"

Does this text argue that the USABILITY or EASE OF USE of a security mechanism \
affects whether people use it correctly — and therefore affects security? Or \
is it actually about mechanism design complexity (Simplicity) or something else?

Respond in exactly this format:
<reasoning>
[1–2 sentences: does the text connect human factors / ease of use to security \
outcomes, or is it primarily about mechanism design?]
</reasoning>
<answer>Usability</answer>  or  <answer>NONE</answer>
"""


# ---------------------------------------------------------------------------
# Dispatch tables: map family → (system_prompt, user_template)
# ---------------------------------------------------------------------------

STAGE3_PROMPTS = {
    "Separation and Scope": (
        STAGE3_SEPARATION_SYSTEM,
        STAGE3_SEPARATION_USER_TEMPLATE,
    ),
    "Trust and Verification": (
        STAGE3_TRUST_SYSTEM,
        STAGE3_TRUST_USER_TEMPLATE,
    ),
    "Redundancy and Observability": (
        STAGE3_REDUNDANCY_SYSTEM,
        STAGE3_REDUNDANCY_USER_TEMPLATE,
    ),
    "Cryptographic Hygiene": (
        STAGE3_CRYPTO_SYSTEM,
        STAGE3_CRYPTO_USER_TEMPLATE,
    ),
    "Design Philosophy": (
        STAGE3_DESIGN_SYSTEM,
        STAGE3_DESIGN_USER_TEMPLATE,
    ),
    "Human Factors": (
        STAGE3_HUMAN_SYSTEM,
        STAGE3_HUMAN_USER_TEMPLATE,
    ),
}


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
        model_name,
        token=hf_token,
        quantization_config=bnb_config,
        device_map="auto",
        torch_dtype=torch.bfloat16,
    )
    model.eval()
    logger.info("Model loaded successfully")
    return tokenizer, model


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------

def build_chat_prompt(tokenizer, system_prompt: str, user_prompt: str) -> str:
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    return tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True,
    )


def run_inference(
    prompt: str,
    tokenizer,
    model,
    max_new_tokens: int = 512,
) -> str:
    inputs = tokenizer(
        prompt,
        return_tensors="pt",
        truncation=True,
        max_length=4096,
    ).to(model.device)
    input_len = inputs["input_ids"].shape[1]

    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            temperature=1.0,
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


def extract_answer(response: str) -> Optional[str]:
    m = ANSWER_RE.search(response)
    return m.group(1).strip() if m else None


def extract_reasoning(response: str) -> str:
    m = REASONING_RE.search(response)
    return m.group(1).strip() if m else response.strip()


def parse_stage1(response: str) -> Tuple[str, str]:
    """Returns (decision, reasoning). Decision is 'YES' or 'NO'."""
    reasoning = extract_reasoning(response)
    answer = extract_answer(response)
    if answer is None:
        logger.warning(f"Stage 1: could not parse answer from: {response[:80]}")
        # Default to NO on parse failure — preserves abstention behaviour
        return "NO", reasoning
    decision = "YES" if answer.upper().startswith("YES") else "NO"
    return decision, reasoning


def parse_stage2(response: str) -> Tuple[Optional[str], str]:
    """Returns (family, reasoning). Family is one of ALL_FAMILIES or None."""
    reasoning = extract_reasoning(response)
    answer = extract_answer(response)
    if answer is None:
        logger.warning(f"Stage 2: could not parse answer from: {response[:80]}")
        return None, reasoning
    # Exact match first
    if answer in ALL_FAMILIES:
        return answer, reasoning
    # Case-insensitive partial match
    answer_lower = answer.lower()
    for fam in ALL_FAMILIES:
        if answer_lower in fam.lower() or fam.lower() in answer_lower:
            return fam, reasoning
    logger.warning(f"Stage 2: could not match family: '{answer}'")
    return None, reasoning


def parse_stage3(
    response: str,
    family: str,
) -> Tuple[List[str], str]:
    """
    Returns (detected_principles, reasoning).
    Handles both single-principle and multi-principle families.
    A NONE answer from a confirmation stage yields an empty list.
    """
    reasoning = extract_reasoning(response)
    answer = extract_answer(response)

    if answer is None:
        logger.warning(f"Stage 3: could not parse answer from: {response[:80]}")
        return ["ERROR"], reasoning

    if answer.upper() == "NONE":
        return [], reasoning

    candidate_principles = FAMILY_MAP.get(family, [])
    detected = []

    for part in answer.split(","):
        part = part.strip()
        if not part:
            continue
        # Exact match
        if part in ALL_PRINCIPLES:
            detected.append(part)
            continue
        # Case-insensitive partial match against candidates in this family
        matched = False
        for p in candidate_principles:
            if part.lower() in p.lower() or p.lower() in part.lower():
                detected.append(p)
                matched = True
                break
        # Fall back to all principles
        if not matched:
            for p in ALL_PRINCIPLES:
                if part.lower() in p.lower() or p.lower() in part.lower():
                    detected.append(p)
                    matched = True
                    break
        if not matched:
            logger.warning(f"Stage 3: could not match principle: '{part}'")

    return detected, reasoning


# ---------------------------------------------------------------------------
# Context block builder
# ---------------------------------------------------------------------------

def build_context_block(context_value: Optional[str]) -> str:
    if not context_value or not context_value.strip():
        return ""
    return f'Context: "{context_value.strip()}"\n\n'


# ---------------------------------------------------------------------------
# Three-stage pipeline for one row
# ---------------------------------------------------------------------------

def run_staged_pipeline(
    text: str,
    tokenizer,
    model,
    max_new_tokens: int,
    context_value: Optional[str] = None,
) -> dict:
    """
    Runs all three stages for a single text.
    Returns a dict of all stage outputs.
    """
    context_block = build_context_block(context_value)
    used_context = bool(context_block)

    result = {
        "principle_present": "NO",
        "selected_family": "NONE",
        "detected_principles": "NONE",
        "principle_count": 0,
        "stage1_reasoning": "",
        "stage2_reasoning": "",
        "stage3_reasoning": "",
        "stage1_raw_response": "",
        "stage2_raw_response": "",
        "stage3_raw_response": "",
        "used_context": str(used_context).upper(),
    }

    # ── Stage 1: Presence ───────────────────────────────────────────────────
    user1 = STAGE1_USER_TEMPLATE.format(
        text=text,
        context_block=context_block,
    )
    prompt1 = build_chat_prompt(tokenizer, STAGE1_SYSTEM, user1)
    raw1 = run_inference(prompt1, tokenizer, model, max_new_tokens)
    decision1, reasoning1 = parse_stage1(raw1)

    result["stage1_raw_response"] = raw1
    result["stage1_reasoning"] = reasoning1
    result["principle_present"] = decision1

    if decision1 == "NO":
        logger.info("  Stage 1 → NO — pipeline stops")
        return result

    logger.info("  Stage 1 → YES — proceeding to Stage 2")

    # ── Stage 2: Family ─────────────────────────────────────────────────────
    user2 = STAGE2_USER_TEMPLATE.format(
        text=text,
        context_block=context_block,
    )
    prompt2 = build_chat_prompt(tokenizer, STAGE2_SYSTEM, user2)
    raw2 = run_inference(prompt2, tokenizer, model, max_new_tokens)
    family, reasoning2 = parse_stage2(raw2)

    result["stage2_raw_response"] = raw2
    result["stage2_reasoning"] = reasoning2

    if family is None:
        logger.warning("  Stage 2 → could not determine family — pipeline stops")
        result["selected_family"] = "UNKNOWN"
        return result

    result["selected_family"] = family
    logger.info(f"  Stage 2 → {family} — proceeding to Stage 3")

    # ── Stage 3: Specific principle ─────────────────────────────────────────
    if family not in STAGE3_PROMPTS:
        logger.error(f"  Stage 3 → no prompt defined for family: {family}")
        return result

    system3, user3_template = STAGE3_PROMPTS[family]
    user3 = user3_template.format(
        text=text,
        context_block=context_block,
    )
    prompt3 = build_chat_prompt(tokenizer, system3, user3)
    raw3 = run_inference(prompt3, tokenizer, model, max_new_tokens)
    principles, reasoning3 = parse_stage3(raw3, family)

    result["stage3_raw_response"] = raw3
    result["stage3_reasoning"] = reasoning3

    if principles == ["ERROR"]:
        result["detected_principles"] = "ERROR"
        result["principle_count"] = -1
    elif not principles:
        result["detected_principles"] = "NONE"
        result["principle_count"] = 0
    else:
        result["detected_principles"] = ", ".join(principles)
        result["principle_count"] = len(principles)

    logger.info(f"  Stage 3 → {result['detected_principles']} ({result['principle_count']})")
    return result


# ---------------------------------------------------------------------------
# Resume support
# ---------------------------------------------------------------------------

def load_existing(output_csv: str) -> dict:
    if not os.path.exists(output_csv):
        return {}
    with open(output_csv, encoding="utf-8") as f:
        return {row["row_index"]: row for row in csv.DictReader(f)}


def _write_output(path: str, fieldnames: list, rows: list) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Staged Basin principle detection (presence → family → principle)"
    )
    parser.add_argument("--input_csv", required=True,
                        help="Input CSV with a 'text' column")
    parser.add_argument("--output_csv", required=True,
                        help="Output CSV path")
    parser.add_argument("--model_name",
                        default="meta-llama/Meta-Llama-3-70B-Instruct")
    parser.add_argument("--hf_token",
                        default=os.environ.get("HF_TOKEN", ""))
    parser.add_argument("--batch_size", type=int, default=10,
                        help="Checkpoint every N processed rows")
    parser.add_argument("--max_new_tokens", type=int, default=512,
                        help="Max tokens per stage call (shorter = faster)")
    parser.add_argument("--use_context", action="store_true",
                        help="Include a context column in the prompt")
    parser.add_argument("--context_column", default="question_title",
                        help="Column name to use as context (default: question_title)")
    parser.add_argument("--resume", action="store_true",
                        help="Skip rows already present in the output CSV")
    parser.add_argument("--limit", type=int, default=None,
                        help="Process at most N rows")
    args = parser.parse_args()

    if not args.hf_token:
        logger.error("No HuggingFace token provided. Set --hf_token or $HF_TOKEN.")
        sys.exit(1)

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
    stage_fields = [
        "principle_present",
        "selected_family",
        "detected_principles",
        "principle_count",
        "stage1_reasoning",
        "stage2_reasoning",
        "stage3_reasoning",
        "stage1_raw_response",
        "stage2_raw_response",
        "stage3_raw_response",
        "used_context",
    ]
    output_fieldnames = ["row_index"] + input_fieldnames + stage_fields

    # ── Resume ───────────────────────────────────────────────────────────────
    existing = load_existing(args.output_csv) if args.resume else {}
    if existing:
        logger.info(f"Resume: {len(existing)} rows already done")

    # ── Validate context column ──────────────────────────────────────────────
    if args.use_context and args.context_column not in input_fieldnames:
        logger.warning(
            f"--use_context set but column '{args.context_column}' not found "
            f"in input. Context will be empty."
        )

    # ── Load model ───────────────────────────────────────────────────────────
    tokenizer, model = load_model(args.model_name, args.hf_token)

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

        # Skip if already done
        if idx in existing and existing[idx].get("detected_principles", "").strip():
            out_row.update(existing[idx])
            results.append(out_row)
            n_skipped += 1
            continue

        logger.info(f"[{i + 1}/{n_total}] {text[:70]}...")

        context_value = None
        if args.use_context:
            context_value = row.get(args.context_column, "")

        try:
            stage_result = run_staged_pipeline(
                text=text,
                tokenizer=tokenizer,
                model=model,
                max_new_tokens=args.max_new_tokens,
                context_value=context_value,
            )
        except Exception as e:
            logger.error(f"  Error on row {idx}: {e}")
            stage_result = {
                "principle_present": "ERROR",
                "selected_family": "ERROR",
                "detected_principles": "ERROR",
                "principle_count": -1,
                "stage1_reasoning": str(e),
                "stage2_reasoning": "",
                "stage3_reasoning": "",
                "stage1_raw_response": "",
                "stage2_raw_response": "",
                "stage3_raw_response": "",
                "used_context": str(bool(context_value)).upper(),
            }

        out_row.update(stage_result)
        results.append(out_row)
        n_processed += 1

        # Checkpoint
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
    logger.info(f"Total inference calls: up to {n_processed * 3} (3 per row, early-exit at Stage 1)")

    # ── Summary stats ────────────────────────────────────────────────────────
    stage1_yes = sum(1 for r in results if r.get("principle_present") == "YES")
    stage1_no  = sum(1 for r in results if r.get("principle_present") == "NO")
    counts = [
        int(r.get("principle_count", 0))
        for r in results
        if str(r.get("principle_count", -1)) not in ("-1", "ERROR")
    ]
    family_dist: dict[str, int] = {}
    for r in results:
        fam = r.get("selected_family", "NONE")
        family_dist[fam] = family_dist.get(fam, 0) + 1

    logger.info(f"Stage 1 → YES: {stage1_yes} | NO: {stage1_no}")
    if counts:
        avg = sum(counts) / len(counts)
        singles = sum(1 for c in counts if c == 1)
        zeros   = sum(1 for c in counts if c == 0)
        multis  = sum(1 for c in counts if c > 1)
        logger.info(f"Avg principles/text: {avg:.2f} | Single: {singles} | None: {zeros} | Multi: {multis}")
    logger.info("Family distribution:")
    for fam, cnt in sorted(family_dist.items(), key=lambda x: -x[1]):
        logger.info(f"  {fam}: {cnt}")


if __name__ == "__main__":
    main()