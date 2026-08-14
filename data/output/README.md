# Pipeline outputs

The recorded outputs of the runs reported in the paper. Released so the reported
figures can be checked without access to an A100 and without spending the
inference time again. A full pass over these corpora is a multi-day job.

## Contents

### `staged_detections/`

Per-unit output of the three-stage principle detector, Llama-3-70B-Instruct in
4-bit NF4. One row per CE unit.

| File | Units | Corpus |
|---|---|---|
| `sse_5232_staged_principles.csv` | 5,232 | Security Stack Exchange, 500 comments |
| `cybok_1843_staged_principles.csv` | 1,843 | CyBOK, five Knowledge Areas |
| `nist80053_5085_staged_principles.csv` | 5,085 | NIST SP 800-53r5, all section types |
| `nist800207_558_staged_principles.csv` | 558 | NIST SP 800-207 |
| `asvs_344_staged_principles.csv` | 344 | OWASP ASVS 5.0.0 |
| `serverfault_2122_staged_principles.csv` | 2,122 | Server Fault |
| `stackoverflow_2179_staged_principles.csv` | 2,179 | Stack Overflow |
| `synthetic_1798_staged_principles.csv` | 1,798 | Synthetic evaluation set |
| `reddit_48846_staged_principles_labels_only.csv` | 48,846 | Reddit ELI5, **labels only, see below** |

Key columns: `principle_present` (Stage 1, YES or NO), `selected_family`
(Stage 2), `detected_principles` (Stage 3), `principle_count`, plus
`stageN_reasoning` and `stageN_raw_response` for each stage, so a decision can be
traced to the stage where it diverged.

### `ablation/`

`synthetic_1798_staged_principles_llama8b.csv` is the same pipeline on
Llama-3-8B-Instruct, the ablation supporting the claim that the 70B model is
needed for reliable detection of implicit normative arguments.

### `nli_baseline/`

Zero-shot NLI baseline output, `MoritzLaurer/deberta-v3-large-zeroshot-v2.0`,
on the synthetic set and on SSE. This is the comparison in Tables 2 and 3.

### `ce_units/`

CE classification output for the corpora where that stage ran separately from
principle detection. For SSE, CyBOK, Server Fault, Stack Overflow and the
synthetic set the CE columns are already carried in the staged detection files,
so they are not duplicated here.

### `sse_92_detection_review.csv`

Manual review of every Stage 1 detection on Security Stack Exchange, 92 units
across 64 comments. This is the evidence behind Table 4 and Appendix D. Columns:
`review`, `comment_idx`, `unit_position`, `detected_principles`, `cae_label`,
`text`, `stage1_reasoning`, `stage3_reasoning`.

Of the 92 units, 87 received a specific principle at Stage 3 and 5 returned NONE
after Stage 2 routing. All 5 abstentions were confirmed correct.

The `review` column uses six categories. Table 4 reports four, collapsed as
follows over the 87 units with a principle.

| `review` | n | Table 4 row |
|---|---|---|
| `Correct` | 60 | Correct |
| `Error` | 14 | Error |
| `Borderline (normative)` | 3 | Borderline, intent too implicit |
| `Correct (borderline)` | 3 | Borderline, intent too implicit |
| `Error (borderline normative)` | 2 | Borderline, intent too implicit |
| `Borderline (principle)` | 5 | Correct, contestable label |

The three categories that collapse into the Borderline row all concern marginal
normative intent, where the text carries normative force without making an
explicit design argument. `Borderline (principle)` is different: the detection is
right but the choice of principle is arguable. All five fall on Minimum Trust and
Maximum Trustworthiness or Least Privilege.

---

## The Reddit file is labels only

The Reddit ELI5 corpus is not redistributed, because its licensing is
unresolved. The full output would have republished 48,846 comment segments.

`reddit_48846_staged_principles_labels_only.csv` therefore carries the unit
counts, CE labels, confidences and detection decisions, but **not** the unit
text and **not** the model reasoning, which quotes the text. That is enough to
verify the 0.03% Stage 1 rate reported in Table 5 without redistributing any
Reddit content.

The Reddit run also used a corpus-specific segmenter that handled markdown code
blocks and paragraph breaks, and that is not part of this release. Reddit unit
counts are therefore not reproducible from the released pipeline.

---
