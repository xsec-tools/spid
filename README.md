# SPID: A Security Principle Instantiation Detector

SPID labels each sentence-level unit of a security explanation with the security
design principle it instantiates, abstaining when the text only describes a
mechanism. A unit instantiates a principle when it argues that the design
property the principle names improves security, not merely when it mentions a
related concept.

Accompanies the paper *SPID: A Security Principle Instantiation Detector for
Security Explanation Text*.

## How it works

**CE classification.** Text is segmented into sentence-level units with NLTK and
each unit is classified as Claim or supporting Evidence by a fine-tuned
RoBERTa-base model. These labels record how reasoning is distributed. They do not
filter which units the principle detector sees.

**Principle detection.** Three staged inference calls on
Meta-Llama-3-70B-Instruct identify which of the twelve Basin et al. design
principles, if any, a unit instantiates.

| Stage | Decision |
|---|---|
| 1. Presence | Does the unit argue *why* a design property improves security? Units returning NO exit here. |
| 2. Family | Which of six principle families? |
| 3. Discrimination | Which principle within that family? |

The pipeline is not restricted to the Basin et al. taxonomy. Definitions,
families and discrimination rules are in `code/basin_principle_definitions.py`.

## Install

```bash
git clone https://github.com/xsec-tools/spid.git
cd spid
pip install -r requirements.txt
python -c "import nltk; nltk.download('punkt'); nltk.download('punkt_tab')"
```

Python 3.10, tested on Linux with CUDA 11.8.

### The CE classifier

The fine-tuned checkpoint is 485 MB, above the GitHub file size limit, so it is
distributed separately.

```bash
python code/download_model.py --output_dir models/ce_classifier
```

> **The checkpoint is not yet on a public host.** Until it is,
> `download_model.py` prints instructions rather than downloading. Obtain it from
> the authors and point `--model_dir` at the directory holding `config.json` and
> `model.safetensors`.

### Hardware

| Stage | Requirement |
|---|---|
| Segmentation | CPU |
| CE classification | CPU workable, GPU preferred |
| Principle detection | A single A100 80GB or equivalent. Llama-3-70B in 4-bit NF4. |
| NLI baseline | One GPU, 16GB or more |

Suited to batch corpus analysis rather than interactive use.

## Usage

### 1. Get your text into a CSV

From a PDF, convert to plain text first, for example with Poppler's `pdftotext`.
There is no PDF reader built in.

For a long document, segment it into units:

```bash
python code/01_segment_text.py \
    --input_file my_document.txt \
    --output_csv my_document_units.csv \
    --source_id  MY_DOC
```

For a CSV where each row is a whole comment or answer, skip this. Step 2 will
segment for you.

### 2. CE classification

```bash
python code/02_run_ce_pipeline.py \
    --input_csv  data/input/sse_500_anonymised.csv \
    --model_dir  models/ce_classifier \
    --output_csv results/sse_ce_units.csv \
    --text_col   Comment \
    --summary    results/sse_ce_summary.csv
```

Already segmented, one row per unit:

```bash
python code/02_run_ce_pipeline.py \
    --input_csv  data/input/segmented_units/nist80053_5085_units.csv \
    --model_dir  models/ce_classifier \
    --output_csv results/nist_ce_units.csv \
    --no-segment --text_col text --group_by control_id
```

| Argument | Default | Purpose |
|---|---|---|
| `--text_col` | `text` | Column holding the text. Exits with the available columns if absent. |
| `--label_col` | none | An existing annotation column to carry through. Not used by the classifier. |
| `--group_by` | source row | Column to group units by for the summary. |
| `--segment` / `--no-segment` | `--segment` | Whether to sentence-split each row. |
| `--encoding` | `utf-8` | Input file encoding. |
| `--confidence_threshold` | `0.6` | Units below this are flagged in `low_confidence`. They keep their label and are still passed downstream. |

Argument predictions are collapsed into whichever of Claim or Evidence scored
higher. The original prediction is kept in `raw_label`.

### 3. Principle detection

```bash
export HF_TOKEN=your_token_here   # Llama-3-70B is gated

python code/03_run_principle_pipeline.py \
    --input_csv  results/sse_ce_units.csv \
    --output_csv results/sse_principles.csv \
    --model_name meta-llama/Meta-Llama-3-70B-Instruct \
    --hf_token   $HF_TOKEN \
    --batch_size 10 --resume
```

Needs a `text` column, which step 2 produces. `--resume` continues from a partial
output, which matters because full corpus runs take hours.

Output includes `principle_present` (Stage 1), `selected_family` (Stage 2),
`detected_principles` (Stage 3), `principle_count`, and the reasoning and raw
response for each stage.

### Comparisons

`code/comparisons/` holds the two reference points from the paper, neither part
of the recommended pipeline. `run_single_call_detector.py` evaluates all twelve
principles in one call. `run_nli_baseline.py` is a zero-shot NLI baseline built
from the bare definitions.

## Contents

```
code/
  01_segment_text.py                Plain text to sentence-level units
  02_run_ce_pipeline.py             CE classification, corpus-agnostic
  03_run_principle_pipeline.py      Three-stage principle detection
  basin_principle_definitions.py    Principle definitions, families, rules
  download_model.py                 Fetch the CE classifier
  preprocessing/                    Per-corpus document preprocessing
  comparisons/                      Single-call detector and NLI baseline
data/
  input/                            Corpus inputs and the evaluation set
  input/segmented_units/            Standards corpora, already segmented
  annotation/                       Our SSE CE annotation
  output/                           Recorded results reported in the paper
  prompts/                          Synthetic generation record
```

This is an inference release. CE classifier training code is not included.

### `data/input/`

| File | Rows | Corpus |
|---|---|---|
| `sse_500_anonymised.csv` | 500 | Security Stack Exchange comments, authors pseudonymised |
| `serverfault_cleaned.csv` | 425 | Server Fault answers |
| `stackoverflow_cleaned.csv` | 440 | Stack Overflow answers |
| `NIST.SP.800-53r5.txt` | n/a | NIST SP 800-53r5, full text |
| `NIST.SP.800-207.txt` | n/a | NIST SP 800-207, full text |
| `OWASP_ASVS_5.0.0_en.csv` | 346 | OWASP ASVS 5.0.0 |
| `synthetic_evaluation_set_1798.csv` | 1,798 | Synthetic evaluation set |
| `synthetic_evaluation_ground_truth_1798.csv` | 1,798 | Its ground-truth labels |

The synthetic set holds 1,798 responses generated with GPT-4.1-mini across twelve
principles and ten questions each, in three types: explicit, where the principle
is named and argued; implicit, where it is argued without being named; and
unrelated, where a principle-adjacent topic is described without a normative
argument.

`input/segmented_units/` holds the three standards corpora after preprocessing:
`nist80053_5085_units.csv`, `nist800207_558_units.csv`, `asvs_344_units.csv`.
Only the standards corpora appear here. The Q&A corpora are segmented on the fly
by `02_run_ce_pipeline.py`.

### Prompts

The Stage 1 to Stage 3 prompt templates are not separate files. They are Python
string literals in `code/basin_principle_definitions.py` and
`code/03_run_principle_pipeline.py`. `data/prompts/` holds the synthetic
generation record. See `data/prompts/README.md`.

## Data licensing

| Corpus | Included | Position |
|---|---|---|
| Security Stack Exchange | Yes, anonymised | Stack Exchange contributions are CC BY-SA. Author handles replaced with pseudonyms. |
| Server Fault | Yes | As above |
| Stack Overflow | Yes | As above |
| NIST SP 800-53r5 | Yes, full text | US Government work, not subject to copyright in the US |
| NIST SP 800-207 | Yes, full text | As above |
| OWASP ASVS 5.0.0 | Yes | OWASP publishes ASVS under CC BY-SA |
| CyBOK | Detection output only | The CyBOK annotation and CE training data are not distributed here. Those datasets are for CyBOK to release. |
| Reddit ELI5 | Labels only | Comment text is not redistributed. `data/output/` carries the detection labels without text or model reasoning. |
| Synthetic set | Yes | Generated for this work |

The code in `code/` is under `LICENSE`. The data in `data/` remains under the
licence of its original source.

## Limitations

SPID is a detector, not a quality predictor. It does not claim that instantiating
a principle predicts whether an explanation improves understanding or is judged
high quality.

There is no human-annotated unit-level ground truth for principle detection.
Inter-annotator agreement on unit-level principle labelling is the main item for
future work.

The staged architecture assigns at most one principle per unit.

Stage 1 detects normative argument structure without gating on whether the text
concerns security, so non-security corpora produce a small number of detections
on domain-general principles.

The known failure mode is Stage 1 firing on rhetorically normative text such as
maxims and rhetorical questions, which carries normative intent without making an
explicit design argument. Manual review of the 87 Stage 3 detections on Security
Stack Exchange found 69% correct, 16% error, 9% borderline and 6% correct with a
contestable label.

## Citation

See `CITATION.cff`.
