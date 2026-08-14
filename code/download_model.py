"""
download_model.py
=================
Fetches the fine-tuned RoBERTa CE classifier used by 02_run_ce_pipeline.py.

The checkpoint is 485 MB, which exceeds the GitHub file size limit, so it is
distributed separately rather than committed to this repository.

Usage:
    python download_model.py                      # into ./models/ce_classifier
    python download_model.py --output_dir /path   # elsewhere

Then pass the resulting directory to the pipeline:
    python 02_run_ce_pipeline.py --model_dir models/ce_classifier ...
"""

import argparse
import os
import sys

# ---------------------------------------------------------------------------
# Set this once the checkpoint has been published. Until then the script exits
# with instructions rather than failing on a missing repository.
# ---------------------------------------------------------------------------
HF_REPO_ID = None          # e.g. "xsec-tools/spid-ce-classifier"
ZENODO_RECORD_URL = None   # e.g. "https://doi.org/10.5281/zenodo.XXXXXXX"

DEFAULT_OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "..", "models", "ce_classifier")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output_dir", default=DEFAULT_OUTPUT,
                        help="Where to place the checkpoint.")
    args = parser.parse_args()

    if HF_REPO_ID is None:
        print(
            "The CE classifier has not yet been published to a public host.\n"
            "\n"
            "Until it is, obtain the checkpoint directly from the authors and\n"
            "point --model_dir at the directory containing config.json and\n"
            "model.safetensors.\n"
            "\n"
            "Maintainers: set HF_REPO_ID at the top of this file once the\n"
            "checkpoint is on the Hugging Face Hub."
        )
        sys.exit(1)

    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        print("Install the Hub client first:  pip install huggingface_hub")
        sys.exit(1)

    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    print(f"Downloading {HF_REPO_ID} to {output_dir}")
    snapshot_download(repo_id=HF_REPO_ID, local_dir=output_dir)
    print("Done. Pass this path to --model_dir.")

    if ZENODO_RECORD_URL:
        print(f"An archival copy is also available at {ZENODO_RECORD_URL}")


if __name__ == "__main__":
    main()
