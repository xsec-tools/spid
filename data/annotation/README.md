# Security Stack Exchange CE annotation

Our manual Claims-Evidence annotation of Security Stack Exchange units, behind
the adaptation step in Section 3.1 of the paper.

| File | Rows | Contents |
|---|---|---|
| `sse_annotation_sheet_v2.csv` | 795 | Full annotation sheet, with source answer IDs, question titles, unit positions, labels and notes |
| `sse_602_adaptation_units.csv` | 602 | Units used for adaptation. Columns: `text`, `unit_type`. |
| `sse_finetune_eval_167.csv` | 167 | Held-out evaluation set. Columns: `text`, `label`. |

Of the 795 rows in the sheet, 769 carry a label and 26 are marked `Skip`. The 769
split into 602 for adaptation and 167 held out, with no overlap.

| | Claim | Evidence | Total |
|---|---|---|---|
| Sheet, labelled | 679 | 90 | 769 |
| Adaptation set | 537 | 65 | 602 |
| Held-out set | 142 | 25 | 167 |

The annotation is two-class, Claim and Evidence. In `sse_finetune_eval_167.csv`
the label is numeric, following the classifier's label ids: `0` Claim, `2`
Evidence. Id `1` is Argument, which does not occur here.

The CyBOK side of the training data is not distributed with this release, and
neither is the training code. Those datasets are for CyBOK to publish.

Unit text is from Security Stack Exchange, whose contributions are CC BY-SA. The
labels are ours.
