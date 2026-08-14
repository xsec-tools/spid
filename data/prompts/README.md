# Prompts

## Stage 1 to Stage 3 detection prompts

The detection prompts are not stored as standalone files. They are Python string
literals, built at runtime from the principle definitions.

`code/basin_principle_definitions.py` holds the twelve Basin et al. definitions,
the mapping into six families, the per-family discrimination rules used at
Stage 3, and the boundary examples separating an instantiation from a topical
mention.

`code/03_run_principle_pipeline.py` holds the prompt assembly for each stage.

| Stage | Decision | Prompt supplies |
|---|---|---|
| 1 | Presence, YES or NO | The instantiation criterion and boundary examples |
| 2 | Family, one of six | The six family definitions and their boundaries |
| 3 | Principle, from 1 to 3 candidates | Definitions of the candidates and that family's discrimination rules |

To read a prompt as the model receives it, run the pipeline with `--limit 1` and
inspect the `stageN_raw_response` columns.

To adapt SPID to a different taxonomy, edit the definitions, family mapping and
discrimination rules in `basin_principle_definitions.py`. The stage logic is
taxonomy-independent.

## Synthetic generation

`synthetic_generation_prompts_and_responses.csv` is the generation record for the
evaluation set. 1,800 rows, one per generated response.

| Column | Contents |
|---|---|
| `question_id` | Identifier for the source question |
| `question_title` | The question the response answers |
| `principle` | The principle the response was generated to instantiate |
| `persona` | The voice the response was written in |
| `response_type` | `explicit`, `implicit` or `unrelated` |
| `prompt` | The full prompt sent to the model |
| `responses` | The generated response |

Responses were generated with GPT-4.1-mini through the GPTforSheets add-in,
calling `=GPT()` over the `prompt` column. There is no standalone generation
script, because generation was driven from the spreadsheet rather than from code.

The grid is twelve principles by ten questions by three response types by five
personas, giving 1,800 rows. Two calls returned `#ERROR!` instead of a response,
which is why the evaluation set holds 1,798.

To build your own evaluation set, take the `prompt` column as the template,
substitute your own principles and questions, and run it through any capable
model.
