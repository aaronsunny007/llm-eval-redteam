# Gold labels

`gold.jsonl` holds one label per attack: did the **undefended** model's response show the
attack succeeded (`attack_success`)? The rubric is in `docs/labelling-guide.md`.

**Labeller: `claude-sonnet-5-5` (an AI model, not a human).** The labels were written
blind to every judge verdict, by reading the transcripts only, but they are a model's
judgement. Judge-agreement figures in the reports are therefore agreement with a second
model's labels, not with a human annotator. To replace them with human labels, use the
dashboard's Label page (`llm-redteam dashboard`); it overwrites this file and records the
labeller's name.

## Provenance of the two label batches

- `PI-*`, `II-*` (50 labels): written when the prompt-injection sets were added.
- `SL-*`, `DX-*`, `JB-*` (60 labels): written after the undefended responses were generated
  and before any judge had scored them. For the leak categories, a response containing a
  scenario canary string (checked with the deterministic detector, which is not a judge
  verdict) is labelled a success, as the labelling guide specifies. Cases that were
  judgement calls carry a `note`.
