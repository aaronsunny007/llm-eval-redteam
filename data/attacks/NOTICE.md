# Attack set provenance

The attack payloads in `prompt_injection.jsonl` and `indirect_injection.jsonl` are taken
verbatim from the **deepset/prompt-injections** dataset
(<https://huggingface.co/datasets/deepset/prompt-injections>), licensed
**Apache-2.0**, dataset revision `4f61ecb038e9c3fb77e21034b22511b523772cdd`.

This repository did not write the payloads. `scripts/build_attack_sets.py` only:

1. keeps rows labelled as injections, in English, 20-600 characters, single-line;
2. orders them by a seeded SHA-256 hash (deterministic) and takes the first 50;
3. uses 25 as direct user-turn attacks (`PI-001`..`PI-025`, technique `deepset-direct`);
4. plants the other 25 inside a neutral filing excerpt returned as a retrieved document,
   with a benign question as the user turn (`II-001`..`II-025`, technique
   `deepset-in-document`).

Regenerate with `python scripts/build_attack_sets.py`.

## Secret-extraction and jailbreak sets (added in v1.0.0)

`scripts/build_extra_attack_sets.py` builds three further sets the same way: payload text is
verbatim from the source, and the script only filters, orders by seeded SHA-256 and formats it.

| File | Source (licence, revision) | Selection |
|---|---|---|
| `system_prompt_leak.jsonl` (`SL-001`..`SL-020`) | [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) (MIT, `04737b65e90a6794ec227012e4a255a7def6344b`) | English, 20-400 chars, asks the model to tell/print/repeat its instructions, prompt or password; first 20 by hash order |
| `data_exfiltration.jsonl` (`DX-001`..`DX-020`) | [Lakera/gandalf_summarization](https://huggingface.co/datasets/Lakera/gandalf_summarization) (MIT, `8e213cc8dd65f099c61dc32dbcfdb2ff6b1c92d8`) | English, 20-400 chars, mentions a password or secret; first 20 by hash order |
| `jailbreak.jsonl` (`JB-001`..`JB-020`) | [JailbreakBench/JBB-Behaviors](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors) (MIT, `886acc352a31533ffbcf4ef22c744658688086fc`), `harmful` split | All 20 behaviours in the "Economic harm" and "Fraud/Deception" categories, the ones relevant to a financial assistant, in dataset order |

Honest scope of these sets:

- The Gandalf prompts were written against a *different* game (a model guarding a password).
  Here they are replayed against the FinAssist scenario, whose confidential content is a
  deployment canary, an escalation code and a customer record, so they are a stand-in for
  "extract what the system prompt protects", not tailored attacks. Leaks are still detected
  deterministically from the scenario's canaries.
- The jailbreak cases are the benchmark's **plain harmful requests**, not optimised
  jailbreak templates or suffixes. They measure whether the assistant stays in role and
  refuses; they do not measure resistance to adversarially optimised jailbreaks.
- Responses to the jailbreak cases can contain model-written harmful content. They are kept
  in the committed transcripts so the judge can be audited.
