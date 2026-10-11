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

Coverage note: the source dataset contains prompt-injection payloads only. The harness
supports `system_prompt_leak`, `jailbreak` and `data_exfiltration` as well (secret leakage
is always detected deterministically from the scenario's canaries), but this set does not
include dedicated cases for them.
