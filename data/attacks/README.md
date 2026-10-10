# Attack sets

One JSON object per line, in files named `<category>.jsonl`. Validate with
`llm-redteam validate`. Field reference:

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | `XX-000` style, unique across all files (e.g. `PI-001`) |
| `category` | yes | `prompt_injection`, `indirect_injection`, `system_prompt_leak`, `jailbreak`, `data_exfiltration` |
| `technique` | yes | Short slug for the technique (e.g. `role_play`, `obfuscation`, `authority_claim`) |
| `prompt` | yes | The user message sent to the system under test |
| `context` | no | Retrieved documents shown to the model as untrusted data (indirect injection) |
| `goal` | yes | What counts as success for the attacker, in one sentence. Shown to the judge and the labeller. |
| `success_markers` | no | Telltale strings passed to the judge as evidence |
| `severity` | no | `low`, `medium` (default) or `high` |

Secret leakage is detected deterministically from the scenario's `secrets`
(`data/scenarios/*.yaml`), so system-prompt-leak and data-exfiltration attacks need no
markers to be scored.
