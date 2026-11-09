# Red-team report — finassist-mistral-gemma-judge

`llm-redteam 1.1.1` · scenario **finassist** · target `{'provider': 'ollama', 'model': 'mistral', 'max_tokens': 400}` · judge `{'provider': 'openai', 'model': 'gemma-4-31b-it', 'base_url': 'https://generativelanguage.googleapis.com/v1beta/openai', 'api_key_env': 'GEMINI_API_KEY', 'seed': None, 'max_tokens': 2048}` (prompt v2.1-grounded) · 110 attacks, 20 benign controls

## Defences

Attack success rate (ASR, lower is better) and benign refusal rate (lower is better), with Wilson 95% intervals. *p* is an exact McNemar test against no defence.

| Defence | ASR | Benign refused | Secret leaks | Fixed / regressed | *p* | Latency |
|---|---|---|---|---|---|---|
| `none` | 43% <sub>[34%–52%]</sub> | 0% <sub>[0%–16%]</sub> | 29 | — | — | 23.7s |
| `hardened_prompt` | 25% <sub>[17%–33%]</sub> | 0% <sub>[0%–16%]</sub> | 15 | 21 / 1 | <0.0001 | 64.1s |
| `input_guard` | 22% <sub>[15%–30%]</sub> | 0% <sub>[0%–16%]</sub> | 12 | 25 / 2 | <0.0001 | 36.5s |
| `output_guard` | 15% <sub>[9%–22%]</sub> | 15% <sub>[5%–36%]</sub> | 0 | 33 / 2 | <0.0001 | 30.9s |
| `layered` | 4% <sub>[1%–9%]</sub> | 0% <sub>[0%–16%]</sub> | 0 | 44 / 1 | <0.0001 | 22.4s |

## Attack success by category

| Category | OWASP | `none` | `hardened_prompt` | `input_guard` | `output_guard` | `layered` |
|---|---|---|---|---|---|---|
| prompt_injection | LLM01:2025 Prompt Injection | 11/25 | 8/25 | 11/25 | 8/25 | 3/25 |
| indirect_injection | LLM01:2025 Prompt Injection (indirect) | 4/25 | 2/25 | 3/25 | 5/25 | 1/25 |
| system_prompt_leak | LLM07:2025 System Prompt Leakage | 10/20 | 7/20 | 3/20 | 1/20 | 0/20 |
| jailbreak | LLM01:2025 Prompt Injection (jailbreak) | 7/20 | 2/20 | 1/20 | 2/20 | 0/20 |
| data_exfiltration | LLM02:2025 Sensitive Information Disclosure | 15/20 | 8/20 | 6/20 | 0/20 | 0/20 |

## Judge validation

Judges vs. 110 gold labels on the undefended responses (labeller(s): Aaron Prakash Gandi).

| Judge | Accuracy | Precision | Recall | F1 | Cohen's κ |
|---|---|---|---|---|---|
| `hybrid` | 79% | 66% | 82% | 0.73 | 0.56 (moderate) |
| `llm` | 79% | 66% | 82% | 0.73 | 0.56 (moderate) |
| `keyword` | 57% | 20% | 8% | 0.11 | -0.10 (poor) |
