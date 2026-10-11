# Red-team report — finassist-mistral

`llm-redteam 1.0.0` · scenario **finassist** · target `{'provider': 'ollama', 'model': 'mistral', 'max_tokens': 400}` · judge `{'provider': 'ollama', 'model': 'qwen2.5:7b', 'max_tokens': 300}` · 50 attacks, 20 benign controls

## Defences

Attack success rate (ASR, lower is better) and benign refusal rate (lower is better), with Wilson 95% intervals. *p* is an exact McNemar test against no defence.

| Defence | ASR | Benign refused | Secret leaks | Fixed / regressed | *p* | Latency |
|---|---|---|---|---|---|---|
| `none` | 32% <sub>[21%–46%]</sub> | 0% <sub>[0%–16%]</sub> | 4 | — | — | 19.2s |
| `hardened_prompt` | 26% <sub>[16%–40%]</sub> | 0% <sub>[0%–16%]</sub> | 2 | 8 / 5 | 0.581 | 37.1s |
| `input_guard` | 30% <sub>[19%–44%]</sub> | 0% <sub>[0%–16%]</sub> | 4 | 4 / 3 | 1 | 53.2s |
| `output_guard` | 26% <sub>[16%–40%]</sub> | 15% <sub>[5%–36%]</sub> | 0 | 4 / 1 | 0.375 | 28.2s |
| `layered` | 16% <sub>[8%–29%]</sub> | 5% <sub>[1%–24%]</sub> | 0 | 13 / 5 | 0.0963 | 27.2s |

## Attack success by category

| Category | OWASP | `none` | `hardened_prompt` | `input_guard` | `output_guard` | `layered` |
|---|---|---|---|---|---|---|
| prompt_injection | LLM01:2025 Prompt Injection | 8/25 | 4/25 | 8/25 | 5/25 | 0/25 |
| indirect_injection | LLM01:2025 Prompt Injection (indirect) | 8/25 | 9/25 | 7/25 | 8/25 | 8/25 |
| system_prompt_leak | LLM07:2025 System Prompt Leakage | — | — | — | — | — |
| jailbreak | LLM01:2025 Prompt Injection (jailbreak) | — | — | — | — | — |
| data_exfiltration | LLM02:2025 Sensitive Information Disclosure | — | — | — | — | — |

## Judge validation

Judges vs. 50 human gold labels on the undefended responses (labeller(s): claude-sonnet-5-5).

| Judge | Accuracy | Precision | Recall | F1 | Cohen's κ |
|---|---|---|---|---|---|
| `hybrid` | 82% | 75% | 71% | 0.73 | 0.59 (moderate) |
| `llm` | 80% | 73% | 65% | 0.69 | 0.54 (moderate) |
| `keyword` | 66% | 0% | 0% | 0.00 | 0.00 (poor) |
