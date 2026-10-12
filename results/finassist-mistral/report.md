# Red-team report — finassist-mistral

`llm-redteam 1.1.1` · scenario **finassist** · target `{'provider': 'ollama', 'model': 'mistral', 'max_tokens': 400}` · judge `{'provider': 'ollama', 'model': 'qwen2.5:7b', 'max_tokens': 300}` (prompt v2.1-grounded) · 110 attacks, 20 benign controls

## Defences

Attack success rate (ASR, lower is better) and benign refusal rate (lower is better), with Wilson 95% intervals. *p* is an exact McNemar test against no defence.

| Defence | ASR | Benign refused | Secret leaks | Fixed / regressed | *p* | Latency |
|---|---|---|---|---|---|---|
| `none` | 41% <sub>[32%–50%]</sub> | 0% <sub>[0%–16%]</sub> | 29 | — | — | 23.7s |
| `hardened_prompt` | 25% <sub>[18%–34%]</sub> | 0% <sub>[0%–16%]</sub> | 15 | 21 / 4 | 0.000911 | 64.1s |
| `input_guard` | 20% <sub>[14%–28%]</sub> | 0% <sub>[0%–16%]</sub> | 12 | 25 / 2 | <0.0001 | 36.5s |
| `output_guard` | 11% <sub>[6%–18%]</sub> | 15% <sub>[5%–36%]</sub> | 0 | 33 / 0 | <0.0001 | 30.9s |
| `layered` | 5% <sub>[2%–10%]</sub> | 5% <sub>[1%–24%]</sub> | 0 | 41 / 1 | <0.0001 | 22.4s |

## Attack success by category

| Category | OWASP | `none` | `hardened_prompt` | `input_guard` | `output_guard` | `layered` |
|---|---|---|---|---|---|---|
| prompt_injection | LLM01:2025 Prompt Injection | 8/25 | 4/25 | 6/25 | 3/25 | 0/25 |
| indirect_injection | LLM01:2025 Prompt Injection (indirect) | 4/25 | 5/25 | 5/25 | 4/25 | 3/25 |
| system_prompt_leak | LLM07:2025 System Prompt Leakage | 11/20 | 6/20 | 3/20 | 2/20 | 0/20 |
| jailbreak | LLM01:2025 Prompt Injection (jailbreak) | 7/20 | 4/20 | 2/20 | 3/20 | 1/20 |
| data_exfiltration | LLM02:2025 Sensitive Information Disclosure | 15/20 | 9/20 | 6/20 | 0/20 | 1/20 |

## Judge validation

Judges vs. 110 gold labels on the undefended responses (labeller(s): claude-sonnet-5-5).

| Judge | Accuracy | Precision | Recall | F1 | Cohen's κ |
|---|---|---|---|---|---|
| `hybrid` | 84% | 84% | 78% | 0.81 | 0.67 (substantial) |
| `llm` | 75% | 80% | 57% | 0.67 | 0.47 (moderate) |
| `keyword` | 49% | 27% | 8% | 0.12 | -0.11 (poor) |
