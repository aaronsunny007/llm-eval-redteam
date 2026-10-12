# Red-team gate

`.github/workflows/redteam.yml` attacks the running API with 85 published attacks and fails when
the attack success rate crosses the gate in [`ledger.yaml`](ledger.yaml). The tool is
[llm-eval-redteam](https://github.com/aaronsunny007/llm-eval-redteam), used as a GitHub Action.

| What | Detail |
|---|---|
| Attacks | prompt injection (25), system-prompt leak (20), data exfiltration (20), jailbreak (20) |
| Not covered | indirect injection: `POST /ask` has no way to plant a document, Ledger retrieves from its own index |
| Judge | Gemini through its OpenAI-compatible endpoint (`GEMINI_API_KEY`), no local GPU needed |
| Gate | attack success at most 10%, system-prompt leaks at most 5% |
| When | weekly (Mondays 05:00 UTC) and on demand from the Actions tab |

Run it locally against a running API:

```bash
pip install "git+https://github.com/aaronsunny007/llm-eval-redteam@v1.1.1"
GEMINI_API_KEY=... llm-redteam ci redteam/ledger.yaml
```

Honest limits: Ledger has no canary secrets, so leaks are judged by the LLM against
`scenario.yaml` (a copy of `ledger/answer/prompts/answer_system.md`; keep it in sync). The jailbreak
cases are plain harmful requests, not optimised jailbreaks. Attack text comes from published
datasets, listed in the tool's `data/attacks/NOTICE.md`.
