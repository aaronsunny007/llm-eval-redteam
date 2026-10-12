# Ledger red-team gate (drop-in)

Copy this folder's contents into the root of the [Ledger](https://github.com/aaronsunny007/ledger)
repository:

```
.github/workflows/redteam.yml   weekly + on-demand workflow
redteam/ledger.yaml             attacks, target (POST /ask), Gemini judge, gate
redteam/scenario.yaml           Ledger's answer prompt, for judging leaks
redteam/README.md               what it covers and its limits
```

Then add a `GEMINI_API_KEY` repository secret (Ledger already uses one) and run the
**redteam** workflow from the Actions tab. Without the secret the job is skipped, not failed.

Checked here against a fake `/ask` server and a fake OpenAI-compatible judge (85 attacks
evaluated, a 429 from the judge retried, gate passed). It has not run against live Gemini or a
live Ledger index, so expect to adjust the filing it downloads (`AAPL 2024`) and the judge
model name (`gemini-2.5-flash`) on the first run.
