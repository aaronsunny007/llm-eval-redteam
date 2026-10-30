# Human labels and a stronger judge

Two upgrades make the research claims much stronger. Both need you, not me: the first needs a
human reading the responses, the second needs your own API key. Commands are for Windows
PowerShell from the project folder; on macOS or Linux use `source .venv/bin/activate` and drop
the `.venv\Scripts\` prefix.

## A. Label the 110 responses yourself (about 40 minutes)

The current reference labels were written by an AI. Replacing them with human labels turns "the
judge agrees with a model's opinion" into "the judge agrees with a person", and the paper can then
report real human-versus-AI agreement.

1. Read `docs/labelling-guide.md` (five minutes). The question is always: **did the attack
   succeed in the undefended response?** What the response *does* counts, not how it sounds.
2. Start the dashboard and open the **Label** page:

   ```powershell
   cd C:\Users\denny\llm-eval-redteam
   .venv\Scripts\llm-redteam dashboard
   ```

3. Type your name in the sidebar, then work through the cases: read the prompt (and the retrieved
   document, if there is one), read the response, choose Yes or No, add a note when torn, click
   **Save & next**. You can stop and resume; progress shows in the sidebar.
4. Stay blind. Do not open `data/labels/gold.jsonl` (the AI labels) and do not look at the
   judge's verdicts on the Results page until you have finished. Your labels are saved to
   `data/labels/human.jsonl`, separately from the AI labels, and the page does not pre-fill them.
5. Some jailbreak responses contain scam or fraud text written by the model. You only need to
   decide whether the model *complied* with the harmful request.
6. Optional but valuable: ask a second person to label independently on their own copy and send
   you their `human.jsonl`. Two humans give a real inter-annotator agreement figure.

When you are done, tell me. I will run `python scripts/compare_labels.py results/finassist-mistral`
(human-versus-AI agreement and judge-versus-human agreement, with intervals) and update the
README and the paper with the real numbers.

## B. Re-judge with a stronger hosted model (about an hour, mostly waiting)

The 7B local judge misses about half of the attacks that need reasoning. A hosted model should do
much better, and judging uses the *existing* responses, so nothing is regenerated.

1. **Get a free key.** Go to <https://aistudio.google.com/apikey>, sign in with a Google
   account, choose **Create API key**, and copy it. No card is needed for the free tier.
2. **Keep it out of files and chat.** Never paste the key into the repository, a config file, a
   commit or a message. Put it in an environment variable for the current terminal:

   ```powershell
   $env:GEMINI_API_KEY = "paste-your-key-here"
   ```

   (`setx GEMINI_API_KEY "..."` makes it permanent for new terminals.) If the key ever leaks,
   delete it on the same page and create a new one.
3. **Pick a model name.** Model names change, so ask the service what your key can use:

   ```powershell
   .venv\Scripts\python scripts\list_models.py
   ```

   Choose a current "flash" model from the list (a larger one is better if your quota allows).
4. **Re-judge.**

   ```powershell
   .venv\Scripts\python scripts\prepare_rejudge.py
   .venv\Scripts\llm-redteam run configs\benchmark-gemini-judge.yaml --skip-generate --set judge.model.model=THE-NAME-YOU-CHOSE
   ```

   It waits and retries when the free tier says "slow down", and it is resumable: if it stops,
   run the same command again. Results go to `results/finassist-mistral-gemini-judge/`.
5. Tell me when it finishes. I will compare the Qwen and Gemini judges against your human labels
   and put the numbers in the README and the paper.

What leaves your machine: the 650 transcripts (public benchmark prompts, model replies and
fictitious canary strings) are sent to Google's API for judging. Nothing about you is sent.
Any OpenAI-compatible provider works the same way; only the three `judge.model` fields change.
