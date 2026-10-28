# Security policy

## Reporting a vulnerability in this tool

Please use GitHub's private reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. Do not open a public issue for something exploitable. You can expect
an acknowledgement within a week.

In scope: code execution or secret exposure through config files or data files, unsafe handling
of `${ENV:NAME}` placeholders in the HTTP target, and anything that lets a malicious attack file
or transcript harm the machine that loads it.

## Responsible use

`llm-redteam` sends adversarial prompts to a system. Only run it against systems you own or are
explicitly authorised to test, and respect the terms of any hosted model or API you point it at.

- The bundled attack payloads come from public research datasets (see
  [`data/attacks/NOTICE.md`](data/attacks/NOTICE.md)); this project does not add new attack text.
- Committed transcripts include model responses to harmful requests (the jailbreak set), kept so
  the judge can be audited. Treat them as test data, not as instructions.
- All secrets in the reference scenario are fictitious canaries. Never put real credentials or
  customer data in a scenario file.
