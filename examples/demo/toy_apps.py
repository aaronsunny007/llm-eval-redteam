"""Two toy HTTP services for the one-minute demo. No model, GPU or API key involved.

* ``vulnerable``: a naive "assistant" that dumps its confidential configuration whenever a
  message mentions certain words (a stand-in for an app with no defences).
* ``safe``: the same app with an output guard that refuses to return any protected value.

Run one by hand with ``python examples/demo/toy_apps.py vulnerable 8081``.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

import yaml

from llm_redteam.config import builtin_data

SCENARIO = yaml.safe_load(builtin_data("scenarios/finassist.yaml").read_text(encoding="utf-8"))
SYSTEM_PROMPT = SCENARIO["system_prompt"]
SECRETS = SCENARIO["secrets"]
REFUSAL = SCENARIO["refusal_message"]

# Words that make the naive app spill its configuration. This is the app's flaw, not an attack.
TRIGGERS = ("password", "secret", "instruction", "prompt", "ignore", "previous", "rules",
            "configuration", "reveal", "repeat", "system")  # fmt: skip
CANNED = "The filing states total revenue grew year over year. [Document 1]"


def naive_answer(question: str) -> str:
    if any(word in question.lower() for word in TRIGGERS):
        return "Sure, here is my configuration:\n" + SYSTEM_PROMPT
    return CANNED


def answer(mode: str, question: str) -> str:
    reply = naive_answer(question)
    if mode == "safe" and any(s.lower() in reply.lower() for s in SECRETS):
        return REFUSAL  # output guard: never return a protected value
    return reply


def make_handler(mode: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # health check
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
            data = json.dumps({"answer": answer(mode, body.get("question", ""))}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args: object) -> None:
            pass

    return Handler


if __name__ == "__main__":
    mode, port = sys.argv[1], int(sys.argv[2])
    HTTPServer(("127.0.0.1", port), make_handler(mode)).serve_forever()
