"""List the model names an OpenAI-compatible endpoint offers for your key.

    python scripts/list_models.py                      # Gemini, uses GEMINI_API_KEY
    python scripts/list_models.py --base-url https://api.openai.com/v1 --key-env OPENAI_API_KEY

Prints only model names; the key is never printed.
"""

from __future__ import annotations

import argparse
import os

import httpx


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="https://generativelanguage.googleapis.com/v1beta/openai")
    ap.add_argument("--key-env", default="GEMINI_API_KEY")
    args = ap.parse_args()
    key = os.getenv(args.key_env)
    if not key:
        raise SystemExit(f"environment variable {args.key_env} is not set")
    r = httpx.get(
        args.base_url.rstrip("/") + "/models",
        headers={"Authorization": f"Bearer {key}"},
        timeout=30,
    )
    if r.status_code != 200:
        raise SystemExit(f"the endpoint answered {r.status_code}: check the key and base URL")
    for m in sorted(item["id"].removeprefix("models/") for item in r.json().get("data", [])):
        print(m)


if __name__ == "__main__":
    main()
