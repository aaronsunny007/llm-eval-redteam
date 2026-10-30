"""One-command demo: red-team a vulnerable toy app and a guarded one, no model needed.

    pip install -e .
    python examples/demo/run_demo.py

Expected: the vulnerable app FAILS the gate (it leaks canaries), the guarded app PASSES.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def wait_for(port: int) -> None:
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
            return
        except OSError:
            time.sleep(0.2)
    raise SystemExit(f"toy app on port {port} did not start")


def run_gate(config: str) -> int:
    exe = shutil.which("llm-redteam") or str(Path(sys.executable).with_name("llm-redteam"))
    return subprocess.call([exe, "ci", str(HERE / config)], cwd=ROOT)


def main() -> int:
    servers = [
        subprocess.Popen([sys.executable, str(HERE / "toy_apps.py"), mode, str(port)], cwd=ROOT)
        for mode, port in (("vulnerable", 8081), ("safe", 8082))
    ]
    try:
        wait_for(8081)
        wait_for(8082)
        print("\n=== 1/2  Vulnerable app (no defences): the gate should FAIL ===\n", flush=True)
        vulnerable = run_gate("vulnerable.yaml")
        print("\n=== 2/2  Same app behind an output guard: the gate should PASS ===\n", flush=True)
        safe = run_gate("safe.yaml")
    finally:
        for s in servers:
            s.terminate()
    ok = vulnerable == 1 and safe == 0
    print(
        "\nDemo " + ("worked: the gate caught the leaky app and passed the guarded one."
                     if ok else f"did not behave as expected (exit codes {vulnerable}, {safe}).")
    )  # fmt: skip
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
