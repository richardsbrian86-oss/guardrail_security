"""Run with python -I backend/run.py --policy <operator-owned policy.json>."""
import argparse
import json
from pathlib import Path
import sys

# -I isolates user site packages/PYTHONPATH; load only this trusted code directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from guardrails.core import Broker, Denied, MAX_REQUEST, Policy
from guardrails.windows import BoundaryError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    args = parser.parse_args()
    try:
        policy = Policy.load(args.policy)
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        response = Broker(policy).handle(raw)
    except (Denied, BoundaryError, OSError, ValueError):
        response = {"version": 1, "ok": False, "reason": "startup_denied"}
    except Exception:
        response = {"version": 1, "ok": False, "reason": "internal_error_denied"}
    print(json.dumps(response, ensure_ascii=True, separators=(",", ":")))
    return 0 if response["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
