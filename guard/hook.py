"""PreToolUse entry point.

Contract with the agent runtime: read one JSON object on stdin, write one JSON
object on stdout, exit 0. Anything else — a traceback, a slow corpus, a corrupt
incident file — must degrade into "no opinion", never into a broken session. A
guard that takes the tooling down with it will be uninstalled the same day, and
then it protects nothing.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

from .config import Config
from .decide import DEFER, DENY, Decision, action_text, evaluate
from .ledger import append, build


def respond(decision: str, reason: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
        }
    }
    if reason:
        out["hookSpecificOutput"]["permissionDecisionReason"] = reason
    return out


def run(raw: str) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return respond(DEFER)
    if not isinstance(payload, dict):
        return respond(DEFER)

    tool = str(payload.get("tool_name", ""))
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return respond(DEFER)

    config = Config.load()
    # The runtime knows who is calling; the guard's own env var is the fallback
    # for anything that does not say.
    config.agent = str(payload.get("agent") or config.agent)[:64]
    decision: Decision = evaluate(tool, tool_input, config)

    receipt = build(
        tool=tool,
        action=action_text(tool, tool_input),
        decision=decision,
        mode=config.mode,
        started=started,
        payload=payload,
    )
    append(config.ledger_path, receipt)

    if decision.decision == DEFER:
        # Say nothing loudly: the normal permission flow is the right default.
        return respond(DEFER)

    prefix = "blocked" if decision.decision == DENY else "needs a look"
    return respond(decision.decision, f"ops-guard: {prefix} — {decision.reason}")


def main() -> int:
    try:
        raw = sys.stdin.read()
    except Exception:
        return 0
    try:
        print(json.dumps(run(raw), ensure_ascii=False))
    except Exception:
        # Deliberately silent: an unhandled failure here would otherwise print a
        # traceback into the agent's transcript and be read as tool output.
        print(json.dumps(respond(DEFER)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
