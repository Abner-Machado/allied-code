"""What happened after the guard spoke.

The guard asks. Until now it never learned the answer. That answer is already
lying on the floor of every session: when a call is questioned and the human says
no, the tool never runs, so no `PostToolUse` event ever arrives. Silence is the
label. When the human says yes, the event arrives and the guard has just been
overruled.

So this module writes one extra line — "this call ran" — and pairs it back to the
decision that preceded it. That pairing turns the ledger into the only honest
measure a guard can have: how often the person it protects agreed with it.

The pairing changes no decision, ever. It produces a report and, later, a
proposed edit to the corpus. `DESIGN.md` says precedent escalates and never
de-escalates; a guard that quietly relaxes because it was overruled a few times
is a guard that can be argued down, and the failure mode is silent. Lowering
friction stays a human act, recorded as a commit.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .config import Config
from .decide import ASK, DENY, action_text
from .ledger import correlation_key, redact

# A decision younger than this may simply still be waiting on the human. Counting
# it as "stopped" would inflate the guard's own score, which is the one number
# this file exists to keep honest.
GRACE_SECONDS = 120

EXECUTED = "executed"
FAILED = "failed"


def record(payload: dict) -> dict:
    """The outcome line for one finished tool call."""
    tool = str(payload.get("tool_name", ""))
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    session_id = str(payload.get("session_id", ""))[:64]
    action = redact(action_text(tool, tool_input))
    return {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "kind": "outcome",
        "key": correlation_key(session_id, tool, action),
        "tool": tool,
        "outcome": FAILED if _failed(payload.get("tool_response")) else EXECUTED,
        "session_id": session_id,
        "tool_use_id": str(payload.get("tool_use_id", ""))[:64],
    }


def _failed(response: object) -> bool:
    """Did the tool itself fail? A failure is not a refusal and is not counted as one."""
    if isinstance(response, dict):
        if response.get("success") is False:
            return True
        return bool(response.get("error"))
    return False


@dataclass
class Tally:
    cited: int = 0
    proceeded: int = 0
    stopped: int = 0


@dataclass
class Verdict:
    questioned: int = 0
    proceeded: int = 0
    stopped: int = 0
    pending: int = 0
    outcomes: int = 0
    incidents: dict[str, Tally] = field(default_factory=dict)
    hazards: dict[str, Tally] = field(default_factory=dict)

    @property
    def wired(self) -> bool:
        """Whether any outcome was ever recorded. Without it the report is noise."""
        return self.outcomes > 0

    @property
    def agreement(self) -> float | None:
        settled = self.proceeded + self.stopped
        return self.stopped / settled if settled else None


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z")
    except (ValueError, TypeError):
        return None


def verdict(rows: list[dict], now: datetime | None = None) -> Verdict:
    """Pair every questioned decision with whether the call actually ran.

    Rows without a `kind` predate the outcome loop and are read as decisions, so
    an old ledger still parses — it simply has nothing to pair against.
    """
    now = now or datetime.now().astimezone()
    out = Verdict()

    # `tool_use_id` identifies the exact call and is preferred when the runtime
    # sends it on both events. The hash is the fallback for the ones that do not,
    # and it is what keeps two identical commands from pairing with each other.
    executed: dict[str, int] = {}
    exact: set[str] = set()
    for row in rows:
        if row.get("kind") == "outcome":
            out.outcomes += 1
            key = row.get("key", "")
            executed[key] = executed.get(key, 0) + 1
            if row.get("tool_use_id"):
                exact.add(row["tool_use_id"])

    for row in rows:
        if row.get("kind", "decision") != "decision":
            continue
        if row.get("decision") not in (ASK, DENY):
            continue
        out.questioned += 1

        key = row.get("key", "")
        call_id = row.get("tool_use_id", "")
        stamp = _parse_ts(row.get("ts", ""))
        if call_id and call_id in exact:
            exact.discard(call_id)
            executed[key] = max(executed.get(key, 0) - 1, 0)
            fate = "proceeded"
            out.proceeded += 1
        elif executed.get(key, 0) > 0:
            executed[key] -= 1
            fate = "proceeded"
            out.proceeded += 1
        elif stamp is not None and (now - stamp).total_seconds() < GRACE_SECONDS:
            fate = None
            out.pending += 1
        else:
            fate = "stopped"
            out.stopped += 1

        for evidence in row.get("evidence", []):
            _credit(out.incidents, evidence.get("id", ""), fate)
        for hazard in row.get("hazards", []):
            _credit(out.hazards, hazard, fate)

    return out


def _credit(table: dict[str, Tally], name: str, fate: str | None) -> None:
    if not name:
        return
    tally = table.setdefault(name, Tally())
    tally.cited += 1
    if fate == "proceeded":
        tally.proceeded += 1
    elif fate == "stopped":
        tally.stopped += 1


def noise(verdicts: dict[str, Tally], minimum: int = 3) -> list[str]:
    """Incidents cited often and overruled every single time.

    Not evidence that the rule is wrong — evidence that it is firing where it does
    not belong. The corpus entry is the thing to edit, and a human edits it.
    """
    return sorted(
        name
        for name, tally in verdicts.items()
        if tally.proceeded >= minimum and tally.stopped == 0
    )


def append_line(path: Path, row: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    except OSError:
        # Same contract as the decision ledger: a ledger that cannot be written
        # must never take the session down.
        pass


def run(raw: str) -> dict:
    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    append_line(Config.load().ledger_path, record(payload))
    return {}


def main() -> int:
    """PostToolUse entry point. Writes a line, says nothing, never fails loudly."""
    try:
        run(sys.stdin.read())
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
