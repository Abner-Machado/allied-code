"""The receipt trail.

Every decision is appended as one JSON object per line: what was proposed, what
the guard decided, which incidents it leaned on, and how long it took. A block
you cannot audit later is just an obstacle, so the receipt is not optional and
the guard writes one even when it defers.

Commands are redacted before they are written. A guard that leaks the secret it
was protecting is worse than no guard.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

from .decide import Decision

MAX_COMMAND = 600

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(sk|rk|pk)-[A-Za-z0-9_\-]{12,}"), "<api-key>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"), "<github-token>"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "<slack-token>"),
    (re.compile(r"(?i)\b(authorization|bearer)\s*[:=]?\s*[A-Za-z0-9._\-]{12,}"), r"\1 <redacted>"),
    (re.compile(r"(?i)\b(api[_-]?key|token|password|passwd|secret)(\s*[:=]\s*)[^\s\"']{6,}"), r"\1\2<redacted>"),
    (re.compile(r"\b[A-Fa-f0-9]{40,}\b"), "<hex>"),
)


def redact(text: str) -> str:
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    if len(text) > MAX_COMMAND:
        text = text[:MAX_COMMAND] + f"… (+{len(text) - MAX_COMMAND} chars)"
    return text


def correlation_key(session_id: str, tool: str, action: str) -> str:
    """The identifier that lets a decision be paired with what happened next.

    `tool_use_id` would be the obvious key, but it is not guaranteed to arrive on
    both hook events, and a key that is empty half the time silently pairs
    everything with everything. Hashing the three things both events do carry
    survives that. Two identical commands in one session collide on purpose: they
    are counted, not identified.
    """
    return hashlib.sha1(f"{session_id}|{tool}|{action}".encode("utf-8")).hexdigest()[:12]


@dataclass
class Receipt:
    ts: str
    tool: str
    action: str
    decision: str
    intended: str
    mode: str
    severity: str | None
    hazards: list[str]
    evidence: list[dict]
    reason: str
    latency_ms: float
    retrieval: str = "skipped"
    session_id: str = ""
    tool_use_id: str = ""
    cwd: str = ""
    agent: str = ""
    # "decision" here, "outcome" on the line written after the tool ran. Receipts
    # written before this field existed have no `kind` and are read as decisions.
    kind: str = "decision"
    # Pairs this decision with the outcome line for the same call. See
    # `correlation_key`.
    key: str = ""

    def to_json(self) -> str:
        return json.dumps(self.__dict__, ensure_ascii=False)


def build(
    tool: str,
    action: str,
    decision: Decision,
    mode: str,
    started: float,
    payload: dict | None = None,
) -> Receipt:
    payload = payload or {}
    session_id = str(payload.get("session_id", ""))[:64]
    redacted = redact(action)
    return Receipt(
        ts=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        tool=tool,
        action=redacted,
        decision=decision.decision,
        intended=decision.intended,
        mode=mode,
        severity=decision.severity,
        hazards=[h.id for h in decision.hazards],
        evidence=[{"id": hit.incident.id, "score": hit.score} for hit in decision.evidence],
        reason=redact(decision.reason),
        retrieval=getattr(decision, "retrieval", "skipped"),
        latency_ms=round((time.perf_counter() - started) * 1000, 2),
        session_id=session_id,
        tool_use_id=str(payload.get("tool_use_id", ""))[:64],
        cwd=str(payload.get("cwd", ""))[:200],
        agent=str(payload.get("agent") or os.environ.get("GUARD_AGENT", ""))[:64],
        key=correlation_key(session_id, tool, redacted),
    )


def append(path: Path, receipt: Receipt) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(receipt.to_json() + "\n")
    except OSError:
        # A ledger that cannot be written must never take the session down.
        pass


def read(path: Path, limit: int | None = None) -> list[dict]:
    if not path.is_file():
        return []
    rows: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows[-limit:] if limit else rows
