"""Turning a classified action plus recorded incidents into one decision.

The rule the whole project rests on: a hazard class alone never blocks anything.
It sets a floor. What raises the floor is evidence — an incident that already
happened, retrieved by similarity, and named in the reason so the person reading
the block can go check whether the guard is right.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config
from .corpus import Hit, search
from .backends import classify_command, classify_write, classify_mcp
from .rules import CRITICAL, HIGH, MEDIUM, Hazard, worst, escalate

ALLOW = "allow"
ASK = "ask"
DENY = "deny"
DEFER = "defer"

# Tool calls that carry a shell command, by tool name.
COMMAND_TOOLS = ("Bash", "PowerShell", "BashOutput")
WRITE_TOOLS = ("Write", "Edit", "NotebookEdit", "MultiEdit")

# Keys whose value is a *target* (a path/id/url), never a credential. When an MCP
# call comes in we only ever surface one of these, truncated, so a token, cookie
# or session id handed as an argument can never reach the log or the search query.
_TARGET_KEYS = ("id", "path", "file_path", "file_id", "url", "message_id", "thread_id")

# Patterns that betray a secret regardless of where they show up. Anything that
# matches is replaced with [REDACTED] before the text is written anywhere.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    # ghp_ / sk- / xox[abpr]- style issuer tokens
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}"),
    re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}"),
    # a 16+ char value glued to a credential word
    re.compile(r"(?i)\b(key|token|secret|password|passwd)\b[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}"),
    # Authorization / Bearer header values
    re.compile(r"(?i)\bauthorization\b\s*[:=]\s*(?:bearer\s+)?[\"']?[A-Za-z0-9._\-]{8,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"),
)


def redact(text: str) -> str:
    """Mask anything that looks like a secret.

    Applied to the action text and to evidence before either is written to disk
    or used as a search query. A guard that logs the secret it was meant to
    protect is worse than no guard.
    """
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def action_text(tool_name: str, tool_input: dict) -> str:
    """The human-readable action a tool call represents.

    For MCP tools we never dump the arguments — that is how a token or cookie
    leaked in the previous build. We surface at most one short *target* drawn
    from a closed list of keys, truncated to 80 characters, then redact it.
    """
    if tool_name in COMMAND_TOOLS:
        return redact(str(tool_input.get("command", "")))
    if tool_name in WRITE_TOOLS:
        target = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        return redact(str(target))
    if tool_name.startswith("mcp__"):
        target = ""
        for key in _TARGET_KEYS:
            if key in tool_input:
                target = str(tool_input[key])[:80]
                break
        return redact(target)
    for key in ("command", "file_path", "path", "url", "query", "prompt"):
        if key in tool_input:
            return redact(str(tool_input[key]))
    return ""


@dataclass
class Decision:
    decision: str
    reason: str
    severity: str | None = None
    hazards: list[Hazard] = field(default_factory=list)
    evidence: list[Hit] = field(default_factory=list)
    # What the guard would have done if it were enforcing. In observe mode this
    # differs from `decision`, and that gap is the whole point of observe mode.
    intended: str = DEFER
    # How the precedent search turned out: "hit", "empty" or "skipped". Recorded
    # so a silent retrieval failure is visible instead of quietly lowering friction.
    retrieval: str = "skipped"

    @property
    def blocked(self) -> bool:
        return self.decision == DENY


def evaluate(tool_name: str, tool_input: dict, config: Config, corpus_dir: Path | None = None) -> Decision:
    text = action_text(tool_name, tool_input)
    if not text.strip():
        return Decision(DEFER, "nothing to inspect", intended=DEFER, retrieval="skipped")

    if tool_name in WRITE_TOOLS:
        hazards = classify_write(text, config.protected_paths)
    elif tool_name.startswith("mcp__"):
        hazards = classify_mcp(tool_name, tool_input)
    else:
        hazards = classify_command(text)

    severity = worst(hazards)
    if severity is None:
        # No hazard means no retrieval. Evidence is there to justify friction, and
        # there is no friction to justify here — searching anyway would spend
        # milliseconds on every harmless call and print precedents nobody needs.
        intended = ALLOW if config.allow_safe else DEFER
        return Decision(intended, "no hazard class matched", intended=intended, retrieval="skipped")

    # Two queries, best score per incident wins. The action text carries the
    # detail; the hazard vocabulary carries the meaning. A file path on its own
    # ("…/.claude/settings.json") is almost all detail and would otherwise dilute
    # every precedent below the threshold.
    where = corpus_dir or config.corpus_dir
    hazard_query = " ".join([*(h.id for h in hazards), *(t for h in hazards for t in h.tags)])
    evidence = _merge(
        search(where, f"{text} {hazard_query}", limit=config.evidence, min_score=config.min_score),
        search(where, hazard_query, limit=config.evidence, min_score=config.min_score),
        limit=config.evidence,
    )

    if _has_strong_precedent(evidence):
        severity = escalate(severity)

    # A delegated agent works under a raised floor. The orchestrator chose to run
    # this one and can be asked; the producer it delegated to was handed a narrow
    # mandate and a hazard class it was never asked to touch is the failure this
    # project exists for — `corpus/delegated-agent-deleted-tooling.md`. The floor
    # only goes up: no agent is ever granted something it would not otherwise get.
    if config.delegated:
        severity = escalate(severity)

    if severity == CRITICAL:
        intended = DENY
    elif severity == HIGH:
        intended = ASK
    else:  # MEDIUM
        intended = ASK if evidence else DEFER

    decision = intended
    if config.mode == "observe" and intended == DENY:
        decision = ASK

    retrieval = "hit" if evidence else "empty"

    return Decision(
        decision=decision,
        reason=explain(hazards, evidence, severity, intended, config.mode, config.agent if config.delegated else ""),
        severity=severity,
        hazards=hazards,
        evidence=evidence,
        intended=intended,
        retrieval=retrieval,
    )


def _merge(*rankings: list[Hit], limit: int) -> list[Hit]:
    best: dict[str, Hit] = {}
    for ranking in rankings:
        for hit in ranking:
            current = best.get(hit.incident.id)
            if current is None or hit.score > current.score:
                best[hit.incident.id] = hit
    return sorted(best.values(), key=lambda h: (-h.score, h.incident.id))[:limit]


def _has_strong_precedent(evidence: list[Hit]) -> bool:
    return any(hit.incident.severity in (CRITICAL, HIGH) and hit.score >= 0.5 for hit in evidence)


def explain(
    hazards: list[Hazard],
    evidence: list[Hit],
    severity: str,
    intended: str,
    mode: str,
    delegated_agent: str = "",
) -> str:
    lead = hazards[0]
    parts = [f"{lead.summary} [{lead.id}]"]
    if len(hazards) > 1:
        parts.append("also " + ", ".join(h.id for h in hazards[1:]))
    if evidence:
        cited = evidence[0].incident
        rule = cited.rule or cited.title
        parts.append(f"precedent {cited.id} ({cited.date or 'undated'}): {rule}")
    else:
        parts.append("no matching precedent on record")
    if delegated_agent:
        parts.append(f"delegated agent {delegated_agent}: floor raised one level")
    if mode == "observe" and intended == DENY:
        parts.append("observe mode: recorded as a block, not enforced")
    return " | ".join(parts)


SEVERITY_LABEL = {CRITICAL: "critical", HIGH: "high", MEDIUM: "medium"}
