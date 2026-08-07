"""Turning a classified action plus recorded incidents into one decision.

The rule the whole project rests on: a hazard class alone never blocks anything.
It sets a floor. What raises the floor is evidence — an incident that already
happened, retrieved by similarity, and named in the reason so the person reading
the block can go check whether the guard is right.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .config import Config
from .corpus import Hit, search
from .rules import CRITICAL, HIGH, MEDIUM, Hazard, classify_command, classify_write, escalate, worst

ALLOW = "allow"
ASK = "ask"
DENY = "deny"
DEFER = "defer"

# Tool calls that carry a shell command, by tool name.
COMMAND_TOOLS = ("Bash", "PowerShell", "BashOutput")
WRITE_TOOLS = ("Write", "Edit", "NotebookEdit", "MultiEdit")


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

    @property
    def blocked(self) -> bool:
        return self.decision == DENY


def action_text(tool_name: str, tool_input: dict) -> str:
    """The human-readable action a tool call represents."""
    if tool_name in COMMAND_TOOLS:
        return str(tool_input.get("command", ""))
    if tool_name in WRITE_TOOLS:
        target = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        return str(target)
    for key in ("command", "file_path", "path", "url", "query", "prompt"):
        if key in tool_input:
            return str(tool_input[key])
    return ""


def evaluate(tool_name: str, tool_input: dict, config: Config, corpus_dir: Path | None = None) -> Decision:
    text = action_text(tool_name, tool_input)
    if not text.strip():
        return Decision(DEFER, "nothing to inspect", intended=DEFER)

    if tool_name in WRITE_TOOLS:
        hazards = classify_write(text, config.protected_paths)
    else:
        hazards = classify_command(text)

    severity = worst(hazards)
    if severity is None:
        # No hazard means no retrieval. Evidence is there to justify friction, and
        # there is no friction to justify here — searching anyway would spend
        # milliseconds on every harmless call and print precedents nobody needs.
        intended = ALLOW if config.allow_safe else DEFER
        return Decision(intended, "no hazard class matched", intended=intended)

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

    if severity == CRITICAL:
        intended = DENY
    elif severity == HIGH:
        intended = ASK
    else:  # MEDIUM
        intended = ASK if evidence else DEFER

    decision = intended
    if config.mode == "observe" and intended == DENY:
        decision = ASK

    return Decision(
        decision=decision,
        reason=explain(hazards, evidence, severity, intended, config.mode),
        severity=severity,
        hazards=hazards,
        evidence=evidence,
        intended=intended,
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
    if mode == "observe" and intended == DENY:
        parts.append("observe mode: recorded as a block, not enforced")
    return " | ".join(parts)


SEVERITY_LABEL = {CRITICAL: "critical", HIGH: "high", MEDIUM: "medium"}
