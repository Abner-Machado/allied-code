"""Injection layer: put the precedent in front of the work, not after it.

`hook.py` is the last line — it sees a command that already exists and can only
add friction. By then the plan is written and the reasoning that produced it is
gone. This module is the earlier line: when the task arrives, and again when a
session opens, it retrieves from the same corpus and hands the result to the
model as context, so the bad command is never proposed in the first place.

Three properties this layer must hold, because it writes into a prompt:

1. It only ever emits text it read from the corpus directory. Nothing is
   synthesised, nothing is fetched, nothing else on disk is eligible. The corpus
   is author-owned by definition, and that boundary is the only reason writing
   into a prompt is acceptable at all.
2. It is capped. An injection that grows with the corpus turns into a tax paid on
   every single turn, and the first thing anyone does with a tax like that is
   remove the thing charging it.
3. It fails into silence. No corpus, bad JSON, unreadable file: emit nothing. The
   session must be unable to tell the difference between "no precedent" and
   "guard broken", except in the ledger.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from .config import Config
from .corpus import Hit, search, tokenize

# The budget for the whole injection. Roughly a short paragraph: enough for three
# rules, far too little to be worth summarising away.
MAX_CHARS = 1200
MAX_INCIDENTS = 3
# Lower than the guard's own floor (0.35), and the reason is not that prompts
# deserve looser evidence. Retrieval scores are normalised by the weight of the
# whole query, so a score is only comparable between queries of similar length.
# Measured against this corpus, one intent — force-pushing a tidied history —
# scores 0.446 written as a command, 0.398 as a short sentence and 0.219 as the
# sentence a person actually types. A floor calibrated on commands, applied to
# prompts, is not a strict filter: it is an off switch that looks like a setting.
PROMPT_MIN_SCORE = 0.15


def _render(hits: list[Hit], heading: str) -> str:
    lines = [heading]
    for hit in hits:
        incident = hit.incident
        rule = incident.rule or incident.title
        lines.append(f"- {rule} (recorded {incident.date or 'undated'}, see corpus/{incident.path.name})")
    lines.append("These are incidents recorded on this machine, not general advice.")
    text = "\n".join(lines)
    return text[:MAX_CHARS]


def _names_the_subject(prompt_tokens: frozenset[str], hit: Hit) -> bool:
    """Does the request use any of the incident's own curated vocabulary?

    The score alone cannot carry this decision. Lowering the floor far enough for
    a sentence to pass also lets prose through on nothing but shared filler —
    "rename a local variable in a test file" retrieved three incidents at 0.15.
    The `tags` line is the one part of an incident a human chose deliberately, so
    requiring one of those words is a cheap second door: the score says "similar
    enough", the tags say "about the same subject".
    """
    vocabulary = frozenset(tokenize(f"{hit.incident.id} {' '.join(hit.incident.tags)}"))
    return bool(prompt_tokens & vocabulary)


def for_prompt(prompt: str, config: Config) -> str:
    """Precedent relevant to the task the user just described."""
    if not prompt.strip():
        return ""
    hits = search(config.corpus_dir, prompt, limit=MAX_INCIDENTS, min_score=PROMPT_MIN_SCORE)
    prompt_tokens = frozenset(tokenize(prompt))
    hits = [hit for hit in hits if _names_the_subject(prompt_tokens, hit)]
    if not hits:
        return ""
    return _render(hits, "Recorded incidents relevant to this request:")


def for_session(config: Config) -> str:
    """The standing rules, for the top of a session.

    Severity order, not relevance: at session start there is no task to be
    relevant to. This is the short list of things that have already gone wrong
    here badly enough to be worth carrying into every session.
    """
    from .corpus import load

    order = {"critical": 0, "high": 1, "medium": 2}
    incidents = sorted(load(config.corpus_dir), key=lambda i: (order.get(i.severity, 3), i.id))
    top = [Hit(incident, 1.0) for incident in incidents if incident.severity == "critical"][:MAX_INCIDENTS]
    if not top:
        return ""
    return _render(top, "Standing rules from recorded incidents on this machine:")


def _envelope(event: str, context: str) -> dict[str, Any]:
    if not context:
        return {}
    return {"hookSpecificOutput": {"hookEventName": event, "additionalContext": context}}


def run(raw: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}

    event = str(payload.get("hook_event_name") or "UserPromptSubmit")
    config = Config.load()
    if event == "SessionStart":
        return _envelope(event, for_session(config))
    return _envelope(event, for_prompt(str(payload.get("prompt", "")), config))


def main() -> int:
    try:
        raw = sys.stdin.read()
        out = run(raw)
    except Exception:
        out = {}
    if out:
        print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
