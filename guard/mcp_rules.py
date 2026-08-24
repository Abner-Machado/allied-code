"""MCP tool-call classification, pure Python, no Rust dependency.

An MCP tool name looks like ``mcp__<server>__<action>``. The server may itself
contain single underscores (``claude_ai_Google_Drive``), which is exactly why the
parts are separated by a *double* underscore — splitting on ``__`` keeps the
server name intact.

The verb lives in the action part and can sit at the start (``trash_file``), at
the end (``ads_catalog_delete``) or be a two-word compound (``execute_action``).
We look for it in that order: whole action, a two-word verb in any position, the
first token, then any token. An unknown verb never goes silent — it is reported
as ``mcp.unknown-verb`` so the human sees the guard was unsure rather than blind.
"""

from __future__ import annotations

from .rules import CRITICAL, HIGH, MEDIUM, Hazard

# Verbs that destroy data with no undo path.
_DESTRUCTIVE_CRITICAL = {"delete", "purge", "drop"}
# Verbs that destroy data but are recoverable.
_DESTRUCTIVE_HIGH = {"trash", "remove", "unlink", "revoke", "disconnect", "cancel"}
# Verbs that push data or an effect outward, to others.
_OUTWARD = {
    "publish",
    "send",
    "post",
    "share",
    "execute_action",
    "create_release",
    "boost",
    "upload",
    "forward",
    "reply",
}
# Verbs that spend money or credits.
_SPEND = {"generate", "purchase", "confirm_billing"}
# Read-only verbs: a match means "no hazard", never silence.
_READONLY = {"get", "list", "search", "read", "show", "describe", "status"}

_TWO_WORD = {v for v in (*_OUTWARD, *_SPEND) if "_" in v}


def _split_tool(tool_name: str) -> tuple[str | None, str | None]:
    """Return (server, action) or (None, None) for a malformed name."""
    if not tool_name.startswith("mcp__"):
        return None, None
    parts = tool_name.split("__")
    if len(parts) < 3:
        return None, None
    return parts[1], parts[2]


def _find_verb(action: str) -> str | None:
    """Locate the hazard verb inside an action string, or None if absent."""
    if action in _READONLY:
        return None
    if action in _DESTRUCTIVE_CRITICAL:
        return f"critical:{action}"
    if action in _DESTRUCTIVE_HIGH:
        return f"high:{action}"
    if action in _OUTWARD:
        return f"outward:{action}"
    if action in _SPEND:
        return f"spend:{action}"

    tokens = action.split("_")

    # A two-word verb anywhere in the action (e.g. "execute_action").
    for verb in _TWO_WORD:
        pair = verb.split("_")
        for i in range(len(tokens) - len(pair) + 1):
            if tokens[i : i + len(pair)] == pair:
                if verb in _OUTWARD:
                    return f"outward:{verb}"
                return f"spend:{verb}"

    # First token, then any token.
    for token in (tokens[0], *tokens[1:]):
        if token in _DESTRUCTIVE_CRITICAL:
            return f"critical:{token}"
        if token in _DESTRUCTIVE_HIGH:
            return f"high:{token}"
        if token in _OUTWARD:
            return f"outward:{token}"
        if token in _SPEND:
            return f"spend:{token}"
        if token in _READONLY:
            return None

    return "unknown"


def classify_mcp(tool_name: str, tool_input: dict) -> list[Hazard]:
    """Classify an MCP tool call into hazard classes.

    ``tool_input`` is accepted for signature parity with the Rust backend and may
    carry an ``evidence`` hint, but the verdict comes from the tool name alone —
    classification must work with nothing but the name, which is all a pure
    Python fallback reliably has.
    """
    _server, action = _split_tool(tool_name)
    if action is None:
        # Malformed name (e.g. "mcp__so_uma_parte"): never raise, just report
        # that we could not make sense of it.
        return [
            Hazard(
                id="mcp.unknown-verb",
                severity=MEDIUM,
                summary="MCP tool name is malformed and could not be classified",
                tags=("mcp", "unknown", "malformed"),
                evidence=tool_name,
            )
        ]

    verdict = _find_verb(action)
    if verdict is None:
        return []
    if verdict == "unknown":
        return [
            Hazard(
                id="mcp.unknown-verb",
                severity=MEDIUM,
                summary=f"MCP action '{action}' is not a recognised verb",
                tags=("mcp", "unknown-verb", action),
                evidence=action,
            )
        ]

    kind, verb = verdict.split(":", 1)
    if kind == "critical":
        return [
            Hazard(
                id="mcp.destructive",
                severity=CRITICAL,
                summary=f"MCP call performs an irreversible destructive action ({verb})",
                tags=("mcp", "destructive", "irreversible", verb),
                evidence=verb,
            )
        ]
    if kind == "high":
        return [
            Hazard(
                id="mcp.destructive",
                severity=HIGH,
                summary=f"MCP call performs a recoverable destructive action ({verb})",
                tags=("mcp", "destructive", "recoverable", verb),
                evidence=verb,
            )
        ]
    if kind == "outward":
        return [
            Hazard(
                id="mcp.outward",
                severity=HIGH,
                summary=f"MCP call pushes data or an effect outward ({verb})",
                tags=("mcp", "outward", verb),
                evidence=verb,
            )
        ]
    # spend
    return [
        Hazard(
            id="mcp.spend",
            severity=MEDIUM,
            summary=f"MCP call may spend money or credits ({verb})",
            tags=("mcp", "spend", verb),
            evidence=verb,
        )
    ]
