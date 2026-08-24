"""Pluggable backend layer: choose the Rust or the Python classifier.

The rest of the system talks to this module, never to ``alliedcore`` directly.
That single boundary is what lets the optional Rust extension be absent without
breaking anything: when it is missing, the Python rules stand in, and when it is
present, every dict it returns is rebuilt into the ``Hazard`` dataclass before it
leaves this module — so nothing downstream ever sees a dict and trips over
``h.id`` / ``h.tags`` / ``h.severity``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .config import Config
from .rules import CRITICAL, HIGH, MEDIUM, Hazard, worst, escalate

# Re-exported so callers can import the vocabulary from one place.
__all__ = [
    "classify_command",
    "classify_write",
    "classify_mcp",
    "worst",
    "escalate",
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "Hazard",
    "get_backend_info",
    "BackendInfo",
]


@dataclass(frozen=True)
class BackendInfo:
    classifier: str  # "rust" | "python"
    reason: str
    rust_available: bool = False
    rust_version: str | None = None


# --- Rust backend detection -------------------------------------------------

def _try_import_rust():
    """Import the optional Rust extension ``alliedcore``.

    Returns the module, or None if it is not built/installed. A missing Rust
    extension is normal, not an error: the Python rules cover the same ground.
    """
    try:
        import alliedcore  # type: ignore
    except ImportError:
        return None
    return alliedcore


# --- Type adapter: Rust dict -> Hazard dataclass -----------------------------

def _adapt(items: list[Any]) -> list[Hazard]:
    """Rebuild Rust dicts into Hazard so downstream code uses attributes."""
    out: list[Hazard] = []
    for item in items:
        if isinstance(item, Hazard):
            out.append(item)
        elif isinstance(item, dict):
            out.append(Hazard(**{**item, "tags": tuple(item.get("tags", ()))}))
        else:
            out.append(item)
    return out


# --- Python fallback implementations -----------------------------------------

def _py_classify_command(command: str) -> list[Hazard]:
    from .rules import classify_command
    return classify_command(command)


def _py_classify_write(path: str, protected: tuple[str, ...]) -> list[Hazard]:
    from .rules import classify_write
    return classify_write(path, protected)


def _py_classify_mcp(tool_name: str, tool_input: dict) -> list[Hazard]:
    from .mcp_rules import classify_mcp
    return classify_mcp(tool_name, tool_input)


# --- Public API -------------------------------------------------------------

def _select_backend() -> BackendInfo:
    config = Config.load()
    env = os.environ.get("ALLIED_BACKEND", "").lower()
    rust = _try_import_rust()
    rust_ok = rust is not None and hasattr(rust, "classify_command") \
        and hasattr(rust, "classify_write") and hasattr(rust, "classify_mcp")

    if env == "python":
        return BackendInfo("python", "ALLIED_BACKEND=python (forced)")
    if env == "rust" and rust_ok:
        return BackendInfo("rust", "ALLIED_BACKEND=rust", True, getattr(rust, "__version__", "unknown"))
    if rust_ok:
        return BackendInfo("rust", "Rust extension available", True, getattr(rust, "__version__", "unknown"))
    return BackendInfo("python", "Rust extension not available")


_backend: BackendInfo | None = None


def get_backend_info() -> BackendInfo:
    global _backend
    if _backend is None:
        _backend = _select_backend()
    return _backend


def classify_command(command: str) -> list[Hazard]:
    info = get_backend_info()
    if info.classifier == "rust":
        import alliedcore  # type: ignore
        return _adapt(alliedcore.classify_command(command))
    return _py_classify_command(command)


def classify_write(path: str, protected: tuple[str, ...]) -> list[Hazard]:
    info = get_backend_info()
    if info.classifier == "rust":
        import alliedcore  # type: ignore
        return _adapt(alliedcore.classify_write(path, protected))
    return _py_classify_write(path, protected)


def classify_mcp(tool_name: str, tool_input: dict) -> list[Hazard]:
    """Classify an MCP tool call. Signature matches the Rust backend exactly."""
    info = get_backend_info()
    if info.classifier == "rust":
        import alliedcore  # type: ignore
        return _adapt(alliedcore.classify_mcp(tool_name, tool_input))
    return _py_classify_mcp(tool_name, tool_input)


def reset_backend() -> None:
    global _backend
    _backend = None
