"""Where the guard reads its corpus, where it writes its receipts, how hard it bites."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# Enforce: the guard may return `deny`.
# Observe: the guard never blocks; it records what it *would* have done.
MODES = ("observe", "enforce")

CONFIG_NAMES = ("guard.toml", ".guard.toml")


def _root() -> Path:
    """Installation root: the directory holding this package."""
    return Path(__file__).resolve().parent.parent


@dataclass
class Config:
    mode: str = "observe"
    corpus_dir: Path = field(default_factory=lambda: _root() / "corpus")
    ledger_path: Path = field(default_factory=lambda: _root() / "ledger.jsonl")
    # Number of incidents retrieved as evidence for a single decision.
    evidence: int = 3
    # Minimum retrieval score for an incident to count as evidence at all.
    min_score: float = 0.35
    # The guard never grants permission it was not asked to grant. Flipping this
    # on lets it return `allow` for actions it classifies as harmless, which
    # silences the normal permission prompt — opt in deliberately.
    allow_safe: bool = False
    # Paths that must never be written by a tool call without a prompt, relative
    # or absolute, matched by suffix against the target path.
    protected_paths: tuple[str, ...] = (
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".env",
        "key.txt",
        "credentials.json",
        "id_rsa",
    )

    @classmethod
    def load(cls, start: Path | None = None) -> "Config":
        """Read the nearest guard.toml, walking up from `start`, then env overrides."""
        cfg = cls()
        path = _find_config(start or Path.cwd())
        if path is not None:
            data = tomllib.loads(path.read_text(encoding="utf-8")).get("guard", {})
            base = path.parent
            if "mode" in data and data["mode"] in MODES:
                cfg.mode = data["mode"]
            if "corpus_dir" in data:
                cfg.corpus_dir = _resolve(base, data["corpus_dir"])
            if "ledger_path" in data:
                cfg.ledger_path = _resolve(base, data["ledger_path"])
            if "evidence" in data:
                cfg.evidence = int(data["evidence"])
            if "min_score" in data:
                cfg.min_score = float(data["min_score"])
            if "allow_safe" in data:
                cfg.allow_safe = bool(data["allow_safe"])
            if "protected_paths" in data:
                cfg.protected_paths = tuple(data["protected_paths"])

        env_mode = os.environ.get("GUARD_MODE")
        if env_mode in MODES:
            cfg.mode = env_mode
        env_corpus = os.environ.get("GUARD_CORPUS")
        if env_corpus:
            cfg.corpus_dir = Path(env_corpus)
        env_ledger = os.environ.get("GUARD_LEDGER")
        if env_ledger:
            cfg.ledger_path = Path(env_ledger)
        return cfg


def _resolve(base: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else (base / path)


def _find_config(start: Path) -> Path | None:
    start = start.resolve()
    for directory in (start, *start.parents):
        for name in CONFIG_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    for name in CONFIG_NAMES:
        candidate = _root() / name
        if candidate.is_file():
            return candidate
    return None
