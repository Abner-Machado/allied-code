"""Classification of a proposed action into hazard classes.

This module is deliberately dumb. It answers "what kind of action is this?",
never "should it run?". The decision lives in `guard.decide`, which weighs these
classes against the incidents in the corpus. Keeping the two apart is what makes
the guard auditable: a class can be wrong without a rule being wrong.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"

_SEVERITY_ORDER = {MEDIUM: 0, HIGH: 1, CRITICAL: 2}


@dataclass(frozen=True)
class Hazard:
    id: str
    severity: str
    summary: str
    tags: tuple[str, ...]
    evidence: str  # the substring that triggered the class


@dataclass(frozen=True)
class _Pattern:
    id: str
    severity: str
    summary: str
    tags: tuple[str, ...]
    regex: re.Pattern[str]


def _p(id: str, severity: str, summary: str, tags: str, pattern: str) -> _Pattern:
    return _Pattern(id, severity, summary, tuple(tags.split()), re.compile(pattern, re.I))


# Order matters only for readability; every pattern is tested.
COMMAND_PATTERNS: tuple[_Pattern, ...] = (
    _p(
        "fs.recursive-delete",
        CRITICAL,
        "recursive, forced delete of a directory tree",
        "filesystem delete destructive",
        r"\brm\s+(-[a-z]*\s+)*-[a-z]*r[a-z]*f|\brm\s+(-[a-z]*\s+)*-[a-z]*f[a-z]*r"
        r"|remove-item\b[^\n|;]*(-recurse\b[^\n|;]*-force|-force\b[^\n|;]*-recurse)"
        r"|\brmdir\s+/s|\bdel\s+/[fsq]",
    ),
    _p(
        "fs.wipe-device",
        CRITICAL,
        "formats or repartitions a device",
        "filesystem device destructive",
        r"\bmkfs\b|\bformat\s+[a-z]:|\bdiskpart\b|\bdd\s+if=.*\bof=/dev/",
    ),
    _p(
        "git.history-rewrite",
        CRITICAL,
        "rewrites or discards committed history",
        "git history destructive",
        r"git\s+push\b[^\n;|]*(--force\b(?!-with-lease)|(?<![\w-])-f(?![\w-]))"
        r"|git\s+reset\s+--hard|git\s+clean\s+-[a-z]*f|git\s+branch\s+-D\b"
        r"|git\s+filter-branch|git\s+reflog\s+expire",
    ),
    _p(
        "publish.outward",
        HIGH,
        "publishes to a remote others can see",
        "publish remote irreversible",
        r"git\s+push\b|gh\s+repo\s+create|gh\s+release\s+create|npm\s+publish"
        r"|twine\s+upload|docker\s+push|gh\s+pr\s+create",
    ),
    _p(
        "secret.exposure",
        CRITICAL,
        "reads a credential file into a command, a log or the network",
        "secret credential exfiltration",
        r"(cat|type|get-content|curl|wget|invoke-webrequest)\b[^\n]*"
        r"(\.env\b|key\.txt|id_rsa|credentials\.json|\.pem\b|secrets?\.(json|ya?ml))"
        r"|(api[_-]?key|token|password)\s*=\s*[\"']?[A-Za-z0-9_\-]{16,}",
    ),
    _p(
        "process.force-kill",
        HIGH,
        "kills a process without letting it shut down",
        "process availability",
        r"taskkill\b[^\n]*/f|stop-process\b[^\n]*-force|\bkill\s+-9\b|\bpkill\s+-9\b",
    ),
    _p(
        "system.config",
        CRITICAL,
        "changes system or security configuration",
        "system security config",
        r"\breg\s+(add|delete)\b|\bbcdedit\b|\bnetsh\b|set-executionpolicy"
        r"|\bwsl\s+--unregister\b|\bsc\s+(delete|config)\b|\bufw\s+disable\b"
        r"|set-mppreference\b|add-mppreference\b",
    ),
    _p(
        "package.global-install",
        MEDIUM,
        "installs software for the whole machine",
        "supply-chain install",
        r"npm\s+(i|install)\b[^\n]*\s-g\b|pip\s+install\b(?![^\n]*(-e\s+\.|requirements))"
        r"|winget\s+install|choco\s+install|scoop\s+install",
    ),
    _p(
        "db.drop",
        CRITICAL,
        "drops or truncates stored data",
        "database destructive",
        r"\bdrop\s+(table|database|schema)\b|\btruncate\s+table\b|\bdelete\s+from\b(?![^\n]*\bwhere\b)",
    ),
    _p(
        "remote.pipe-to-shell",
        CRITICAL,
        "runs code fetched from the network without review",
        "supply-chain execution",
        r"(curl|wget|iwr|invoke-webrequest)\b[^\n]*\|\s*(ba)?sh\b"
        r"|(curl|iwr)\b[^\n]*\|\s*(iex|invoke-expression)",
    ),
)


def classify_command(command: str) -> list[Hazard]:
    """Return every hazard class the command falls into, worst first."""
    found: list[Hazard] = []
    for pattern in COMMAND_PATTERNS:
        match = pattern.regex.search(command)
        if match:
            found.append(
                Hazard(
                    id=pattern.id,
                    severity=pattern.severity,
                    summary=pattern.summary,
                    tags=pattern.tags,
                    evidence=match.group(0).strip()[:120],
                )
            )
    return sorted(found, key=lambda h: -_SEVERITY_ORDER[h.severity])


def classify_write(path: str, protected: tuple[str, ...]) -> list[Hazard]:
    """Hazards for a file-writing tool call (Write, Edit, NotebookEdit)."""
    normalised = path.replace("\\", "/").lower()
    for entry in protected:
        needle = entry.replace("\\", "/").lower()
        if normalised.endswith(needle) or f"/{needle}" in normalised:
            return [
                Hazard(
                    id="fs.protected-write",
                    severity=HIGH,
                    summary="writes to a file that configures the machine or holds a secret",
                    tags=("filesystem", "config", "secret"),
                    evidence=entry,
                )
            ]
    return []


def worst(hazards: list[Hazard]) -> str | None:
    if not hazards:
        return None
    return max((h.severity for h in hazards), key=lambda s: _SEVERITY_ORDER[s])


def escalate(severity: str) -> str:
    if severity == MEDIUM:
        return HIGH
    return CRITICAL
