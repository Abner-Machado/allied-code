"""The corpus of incidents: what already went wrong, and the rule it bought us.

One incident per file. The front matter is intentionally small so an incident can
be written by hand in a minute, right after the thing goes wrong, which is the
only moment anybody actually remembers the details.

Retrieval is lexical and dependency-free on purpose. This code runs inside a
pre-execution hook, in front of every tool call, so it has a latency budget of a
few milliseconds and no right to load a model or reach the network.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.-]*")
_FRONT = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.S)
# Words that carry no signal in a corpus that is entirely about running commands.
_STOP = frozenset(
    "the a an and or of to in on for with without it its this that was were is are "
    "be been by as at from into then than so we our us i you your he she they them "
    "not no yes do did does done run ran running command commands file files".split()
)


@dataclass(frozen=True)
class Incident:
    id: str
    title: str
    severity: str
    tags: tuple[str, ...]
    rule: str
    source: str
    date: str
    body: str
    path: Path

    @property
    def tokens(self) -> tuple[str, ...]:
        return tokenize(f"{self.id} {self.title} {' '.join(self.tags)} {self.rule} {self.body}")


@dataclass(frozen=True)
class Hit:
    incident: Incident
    score: float


def tokenize(text: str) -> tuple[str, ...]:
    out: list[str] = []
    for raw in _TOKEN.findall(text.lower()):
        token = raw.strip(".-_")
        if not token or token in _STOP or len(token) == 1:
            continue
        out.append(token)
        # Split dotted identifiers so `git.history-rewrite` also matches `history`.
        for piece in re.split(r"[.\-_]", token):
            if len(piece) > 2 and piece not in _STOP:
                out.append(piece)
    return tuple(out)


def parse(text: str, path: Path) -> Incident | None:
    match = _FRONT.match(text)
    if not match:
        return None
    meta: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" not in line or line.lstrip().startswith("#"):
            continue
        key, _, value = line.partition(":")
        meta[key.strip().lower()] = value.strip().strip('"').strip("'")

    identifier = meta.get("id") or path.stem
    tags = tuple(t for t in re.split(r"[,\s]+", meta.get("tags", "")) if t)
    return Incident(
        id=identifier,
        title=meta.get("title", identifier),
        severity=meta.get("severity", "medium").lower(),
        tags=tags,
        rule=meta.get("rule", ""),
        source=meta.get("source", "unknown"),
        date=meta.get("date", ""),
        body=match.group(2).strip(),
        path=path,
    )


def load(corpus_dir: Path) -> list[Incident]:
    if not corpus_dir.is_dir():
        return []
    incidents = []
    for path in sorted(corpus_dir.glob("*.md")):
        try:
            incident = parse(path.read_text(encoding="utf-8"), path)
        except OSError:
            continue
        if incident is not None:
            incidents.append(incident)
    return incidents


@lru_cache(maxsize=8)
def _index(corpus_dir: Path, stamp: float) -> tuple[tuple[Incident, ...], dict[str, float]]:
    """Incidents plus inverse document frequency. `stamp` busts the cache."""
    incidents = tuple(load(corpus_dir))
    total = len(incidents) or 1
    seen: dict[str, int] = {}
    for incident in incidents:
        for token in set(incident.tokens):
            seen[token] = seen.get(token, 0) + 1
    idf = {token: math.log(1 + total / count) for token, count in seen.items()}
    return incidents, idf


def _stamp(corpus_dir: Path) -> float:
    if not corpus_dir.is_dir():
        return 0.0
    try:
        return max((p.stat().st_mtime for p in corpus_dir.glob("*.md")), default=0.0)
    except OSError:
        return 0.0


def search(corpus_dir: Path, query: str, limit: int = 3, min_score: float = 0.0) -> list[Hit]:
    """Score incidents against a query, normalised so 1.0 is a perfect overlap."""
    incidents, idf = _index(corpus_dir, _stamp(corpus_dir))
    if not incidents:
        return []

    query_tokens = tokenize(query)
    if not query_tokens:
        return []
    weights: dict[str, float] = {}
    for token in query_tokens:
        weights[token] = weights.get(token, 0.0) + idf.get(token, math.log(2))
    ceiling = sum(weights.values()) or 1.0

    hits: list[Hit] = []
    for incident in incidents:
        counts: dict[str, int] = {}
        for token in incident.tokens:
            counts[token] = counts.get(token, 0) + 1
        score = 0.0
        for token, weight in weights.items():
            tf = counts.get(token, 0)
            if tf:
                # Saturating term frequency: the fifth mention adds almost nothing.
                score += weight * (tf / (tf + 1.5))
        normalised = score / ceiling
        if normalised >= min_score:
            hits.append(Hit(incident, round(normalised, 4)))

    hits.sort(key=lambda h: (-h.score, h.incident.id))
    return hits[:limit]
