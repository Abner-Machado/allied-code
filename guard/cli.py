"""Command line: inspect the guard, brief an agent, grow the corpus.

`check` and `brief` are two readings of the same corpus. `check` asks "should
this run?" one command at a time. `brief` asks "what should whoever is about to
work on this already know?" — the same evidence, delivered before the work
instead of during it. That second reading is what makes the corpus worth keeping
once the blocking part becomes boring.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from collections import Counter
from pathlib import Path

from . import __version__
from .config import Config
from .corpus import load, search
from .decide import DENY, evaluate
from .ledger import build, read, redact

_SLUG = re.compile(r"[^a-z0-9]+")


def _fmt_hit(hit) -> str:
    incident = hit.incident
    head = f"  {hit.score:>5.2f}  {incident.id}  ({incident.severity}, {incident.date or 'undated'})"
    rule = f"         rule: {incident.rule}" if incident.rule else ""
    return "\n".join(part for part in (head, rule) if part)


def cmd_check(args, config: Config) -> int:
    tool = args.tool
    tool_input = {"command": args.action} if tool not in ("Write", "Edit") else {"file_path": args.action}
    started = time.perf_counter()
    decision = evaluate(tool, tool_input, config)

    if args.json:
        receipt = build(tool, args.action, decision, config.mode, started)
        print(receipt.to_json())
        return 1 if decision.blocked else 0

    print(f"action    {redact(args.action)}")
    print(f"tool      {tool}")
    print(f"decision  {decision.decision.upper()}  (would be {decision.intended.upper()} when enforcing)")
    print(f"severity  {decision.severity or '-'}")
    if decision.hazards:
        print("hazards")
        for hazard in decision.hazards:
            print(f"  {hazard.severity:<8} {hazard.id:<26} matched: {hazard.evidence}")
    print("evidence" if decision.evidence else "evidence  none above threshold")
    for hit in decision.evidence:
        print(_fmt_hit(hit))
    print(f"elapsed   {(time.perf_counter() - started) * 1000:.1f} ms")
    return 1 if decision.blocked else 0


def cmd_brief(args, config: Config) -> int:
    """Pre-flight briefing for whoever — or whatever — is about to do the work."""
    hits = search(config.corpus_dir, args.task, limit=args.limit, min_score=config.min_score)
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "id": h.incident.id,
                        "score": h.score,
                        "severity": h.incident.severity,
                        "rule": h.incident.rule,
                        "title": h.incident.title,
                    }
                    for h in hits
                ],
                ensure_ascii=False,
            )
        )
        return 0

    if not hits:
        print(f"No recorded incident resembles: {args.task}")
        return 0
    print(f"Before starting: {args.task}\n")
    for hit in hits:
        incident = hit.incident
        print(f"- {incident.title} [{incident.id}, {incident.severity}, {incident.date or 'undated'}]")
        if incident.rule:
            print(f"  Rule: {incident.rule}")
    print("\nThese are recorded incidents, not guesses. Source: corpus/")
    return 0


def cmd_ledger(args, config: Config) -> int:
    rows = read(config.ledger_path, limit=args.last)
    if not rows:
        print(f"No receipts yet at {config.ledger_path}")
        return 0
    for row in rows:
        marker = {"deny": "BLOCK", "ask": "ASK  ", "allow": "ALLOW", "defer": "     "}.get(row["decision"], "     ")
        print(f"{row['ts']}  {marker}  {row['tool']:<10} {row['action'][:80]}")
        if args.verbose:
            print(f"    {row['reason']}")
    return 0


def cmd_stats(args, config: Config) -> int:
    rows = read(config.ledger_path)
    if not rows:
        print("No receipts yet.")
        return 0
    decisions = Counter(r["decision"] for r in rows)
    hazards = Counter(h for r in rows for h in r.get("hazards", []))
    cited = Counter(e["id"] for r in rows for e in r.get("evidence", []))
    latency = sorted(r.get("latency_ms", 0) for r in rows)

    print(f"receipts      {len(rows)}")
    print(f"decisions     {dict(decisions)}")
    print(f"latency p50   {latency[len(latency) // 2]:.1f} ms")
    print(f"latency p95   {latency[int(len(latency) * 0.95) - 1]:.1f} ms")
    if hazards:
        print("top hazards")
        for name, count in hazards.most_common(5):
            print(f"  {count:>4}  {name}")
    if cited:
        print("most cited incidents")
        for name, count in cited.most_common(5):
            print(f"  {count:>4}  {name}")
    unused = [i.id for i in load(config.corpus_dir) if i.id not in cited]
    if unused:
        print(f"never cited   {', '.join(unused)}")
    return 0


def cmd_learn(args, config: Config) -> int:
    slug = _SLUG.sub("-", args.id.lower()).strip("-")
    path = config.corpus_dir / f"{slug}.md"
    if path.exists() and not args.force:
        print(f"{path} already exists. Use --force to overwrite.")
        return 1
    body = args.what or "(fill in what happened, in one paragraph)"
    content = (
        "---\n"
        f"id: {slug}\n"
        f"title: {args.title}\n"
        f"date: {args.date or time.strftime('%Y-%m-%d')}\n"
        f"severity: {args.severity}\n"
        f"tags: {' '.join(args.tags)}\n"
        f"rule: {args.rule}\n"
        f"source: {args.source}\n"
        "---\n\n"
        "## What happened\n\n"
        f"{body}\n\n"
        "## Why the rule\n\n"
        "(what the rule buys, and what it costs)\n"
    )
    config.corpus_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"wrote {path}")
    return 0


def cmd_install(args, config: Config) -> int:
    root = Path(__file__).resolve().parent.parent
    command = f'"{args.python}" -m guard.hook'
    snippet = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash|PowerShell|Write|Edit|NotebookEdit",
                    "hooks": [{"type": "command", "command": command, "timeout": 10}],
                }
            ]
        }
    }
    print("Add to your agent settings (PYTHONPATH must reach this checkout):\n")
    print(json.dumps(snippet, indent=2))
    print(f"\nCheckout: {root}")
    print(f"Mode:     {config.mode} (set GUARD_MODE=enforce once the ledger looks right)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guard", description="Pre-execution guard backed by recorded incidents.")
    parser.add_argument("--version", action="version", version=f"ops-guard {__version__}")
    parser.add_argument("--corpus", type=Path, help="override corpus directory")
    parser.add_argument("--mode", choices=("observe", "enforce"), help="override mode")
    sub = parser.add_subparsers(dest="cmd", required=True)

    check = sub.add_parser("check", help="evaluate one action without running it")
    check.add_argument("action")
    check.add_argument("--tool", default="Bash")
    check.add_argument("--json", action="store_true")
    check.set_defaults(func=cmd_check)

    brief = sub.add_parser("brief", help="what to know before starting a task")
    brief.add_argument("task")
    brief.add_argument("--limit", type=int, default=5)
    brief.add_argument("--json", action="store_true")
    brief.set_defaults(func=cmd_brief)

    ledger = sub.add_parser("ledger", help="show receipts")
    ledger.add_argument("--last", type=int, default=20)
    ledger.add_argument("--verbose", "-v", action="store_true")
    ledger.set_defaults(func=cmd_ledger)

    stats = sub.add_parser("stats", help="summarise the ledger")
    stats.set_defaults(func=cmd_stats)

    learn = sub.add_parser("learn", help="record a new incident")
    learn.add_argument("--id", required=True)
    learn.add_argument("--title", required=True)
    learn.add_argument("--rule", required=True)
    learn.add_argument("--severity", default="high", choices=("medium", "high", "critical"))
    learn.add_argument("--tags", nargs="*", default=[])
    learn.add_argument("--what", help="one paragraph on what happened")
    learn.add_argument("--date")
    learn.add_argument("--source", default="local-incident")
    learn.add_argument("--force", action="store_true")
    learn.set_defaults(func=cmd_learn)

    install = sub.add_parser("install", help="print the hook configuration snippet")
    install.add_argument("--python", default="python")
    install.set_defaults(func=cmd_install)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = Config.load()
    if args.corpus:
        config.corpus_dir = args.corpus
    if args.mode:
        config.mode = args.mode
    return args.func(args, config)


if __name__ == "__main__":
    raise SystemExit(main())
