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
import shutil
import sys
import time
from collections import Counter
from pathlib import Path

DEFAULT_SETTINGS = Path.home() / ".claude" / "settings.json"

from . import __version__
from .config import Config
from .corpus import load, search
from .decide import DENY, evaluate
from .ledger import build, read, redact
from .outcome import Verdict, noise, verdict

_SLUG = re.compile(r"[^a-z0-9]+")


def _fmt_hit(hit) -> str:
    incident = hit.incident
    head = f"  {hit.score:>5.2f}  {incident.id}  ({incident.severity}, {incident.date or 'undated'})"
    rule = f"         rule: {incident.rule}" if incident.rule else ""
    return "\n".join(part for part in (head, rule) if part)


def cmd_check(args, config: Config) -> int:
    tool = args.tool
    if getattr(args, "agent", None):
        config.agent = args.agent
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
    if config.delegated:
        print(f"agent     {config.agent}  (strict: floor raised one level)")
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


def _decisions(rows: list[dict]) -> list[dict]:
    """Only the decision receipts.

    The ledger carries outcome lines too since the guard started recording
    whether a questioned call actually ran. Rows written before that field
    existed have no `kind` and are decisions.
    """
    return [r for r in rows if r.get("kind", "decision") == "decision"]


def cmd_ledger(args, config: Config) -> int:
    rows = _decisions(read(config.ledger_path))[-args.last :] if args.last else _decisions(read(config.ledger_path))
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
    all_rows = read(config.ledger_path)
    rows = _decisions(all_rows)
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
    result = verdict(all_rows)
    if cited:
        print("most cited incidents")
        for name, count in cited.most_common(5):
            tally = result.incidents.get(name)
            fate = ""
            if result.wired and tally is not None:
                fate = f"   stopped {tally.stopped}  overruled {tally.proceeded}"
            print(f"  {count:>4}  {name}{fate}")
    unused = [i.id for i in load(config.corpus_dir) if i.id not in cited]
    if unused:
        print(f"never cited   {', '.join(unused)}")

    _print_verdict(result)
    return 0


def _print_verdict(result: Verdict) -> None:
    """How often the person being protected agreed with the guard.

    Every other number here is the guard grading its own homework: how fast it
    was, how often it fired, what it cited. This is the only one measured against
    somebody else's behaviour, which is why it is the one worth reading.
    """
    if not result.wired:
        print("\nverdict       no outcome receipts yet — PostToolUse is not wired.")
        print("              guard install --write   (then work for a week)")
        return

    print(f"\nverdict       {result.questioned} call(s) questioned")
    agreement = result.agreement
    if agreement is None:
        print("              nothing settled yet")
    else:
        print(f"  stopped     {result.stopped:>4}  {agreement * 100:.0f}%  you agreed with the guard")
        print(f"  overruled   {result.proceeded:>4}  {(1 - agreement) * 100:.0f}%  you ran it anyway")
    if result.pending:
        print(f"  pending     {result.pending:>4}        too recent to call")

    loud = noise(result.incidents)
    if loud:
        print("noise         cited repeatedly, never once stopped you:")
        for name in loud:
            print(f"  {name}")
        print("              that incident is firing where it does not belong.")
        print("              edit the file or delete it — the guard will not do it for you.")


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


def _commands(python: str | None) -> tuple[str, str, str]:
    """The three hook commands, preferring the installed entry points.

    After `pip install` the console scripts are on PATH and the settings file can
    stay free of interpreter paths. Running straight from a checkout there are no
    scripts, so fall back to the interpreter — with the absolute path, because a
    hook inherits neither the shell nor the working directory it was written in.
    """
    if python is None and shutil.which("guard-hook") and shutil.which("guard-inject"):
        return "guard-hook", "guard-inject", "guard-outcome"
    interpreter = python or sys.executable
    return (
        f'"{interpreter}" -m guard.hook',
        f'"{interpreter}" -m guard.inject',
        f'"{interpreter}" -m guard.outcome',
    )


def hook_settings(python: str | None = None) -> dict:
    """The three places the corpus is consulted, as an agent settings block.

    They are not redundant. `SessionStart` carries the standing rules, once, for
    free. `UserPromptSubmit` answers "has this gone wrong here before?" while the
    plan is still being written. `PreToolUse` is the last line, and the only one
    that can stop anything — by which point the reasoning that produced the
    command is already spent. Installing only the last one is how a guard ends up
    arguing with a plan instead of shaping it.

    `PostToolUse` is the fourth, and it decides nothing. It records that the call
    actually ran. Paired with the decision that preceded it, the absence of that
    line is the human answering "no" to a question the guard asked — which is the
    only feedback a guard ever gets for free.
    """
    hook_cmd, inject_cmd, outcome_cmd = _commands(python)
    return {
        "hooks": {
            "SessionStart": [{"hooks": [{"type": "command", "command": inject_cmd, "timeout": 10}]}],
            "UserPromptSubmit": [{"hooks": [{"type": "command", "command": inject_cmd, "timeout": 10}]}],
            "PreToolUse": [
                {
                    "matcher": "Bash|PowerShell|Write|Edit|NotebookEdit",
                    "hooks": [{"type": "command", "command": hook_cmd, "timeout": 10}],
                }
            ],
            "PostToolUse": [
                {
                    "matcher": "Bash|PowerShell|Write|Edit|NotebookEdit",
                    "hooks": [{"type": "command", "command": outcome_cmd, "timeout": 10}],
                }
            ],
        }
    }


def _merge_hooks(existing: dict, block: dict) -> dict:
    """Add our hooks to a settings file without taking anything else out.

    Whatever else is in that file was put there by someone who wanted it. The
    corpus already carries the incident where editing a global config to install
    tooling broke the tooling that was working; overwriting a settings file to
    install a guard would be the same mistake with a better excuse.
    """
    merged = json.loads(json.dumps(existing))
    hooks = merged.setdefault("hooks", {})
    for event, entries in block["hooks"].items():
        current = hooks.setdefault(event, [])
        ours = json.dumps(entries[0], sort_keys=True)
        if not any(json.dumps(entry, sort_keys=True) == ours for entry in current):
            current.append(entries[0])
    return merged


def cmd_install(args, config: Config) -> int:
    block = hook_settings(args.python)

    if not args.write:
        print("Add to your agent settings:\n")
        print(json.dumps(block, indent=2))
        print(f"\nSettings file: {args.settings}")
        print("Write it automatically with:  guard install --write")
        print(f"Mode:          {config.mode} (set GUARD_MODE=enforce once the ledger looks right)")
        return 0

    target = Path(args.settings).expanduser()
    existing: dict = {}
    if target.is_file():
        try:
            existing = json.loads(target.read_text(encoding="utf-8") or "{}")
        except json.JSONDecodeError:
            print(f"{target} is not valid JSON. Refusing to touch it — fix or move it first.")
            return 1
        backup = target.with_suffix(f".backup-{time.strftime('%Y%m%d-%H%M%S')}.json")
        backup.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        print(f"backed up  {backup}")

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(_merge_hooks(existing, block), indent=2) + "\n", encoding="utf-8")
    print(f"wrote      {target}")
    print("Restart the agent for the hooks to load, then run: guard doctor")
    return 0


def cmd_doctor(args, config: Config) -> int:
    """Answer the only question that matters after installing: is it actually on."""
    checks: list[tuple[bool, str]] = []

    checks.append((sys.version_info >= (3, 11), f"python {sys.version_info.major}.{sys.version_info.minor} (needs 3.11+)"))

    try:
        from .backends import get_backend_info
        info = get_backend_info()
        label = f"classifier: {info.classifier} ({info.reason})"
    except Exception:
        label = "classifier: python (backend layer unavailable)"
    checks.append((True, label))

    incidents = load(config.corpus_dir)
    checks.append((bool(incidents), f"corpus: {len(incidents)} incident(s) at {config.corpus_dir}"))

    try:
        config.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with config.ledger_path.open("a", encoding="utf-8"):
            pass
        writable = True
    except OSError:
        writable = False
    checks.append((writable, f"ledger writable: {config.ledger_path}"))

    probe = evaluate("Bash", {"command": "rm -rf /tmp/doctor-probe"}, config)
    checks.append((probe.intended == DENY, f"classification: recursive delete -> {probe.intended}"))

    settings = Path(args.settings).expanduser()
    wired = False
    outcome_wired = False
    if settings.is_file():
        try:
            text = settings.read_text(encoding="utf-8")
            wired = "guard.hook" in text or "guard-hook" in text
            outcome_wired = "guard.outcome" in text or "guard-outcome" in text
        except OSError:
            wired = False
    checks.append((wired, f"hook wired in {settings}"))

    for ok, label in checks:
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    failed = [label for ok, label in checks if not ok]
    if failed:
        print(f"\n{len(failed)} check(s) failed. The guard is not protecting anything until they pass.")
        return 1
    if wired and not outcome_wired:
        # Not a failure: the guard protects fine without it. It just stays unable
        # to tell whether any of that protection was ever worth anything.
        print("\nnote: PostToolUse is not wired, so `guard stats` cannot tell you")
        print("      which of its blocks you agreed with. `guard install --write` adds it.")
    print(f"\nAll checks passed. Mode: {config.mode}.")
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
    check.add_argument("--agent", help="evaluate as this agent (raises the floor if it is a strict agent)")
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

    install = sub.add_parser("install", help="print — or write — the hook configuration")
    install.add_argument("--python", help="interpreter to run the hooks with (default: the installed entry points)")
    install.add_argument("--settings", default=str(DEFAULT_SETTINGS), help="agent settings file")
    install.add_argument("--write", action="store_true", help="merge into the settings file, after backing it up")
    install.set_defaults(func=cmd_install)

    doctor = sub.add_parser("doctor", help="check that the install actually works")
    doctor.add_argument("--settings", default=str(DEFAULT_SETTINGS))
    doctor.set_defaults(func=cmd_doctor)
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
