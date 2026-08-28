"""The outcome loop: does the guard learn what the human answered?

The load-bearing claim is that a decision receipt and the outcome line written
after the tool ran can be paired without the runtime handing us a shared id. If
that pairing is wrong, every number the verdict prints is wrong in the direction
that flatters the guard, which is the worst direction available.
"""

from __future__ import annotations

import json
import os
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from guard import hook, outcome
from guard.config import Config
from guard.decide import action_text, evaluate
from guard.ledger import append, build, read

CORPUS = Path(__file__).resolve().parent.parent / "corpus"


def _old(seconds: int = 3600) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(time.time() - seconds))


def _decision(key, ts, decision="ask", evidence=(), hazards=(), call_id=""):
    return {
        "ts": ts,
        "kind": "decision",
        "key": key,
        "tool": "Bash",
        "decision": decision,
        "evidence": [{"id": e, "score": 0.9} for e in evidence],
        "hazards": list(hazards),
        "tool_use_id": call_id,
    }


def _outcome(key, call_id=""):
    return {
        "ts": _old(60),
        "kind": "outcome",
        "key": key,
        "tool": "Bash",
        "outcome": "executed",
        "tool_use_id": call_id,
    }


class TestPairing(unittest.TestCase):
    def test_a_questioned_call_that_never_ran_counts_as_stopped(self):
        result = outcome.verdict([_decision("k1", _old())])
        self.assertEqual((result.questioned, result.stopped, result.proceeded), (1, 1, 0))

    def test_a_questioned_call_that_ran_counts_as_overruled(self):
        result = outcome.verdict([_decision("k1", _old()), _outcome("k1")])
        self.assertEqual((result.stopped, result.proceeded), (0, 1))

    def test_a_fresh_decision_is_pending_not_stopped(self):
        """The human may still be looking at the prompt. Counting that as a win
        for the guard is the guard grading its own homework."""
        now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        result = outcome.verdict([_decision("k1", now)])
        self.assertEqual((result.pending, result.stopped), (1, 0))

    def test_identical_commands_pair_one_for_one(self):
        rows = [_decision("k1", _old()), _decision("k1", _old()), _outcome("k1")]
        result = outcome.verdict(rows)
        self.assertEqual((result.proceeded, result.stopped), (1, 1))

    def test_tool_use_id_pairs_the_exact_call(self):
        rows = [
            _decision("k1", _old(), call_id="u1"),
            _decision("k1", _old(), call_id="u2"),
            _outcome("k1", call_id="u2"),
        ]
        result = outcome.verdict(rows)
        self.assertEqual((result.proceeded, result.stopped), (1, 1))

    def test_deferred_calls_are_not_counted(self):
        """The guard said nothing, so there is no answer to learn."""
        result = outcome.verdict([_decision("k1", _old(), decision="defer"), _outcome("k1")])
        self.assertEqual(result.questioned, 0)

    def test_receipts_written_before_the_outcome_loop_still_parse(self):
        legacy = {"ts": _old(), "tool": "Bash", "decision": "ask", "evidence": [], "hazards": []}
        result = outcome.verdict([legacy])
        self.assertEqual(result.questioned, 1)
        self.assertFalse(result.wired)


class TestAttribution(unittest.TestCase):
    def test_an_incident_cited_and_always_overruled_is_noise(self):
        rows = []
        for n in range(3):
            rows.append(_decision("k", _old(), evidence=("loud-incident",), call_id=f"u{n}"))
            rows.append(_outcome("k", call_id=f"u{n}"))
        result = outcome.verdict(rows)
        self.assertEqual(outcome.noise(result.incidents), ["loud-incident"])

    def test_an_incident_that_stopped_something_is_never_noise(self):
        rows = [
            _decision("k1", _old(), evidence=("useful",), call_id="a"),
            _outcome("k1", call_id="a"),
            _decision("k2", _old(), evidence=("useful",)),
        ]
        result = outcome.verdict(rows)
        self.assertEqual(outcome.noise(result.incidents, minimum=1), [])


class TestKeyParity(unittest.TestCase):
    """The pre and post hooks must derive the same key from the same call.

    They redact independently and never see each other's output, so this is the
    one place where a silent divergence would make every verdict meaningless.
    """

    def test_pre_and_post_agree_on_the_key(self):
        with TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            payload = {
                "tool_name": "Bash",
                "tool_input": {"command": "git push --force origin main"},
                "session_id": "s1",
                "tool_use_id": "u1",
            }
            config = Config(ledger_path=ledger, corpus_dir=CORPUS)
            started = time.perf_counter()
            decision = evaluate("Bash", payload["tool_input"], config)
            append(
                ledger,
                build("Bash", action_text("Bash", payload["tool_input"]), decision, config.mode, started, payload),
            )
            outcome.append_line(ledger, outcome.record(payload))

            rows = read(ledger)
            self.assertEqual(rows[0]["key"], rows[1]["key"])
            later = datetime.now().astimezone() + timedelta(hours=1)
            self.assertEqual(outcome.verdict(rows, now=later).proceeded, 1)

    def test_a_secret_in_the_command_never_reaches_the_outcome_line(self):
        row = outcome.record(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "curl -H 'authorization: Bearer sk-abcdefghijklmnop12345'"},
                "session_id": "s1",
            }
        )
        self.assertNotIn("abcdefghijklmnop", json.dumps(row))


class TestFailureIsNotRefusal(unittest.TestCase):
    def test_a_tool_that_errored_still_counts_as_run(self):
        row = outcome.record(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "ls /nope"},
                "tool_response": {"error": "no such file"},
            }
        )
        self.assertEqual(row["outcome"], outcome.FAILED)
        paired = outcome.verdict([_decision("k", _old()), dict(row, key="k")])
        self.assertEqual(paired.proceeded, 1)


class TestNeverTakesTheSessionDown(unittest.TestCase):
    def test_garbage_stdin_never_raises(self):
        for raw in ("", "not json", "[]", '{"tool_input": null}'):
            with self.subTest(raw=raw):
                self.assertIsInstance(outcome.run(raw), dict)


class TestDelegatedFloor(unittest.TestCase):
    def _config(self, agent):
        return Config(corpus_dir=CORPUS, agent=agent, strict_agents=("produtor-*", "hermes/*"))

    def test_a_delegated_agent_is_held_one_level_higher(self):
        orchestrator = evaluate("Bash", {"command": "npm install -g typescript"}, self._config(""))
        producer = evaluate("Bash", {"command": "npm install -g typescript"}, self._config("produtor-haiku"))
        self.assertEqual(orchestrator.severity, "medium")
        self.assertEqual(producer.severity, "high")

    def test_an_agent_outside_the_list_is_unchanged(self):
        plain = evaluate("Bash", {"command": "npm install -g typescript"}, self._config("orchestrator"))
        self.assertEqual(plain.severity, "medium")

    def test_it_only_ever_raises(self):
        """A harmless call stays harmless. The floor is not an excuse to invent one."""
        harmless = evaluate("Bash", {"command": "ls -la"}, self._config("produtor-haiku"))
        self.assertIsNone(harmless.severity)
        self.assertEqual(harmless.decision, "defer")

    def test_the_reason_names_the_agent_it_was_raised_for(self):
        producer = evaluate("Bash", {"command": "npm install -g typescript"}, self._config("produtor-haiku"))
        self.assertIn("produtor-haiku", producer.reason)

    def test_the_hook_reads_the_agent_off_the_payload(self):
        with TemporaryDirectory() as tmp:
            os.environ["GUARD_LEDGER"] = str(Path(tmp) / "l.jsonl")
            os.environ["GUARD_STRICT_AGENTS"] = "produtor-*"
            try:
                out = hook.run(
                    json.dumps(
                        {
                            "tool_name": "Bash",
                            "tool_input": {"command": "npm install -g typescript"},
                            "agent": "produtor-haiku",
                        }
                    )
                )
            finally:
                del os.environ["GUARD_LEDGER"]
                del os.environ["GUARD_STRICT_AGENTS"]
        reason = out["hookSpecificOutput"].get("permissionDecisionReason", "")
        self.assertIn("produtor-haiku", reason)


if __name__ == "__main__":
    unittest.main()
