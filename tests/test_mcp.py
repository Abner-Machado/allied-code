"""Tests for the pure-Python MCP classifier (Defeitos 2 e 4).

These cases come straight from the briefing. Every verdict must come from the
tool name alone, with the server's internal underscores (``claude_ai_Google_Drive``)
left intact by splitting on the double underscore.
"""

from __future__ import annotations

import unittest

from guard.mcp_rules import classify_mcp
from guard.backends import classify_mcp as backend_classify_mcp


def _ids(hazards):
    return [h.id for h in hazards]


def _sev(hazards, hazard_id):
    for h in hazards:
        if h.id == hazard_id:
            return h.severity
    return None


class TestMcpClassification(unittest.TestCase):
    def test_delete_is_critical(self):
        h = classify_mcp("mcp__claude_ai_Google_Drive__delete_file", {})
        self.assertIn("mcp.destructive", _ids(h))
        self.assertEqual(_sev(h, "mcp.destructive"), "critical")

    def test_trash_is_high_not_critical(self):
        h = classify_mcp("mcp__claude_ai_Google_Drive__trash_file", {})
        self.assertIn("mcp.destructive", _ids(h))
        self.assertEqual(_sev(h, "mcp.destructive"), "high")

    def test_send_is_outward_high(self):
        h = classify_mcp("mcp__claude_ai_Gmail__send_message", {})
        self.assertIn("mcp.outward", _ids(h))
        self.assertEqual(_sev(h, "mcp.outward"), "high")

    def test_readonly_is_empty(self):
        self.assertEqual(classify_mcp("mcp__claude_ai_Gmail__search_threads", {}), [])

    def test_unknown_verb_is_medium(self):
        h = classify_mcp("mcp__servidor__frobnicate", {})
        self.assertIn("mcp.unknown-verb", _ids(h))
        self.assertEqual(_sev(h, "mcp.unknown-verb"), "medium")

    def test_verb_at_end_is_caught(self):
        h = classify_mcp("mcp__x__ads_catalog_delete", {})
        self.assertIn("mcp.destructive", _ids(h))
        self.assertEqual(_sev(h, "mcp.destructive"), "critical")

    def test_malformed_name_does_not_raise(self):
        try:
            result = classify_mcp("mcp__so_uma_parte", {})
        except Exception as exc:  # pragma: no cover
            self.fail(f"malformed MCP name raised {exc!r}")
        self.assertIsInstance(result, list)

    def test_backend_exposes_same_signature(self):
        # Defeito 4: both sides use (tool_name, tool_input).
        h = backend_classify_mcp("mcp__claude_ai_Gmail__send_message", {})
        self.assertIn("mcp.outward", _ids(h))


if __name__ == "__main__":
    unittest.main()
