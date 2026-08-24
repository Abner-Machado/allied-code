"""Tests for secret redaction and safe MCP target extraction (Defeito 1)."""

from __future__ import annotations

import unittest

from guard.decide import redact, action_text

_LONG = "x" * 200

# Assembled at run time rather than written out. A literal in PAT shape is enough
# to trip a secret scanner on push, and a test fixture is not worth that argument.
_SECRET_TOKEN = "ghp_" + "a" * 36
_SECRET_LINE = f'{{"token": "{_SECRET_TOKEN}"}}'
_AUTH_LINE = "Authorization: Bearer xyzabc1234567890supersecretvalue"


class TestRedaction(unittest.TestCase):
    def test_ghp_token_never_appears_in_clear(self):
        out = redact(_SECRET_LINE)
        self.assertNotIn("ghp_", out)
        self.assertNotIn(_SECRET_TOKEN, out)

    def test_authorization_bearer_masked(self):
        out = redact(_AUTH_LINE)
        self.assertNotIn("xyzabc1234567890supersecretvalue", out)

    def test_clean_text_passes_untouched(self):
        text = "delete the file at /home/user/docs/report.txt and list the threads"
        self.assertEqual(redact(text), text)

    def test_extracted_target_never_exceeds_80(self):
        for key in ("id", "path", "file_path", "file_id", "url", "message_id", "thread_id"):
            with self.subTest(key=key):
                out = action_text("mcp__srv__get_file", {key: _LONG})
                self.assertLessEqual(len(out), 80)

    def test_mcp_does_not_leak_secret_argument(self):
        # A token passed as an argument must never reach the action text.
        out = action_text("mcp__srv__do_thing", {"token": _SECRET_TOKEN, "id": "abc123"})
        self.assertNotIn("ghp_", out)
        self.assertNotIn(_SECRET_TOKEN, out)
        self.assertEqual(out, "abc123")


if __name__ == "__main__":
    unittest.main()
