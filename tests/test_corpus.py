"""Tests for the incident corpus: tokenizing, front matter and retrieval.

The corpus is the one place the guard learns from. If the tokenizer drops a word,
or the front matter parser loses the tags an incident was filed under, retrieval
degrades silently and nobody is told. These tests pin the three parts that fail
quietly: `tokenize`, the front matter shapes an editor actually writes, and the
scoring/ordering of `search`.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from guard import corpus


class TokenizeTests(unittest.TestCase):
    def test_drops_stopwords_and_single_chars(self):
        toks = corpus.tokenize("We did run the X command on a file")
        # stopwords (we/did/run/the/on/a/command/file) and the 1-char "x" all go.
        self.assertEqual(toks, ())

    def test_lowercases(self):
        self.assertEqual(corpus.tokenize("GitPush"), ("gitpush",))

    def test_splits_dotted_identifier_but_keeps_whole(self):
        toks = corpus.tokenize("git.history-rewrite")
        self.assertIn("git.history-rewrite", toks)
        self.assertIn("history", toks)
        self.assertIn("rewrite", toks)
        # "git" is 3 chars, kept; a 2-char piece would be dropped.
        self.assertIn("git", toks)

    def test_short_pieces_dropped(self):
        # "a.b" -> whole token survives the >1-char rule, pieces "a"/"b" are <3 chars.
        toks = corpus.tokenize("xy.ab")
        self.assertNotIn("ab", toks)
        self.assertNotIn("xy", toks)


class FrontMatterTests(unittest.TestCase):
    def parse(self, text: str) -> corpus.Incident:
        inc = corpus.parse(text, Path("mem.md"))
        assert inc is not None
        return inc

    def test_inline_tags_lose_brackets(self):
        inc = self.parse("---\ntitle: T\ntags: [git, rm]\n---\nbody\n")
        self.assertEqual(inc.tags, ("git", "rm"))

    def test_block_tags_are_collected(self):
        inc = self.parse("---\ntitle: T\ntags:\n  - git\n  - rm\n---\nbody\n")
        self.assertEqual(inc.tags, ("git", "rm"))

    def test_severity_lowercased_default_medium(self):
        self.assertEqual(self.parse("---\ntitle: T\nseverity: HIGH\n---\nx").severity, "high")
        self.assertEqual(self.parse("---\ntitle: T\n---\nx").severity, "medium")

    def test_id_falls_back_to_stem(self):
        inc = corpus.parse("---\ntitle: T\n---\nbody", Path("incident-07.md"))
        assert inc is not None
        self.assertEqual(inc.id, "incident-07")

    def test_no_front_matter_returns_none(self):
        self.assertIsNone(corpus.parse("just a body, no fence", Path("x.md")))

    def test_body_is_stripped(self):
        self.assertEqual(self.parse("---\ntitle: T\n---\n\n  hello  \n\n").body, "hello")


class SearchTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self._write("a.md", "git-push", ["git"], "pushed to the wrong remote")
        self._write("b.md", "rm-rf", ["disk"], "deleted the build output")
        self.addCleanup(self._tmp.cleanup)

    def _write(self, name, title, tags, body):
        (self.dir / name).write_text(
            f"---\ntitle: {title}\ntags: [{', '.join(tags)}]\n---\n{body}\n",
            encoding="utf-8",
        )

    def test_empty_dir_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(corpus.search(Path(d), "anything"), [])

    def test_blank_query_returns_empty(self):
        self.assertEqual(corpus.search(self.dir, "the a an"), [])

    def test_relevant_incident_ranks_first(self):
        hits = corpus.search(self.dir, "pushed remote git")
        self.assertTrue(hits)
        self.assertEqual(hits[0].incident.title, "git-push")

    def test_score_is_normalised_0_to_1(self):
        for hit in corpus.search(self.dir, "git push remote disk build"):
            self.assertGreaterEqual(hit.score, 0.0)
            self.assertLessEqual(hit.score, 1.0)

    def test_limit_and_min_score(self):
        self.assertEqual(len(corpus.search(self.dir, "git disk", limit=1)), 1)
        self.assertEqual(corpus.search(self.dir, "git", min_score=1.1), [])

    def test_reindex_sees_new_incident(self):
        # The mtime stamp busts the lru_cache; a freshly written incident is found.
        self._write("c.md", "chmod-world", ["perms"], "made a secret world readable")
        hits = corpus.search(self.dir, "secret readable perms")
        self.assertTrue(any(h.incident.title == "chmod-world" for h in hits))


if __name__ == "__main__":
    unittest.main()
