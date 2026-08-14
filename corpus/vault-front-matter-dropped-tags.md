---
id: vault-front-matter-dropped-tags
title: Notes edited in a vault app lost their tags, and retrieval quietly got worse
date: 2026-08-14
severity: medium
tags: parsing front-matter yaml obsidian vault markdown ingestion silent-failure knowledge-base
rule: A parser that reads files written by another tool is tested against that tool's real output, not against the format we would have chosen. When a field cannot be read, that is reported — never treated as absent.
source: local-incident
---

## What happened

Incidents in this corpus are plain markdown with YAML front matter, chosen so the
corpus could live inside a knowledge base the author already keeps rather than in
a folder only this tool reads. The front-matter reader, however, was written
against the format this project emits: `key: value`, one line, values separated by
spaces.

Note-taking applications do not write that. They write list values two ways, and
both were mishandled. The inline form, `tags: [delete, uninstall]`, produced the
tags `[delete` and `uninstall]` — brackets welded to the words. The block form,

    tags:
      - delete
      - uninstall

produced no tags at all, because a `- delete` line contains no colon and was
skipped by a filter looking for `key: value`.

The block form is the damaging one, and it is the form these apps write by
default. The document still parsed. The incident still loaded. The title, rule and
body were all intact, so every visible check passed. What was gone was the curated
vocabulary — the one field written by hand specifically so the incident could be
found — which meant the incident was retrievable only by whatever words happened
to survive in its prose. Ranking degraded silently, in the direction of not
retrieving things.

The reader now accepts all three shapes and strips brackets, quotes and leading
`#` from tag values. Five tests cover the formats, including the legacy one, so a
future rewrite cannot quietly drop a shape again.

## Why the rule

The failure mode is specific to reading someone else's files: a tolerant parser
that silently discards what it does not understand looks identical to a parser
that works. Nothing throws, because nothing is technically missing — the field was
simply never seen.

It matters most for exactly the design that makes this project worth using: if the
corpus is supposed to live where the author already writes, then the author's
editor, not this project, defines the format that has to be read. Every field that
tool can write is a field that must round-trip, and any field that cannot be read
has to be loud about it, because a knowledge base that degrades in silence still
answers — just worse, and with no way to tell.
