---
id: retrieval-failed-silently
title: Precedent search returned nothing and the guard relaxed on its own
date: 2026-06-03
severity: critical
tags: retrieval search precedent corpus coverage empty silent failure escalation language
rule: An empty search is a failure, not a permission. Raise the severity when the corpus has nothing to say.
source: illustrative
---

## What happened

An agent proposed an unusual sequence: mount a disk image, copy SSH keys, restart a
service. The query reached the guard in one language; the corpus was written in
another. Retrieval returned zero matches — no error, no warning, just an empty list.
The guard read "no precedent" as "unknown risk, therefore low risk", dropped the
severity from high to medium, and let the sequence through without a human. The
pattern was a documented exfiltration shape. It was documented in the language
nobody had queried in. The leak surfaced days later during a routine audit.

## Why the rule

Absence of evidence is not evidence of absence. The cost of the rule is that every
empty search becomes a coverage failure: the guard escalates, asks for a human, and
records a gap in the corpus — more prompts, more noise, and standing pressure to
keep the corpus in the language the work is done in. Without that, a retrieval
failure is a security failure nobody is told about.
