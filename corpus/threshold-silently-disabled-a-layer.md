---
id: threshold-silently-disabled-a-layer
title: A threshold copied from one context switched a safety layer off without failing
date: 2026-08-14
severity: high
tags: threshold retrieval calibration silent-failure safety-layer configuration tuning score
rule: A control with a tunable threshold ships with the measurement that justifies the number, and a test that proves it fires on a real input. A threshold with no measurement behind it is an off switch wearing a setting's clothes.
source: local-incident
---

## What happened

A second retrieval layer was added to this project so that recorded incidents
would reach the model when a task is described, not only when a dangerous command
is already written. Its relevance floor was set to 0.45 — higher than the 0.35 the
guard itself uses, on the reasoning that text written into a prompt should be held
to a stricter standard than text shown in a block.

The number was wrong, and wrong in the direction that produces no symptom.
Retrieval scores here are normalised by the weight of the whole query, so they
only compare between queries of similar length. Measured against this corpus, one
intent — force-pushing a tidied history — scores 0.446 as a command, 0.398 as a
short sentence, and 0.219 as the sentence a person actually types. A floor of 0.45
sat above every realistic prompt. The layer was installed, was running, was
consuming a hook slot on every turn, and could never once have fired.

Nothing failed. No error, no empty result anybody would notice, no line in the
ledger saying "considered and rejected". The first evidence was a deliberate test
of the new layer against a realistic prompt, which returned nothing at all.

Lowering the floor to 0.15 made it fire — and immediately made it fire on
"rename a local variable in a test file", which matched three incidents on shared
filler words. The fix that held was two doors instead of one: the score, plus a
requirement that the request use at least one word from the incident's own `tags`
line, which is the part a human curated on purpose.

## Why the rule

A threshold is the cheapest place in a system to hide a total failure. A wrong
limit in a loop crashes; a wrong limit in a filter returns an empty set, which is
indistinguishable from "correctly found nothing" at every layer above it. This one
was defensible in prose, matched the surrounding code's units, and was off by
enough to disable the feature completely.

The generalisation is not about retrieval. Any control whose job is to sometimes
do nothing — a rate limiter, an alert rule, a sampling gate, a filter — can be
switched off by a plausible constant and keep reporting healthy. The only defence
that survives review months later is the measurement pinned next to the number,
and a test that fails when the control stops firing on an input that should trip
it.
