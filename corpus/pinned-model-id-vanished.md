---
id: pinned-model-id-vanished
title: Pinned model identifiers disappeared from the provider catalog
date: 2026-08-07
severity: medium
tags: model catalog route fallback provider 404 config drift
rule: Model identifiers are not stable. Build the fallback chain from the live catalog at run time, and fail loudly when a pinned identifier no longer exists.
source: local-incident
---

## What happened

Two independent tools on the same machine pinned model identifiers in code and
in a static catalog file. Checked against the provider's live list on 7 August
2026: the default model of the first tool no longer existed, and neither did one
of its two fallbacks — leaving a three-entry chain with one working entry. The
second tool shipped a catalog of 38 identifiers, of which 4 were gone; its user
interface still offered all 38.

Neither tool reported anything. The first silently fell through to whichever
entry still answered; the second only failed when a user picked a dead option.

## Why the rule

A pinned identifier is a cache with no invalidation. Provider catalogs rotate
faster than the code that references them, so the failure is not "if" but "when",
and it degrades quietly: a fallback chain that silently shrinks looks identical
to one that works, right up to the day the last entry rotates out too.

This incident does not block anything on its own. It is here because the same
corpus that blocks is also what a briefing reads before touching routing code.
