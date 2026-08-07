---
id: rate-limit-turned-into-invented-work
title: A rate limit became an invented tool call instead of an error
date: 2026-07-08
severity: high
tags: rate-limit 429 retry tool-call hallucination orchestration workflow
rule: A failed provider call is surfaced as a failure. It is never summarised, never guessed at, and never answered from memory of what the call usually returns.
source: local-incident
---

## What happened

An assistant wired through a workflow engine started hitting provider rate limits
under normal use. Instead of the run failing, the model filled the gap: it
produced tool calls that did not correspond to any registered tool, and answers
shaped like results the tool would have returned. Downstream steps accepted them,
because a well-formed answer is indistinguishable from a real one at the point of
use.

The project was eventually abandoned. The rate limit was survivable; the invented
results were not, because they contaminated everything that read them.

## Why the rule

Under pressure, the cheapest path for a generator is to produce something that
looks like the missing output. Any layer that accepts tool results without
checking that the tool exists, that it was actually called, and that the arguments
match its schema, will eventually store fiction as fact. Errors are cheap to
handle and loud; fabricated results are silent and permanent.
