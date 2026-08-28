---
id: quoted-command-blocked-by-mistake
title: A destructive command inside quotes was blocked as if it were real
date: 2026-04-15
severity: medium
tags: quotes false-positive echo print destructive text segmentation trust
rule: A guard distinguishes an executed command from printed text. Text inside quotes is never an action.
source: illustrative
---

## What happened

An agent tried to print a diagnostic message containing `rm -rf /` inside double
quotes, to show the user what must never be run. The guard matched the forbidden
string inside the argument and blocked the call as a real deletion attempt. The
agent stalled in the middle of an onboarding flow; the user waited ten minutes,
investigated, and found a false positive. Trust went first: the team started
approving everything on reflex so work would not stall, which cancelled out the
protection the guard was there to give.

## Why the rule

A guard that cannot tell code from data creates more risk than no guard at all. The
cost is accepting that suspicious strings inside printing, logging and documentation
pass without a block, which means reading context — is this being executed, or only
displayed? Without that distinction the system trains the human to ignore it, and
"approve everything" becomes the default.
