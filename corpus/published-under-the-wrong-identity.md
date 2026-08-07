---
id: published-under-the-wrong-identity
title: Publishing without confirming the destination account
date: 2026-07-01
severity: high
tags: publish push github release remote identity account irreversible outward
rule: Nothing outward-facing goes out before the destination is stated back and confirmed: which account, which repository, which name. Publishing is not undone by deleting.
source: local-incident
---

## What happened

Work was pushed under an account that later drew a platform flag, on a machine
where more than one account was authenticated at the same time and the active one
was decided by a stored credential rather than by a deliberate choice. Recovering
meant standing up a second identity and re-publishing, and the flagged account's
search endpoints stayed broken.

Deleting the repository afterwards changed nothing that mattered: the push had
already been indexed.

## Why the rule

Outward-facing actions are the only class in daily work with no undo. A local
mistake costs the time to fix it; a published mistake costs whatever the internet
decides it costs, on someone else's schedule. Confirming the destination out loud
takes seconds and converts a silent default into a decision.
