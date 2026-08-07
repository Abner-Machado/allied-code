---
id: config-edit-broke-working-tooling
title: Editing shared configuration broke tooling that already worked
date: 2026-07-05
severity: high
tags: config settings hook install global machine-wide reversible
rule: Prefer the change that is isolated and reversible. Machine-wide configuration is edited only when a scoped alternative does not exist, and the previous content is kept.
source: local-incident
---

## What happened

Automating a behaviour by editing a shared settings file looked cheaper than
building an isolated equivalent. It broke unrelated tooling that read the same
file, and the breakage appeared later, in a different task, with no obvious link
back to the edit that caused it. The recovery cost more than building the
isolated version would have.

## Why the rule

Shared configuration is a global variable with a filesystem path. Every consumer
of it is a caller you did not write and cannot see. The scoped alternative is
usually a little more work up front and takes the blast radius from "everything
on this machine" to "this one thing", which is the entire difference between an
experiment and an outage.
