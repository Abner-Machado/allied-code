---
id: write-followed-a-symlink
title: A write followed a symlink and overwrote a protected file
date: 2026-02-28
severity: high
tags: symlink protected-file path traversal canonical resolve secret filesystem
rule: Resolve the canonical path before authorising a write. Never trust the path as given.
source: illustrative
---

## What happened

An agent was told to write a temporary report to `./tmp/report.json`. The path looked
harmless and inside the workspace, so the guard checked the `./tmp/` prefix and
allowed it. What the guard did not see: `./tmp/` was a symlink to
`/etc/app/secrets/`, which held API keys and TLS certificates. The write replaced
`secrets.yaml` with invalid JSON and took signature validation down for every
downstream service. It was noticed thirty minutes later, when deployments started
failing in cascade.

## Why the rule

The filesystem lies. Symlinks, bind mounts, Windows junction points and hardlinks all
separate the logical path from the physical target. The cost is resolving every path
to its real target before checking policy: one more system call per operation, a
TOCTOU race to think about, and awkward behaviour on remote filesystems. Without
canonical resolution, any link is a bypass.
