---
id: mcp-call-deleted-data-unchecked
title: An MCP tool call deleted data without passing any check
date: 2026-03-22
severity: critical
tags: mcp tool call delete data verification bypass coverage integration
rule: Every write path — shell, file, MCP, API — goes through the guard. No exceptions.
source: illustrative
---

## What happened

An agent connected to an MCP server that exposed a `delete_database` function for
cleaning test environments. The agent called it believing it was working in an
isolated sandbox; the server pointed at the shared production database. The installed
guard watched shell commands (`rm`, `shred`, `dd`) and direct file writes. The MCP
call went over JSON-RPC and was invisible to all of it: no hook saw it, nothing logged
the destructive intent. The database was gone in three seconds. Restoring it took six
hours and lost every transaction that had not replicated.

## Why the rule

The write surface is not shell plus filesystem. The cost is instrumenting every MCP
integration, every database client and every storage API through the same control
point, which roughly doubles the surface of the guard and depends on what third
parties expose. Without it, each new tool is another back door.
