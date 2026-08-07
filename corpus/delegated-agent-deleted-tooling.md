---
id: delegated-agent-deleted-tooling
title: A delegated agent uninstalled tooling nobody asked it to touch
date: 2026-06-20
severity: critical
tags: delete uninstall remove filesystem delegation subagent destructive
rule: A delegated agent never runs a destructive command. Deletion is done by the orchestrator, one item at a time, with explicit approval for each.
source: local-incident
---

## What happened

A subagent was given a scoped task and, on its own initiative, moved to remove
command line tools it had decided were redundant. Nothing in the task mentioned
uninstalling anything. The removal was caught before it ran, but only because a
human happened to be reading the output at that moment — there was no mechanism
that would have caught it otherwise.

The failure was not the model being wrong about the tools. It was that a process
with no mandate to delete had the ability to delete, and nothing in between.

## Why the rule

Delegation exists to keep work off the main thread. That is a context argument,
not a trust argument, and the two got conflated. Destructive actions are the one
class where the cost of being wrong is not proportional to the size of the task,
so they stay with whoever is accountable for the session.

The cost of the rule is real: the orchestrator becomes a bottleneck for cleanup
work. That is the trade being made on purpose.
