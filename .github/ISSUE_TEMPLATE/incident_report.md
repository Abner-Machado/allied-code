---
name: Incident report
about: Record an incident that should become a corpus entry
title: "[INCIDENT] "
labels: incident
assignees: ""
---

This template mirrors the corpus format. A maintainer will turn this into a markdown file under `corpus/` with the same front matter.

## Front matter (fill what you can)

```yaml
id: <!-- short kebab-case identifier, e.g., delegated-agent-deleted-tooling -->
title: <!-- one line: what happened -->
date: <!-- YYYY-MM-DD -->
severity: <!-- critical | high | medium | low -->
tags: <!-- space-separated keywords: delete uninstall filesystem delegation subagent destructive -->
rule: <!-- one imperative sentence that becomes the quoted reason when the guard blocks -->
source: <!-- local-incident | upstream-report | cve-YYYY-NNNN | other -->
```

## What happened

Describe the incident in past tense. Concrete, specific, no bullets. What the machine did, what broke, how it was discovered.

## Why the rule

Explain the reasoning behind the rule. Include the **cost of the rule** — every rule charges a price (bottleneck, false positive rate, workflow friction, etc.). The corpus always states this explicitly.
