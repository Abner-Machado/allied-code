---
id: truncated-output-treated-as-complete
title: Output hit the token ceiling and the cut was never noticed
date: 2026-06-28
severity: high
tags: truncation output ceiling delegation write incomplete finish-reason
rule: Before treating generated output as complete, check the stop reason. Output that ended because it ran out of room is an error, not a result.
source: local-incident
---

## What happened

A delegated task had to write a large file. The response ended at the output
ceiling, mid-content. Nothing in the pipeline looked at why the response ended,
so the truncated text was written to disk as if it were the whole file. The
damage surfaced later, when the file was used and failed in a way that pointed
at the wrong place entirely.

The same shape shows up in any client that reads only the message body and
ignores the stop reason.

## Why the rule

A truncated response is indistinguishable from a complete one if you only read
the text — it ends in a plausible place, because models end in plausible places.
The stop reason is the only cheap signal that separates them, and it is one field.
Large writes either stay with whoever has the bigger ceiling, or get written
incrementally so a cut is visible as a missing chunk rather than a silent one.
