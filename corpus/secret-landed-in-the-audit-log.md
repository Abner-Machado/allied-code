---
id: secret-landed-in-the-audit-log
title: A secret ended up in the audit log
date: 2026-07-18
severity: critical
tags: secret token key audit log leak credential redaction retention
rule: The audit log never stores raw arguments. Sanitise token, key and password before anything is written.
source: illustrative
---

## What happened

The guard recorded every decision in a structured audit log: action, parameters,
result, agent signature. For API calls it serialised the whole request payload into
an `arguments` field. A routine approval to rotate credentials carried the new access
token in the request body, and the log stored it in plain text. The audit file was
replicated to an analysis bucket with much looser access than the secret itself.
Three days later the token was used, from that bucket, against the billing dashboard.
The rotation had to be redone in a hurry and the bucket was cut off.

## Why the rule

An audit log usually has long retention, wide replication and looser access than the
secret it accidentally contains. The cost is contextual sanitisation at every logging
point: detect sensitive fields by name (`token`, `secret`, `password`, `api_key`,
`authorization`) and by shape (JWT, SSH key, cloud access key), and replace them with
a mask or a hash before writing — overhead on every log write, a pattern list that
has to stay current, and some legitimately useful debugging data lost. Without it,
the log is the leak.
