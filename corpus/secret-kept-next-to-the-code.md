---
id: secret-kept-next-to-the-code
title: An API key stored in plain text beside the script that reads it
date: 2026-06-15
severity: high
tags: secret credential key token env exfiltration read log
rule: A credential file is never read into a command, a log, or a message. Tools take the path or the environment variable, never the value.
source: local-incident
---

## What happened

A working CLI keeps its provider key in a plain text file in its own directory,
read at startup. Convenient, and fine while it stays there. The failure mode is
not the file — it is the next step, when someone debugging prints the file to
compare it against a header, or pipes it into a request that gets logged, or asks
an agent to "show me the config". At that moment the secret leaves the disk and
enters a transcript, a scrollback buffer, or a bug report.

## Why the rule

Storage and exposure are different problems and only the second one is urgent. A
key at rest in a file has a small blast radius; the same key inside a log line has
none of the same limits, because logs get copied, shared, and pasted into issues.
Blocking the read is cheap and does not require moving anyone to a vault first.
