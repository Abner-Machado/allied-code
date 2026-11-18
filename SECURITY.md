# Security

## Reporting

Use [private vulnerability reporting](https://github.com/Abner-Machado/allied-code/security/advisories/new)
on this repository, rather than a public issue. No bounty, and no promised response window:
what you get is an honest answer about whether it is real and what happens next.

## What the attack surface actually is

This decides whether a command is allowed to run, so the failure that matters is a **wrong
allow**, not a crash. A guard that lets something through is worse than no guard, because
somebody stopped watching.

Worth probing, in rough order of how much it would hurt:

- A destructive command that comes back allowed. The repository is already honest that
  `remote.pipe-to-shell` has an accepted false positive and that shell substitution is hard
  to read statically; the interesting report is the opposite direction, something the
  classifier reads as safe that a shell reads as destructive. Quoting, encoding, a command
  split across segments, a locale or alias trick.
- A corpus or ledger file that changes the verdict in a way the receipts do not show. The
  ledger is the evidence that a decision was made; anything that corrupts, truncates or
  silently rewrites it undermines every audit after the fact.
- A difference between the Python and the Rust backend on the same input. CI asserts the
  Rust backend really activated, precisely so the two cannot drift unnoticed, and a verdict
  that depends on which one is installed is a bug.
- Anything in the hook path that makes the guard fail open rather than refuse to start. A
  missing corpus or an unwritable ledger should degrade loudly.

The package declares no runtime dependencies. The Rust side is built from `alliedcore/` in
this repository, not fetched as a binary.

## What is out of scope

Disagreeing with a decision, or with a precedent in the corpus, is an issue rather than a
vulnerability. So is the guard blocking something you believe is safe: it is designed to err
in that direction, and `observe` mode exists for when you want it to watch without
intervening.
