# Design notes

## The premise

Guardrails are usually written as a list of forbidden patterns. That list has two
properties that make it age badly: it is written before the failures happen, and
it never changes after them. Meanwhile every team accumulates the other thing —
a set of scars, each one with a rule attached, kept in someone's head or in a
document nobody reads at the moment it would matter.

`ops-guard` is the claim that those scars are the right input to a guard, and
that consulting them before an action is the part worth automating. Retrieving
the relevant past failure at the exact moment it applies is not something a human
does well, because it requires perfect recall of things that happened months ago
and were boring at the time.

## Two readings of one corpus

The same set of incidents answers two different questions.

| Question | When | Command |
|---|---|---|
| Should this action run? | during the work, per tool call | `guard check`, the hook |
| What should I know first? | before the work, per task | `guard brief` |

The second reading is why the corpus keeps paying after the blocking becomes
routine. A briefing is retrieval without enforcement: hand it to whoever — or
whatever — is about to start, and the failure gets avoided instead of blocked.
This is also the hook into orchestration: before delegating a task, the
orchestrator asks for a briefing on that task and passes it down. The subagent
starts with the scars already in context, and the guard still stands behind it
per call.

## The decision

```
hazard classes  →  severity floor
recorded incidents  →  raise the floor when precedent is strong
                       (a critical/high incident scoring ≥ 0.5)

critical  →  deny
high      →  ask
medium    →  ask if there is precedent, otherwise defer
none      →  defer (no retrieval; nothing to justify)
```

Three deliberate choices in that table:

**The guard never grants.** It returns `deny`, `ask` or `defer` — never `allow`
by default. A guard that can lower friction is a guard that can be talked into
lowering it, and the failure mode is silent.

**Precedent escalates, it never de-escalates.** An absent incident cannot make a
`critical` action acceptable. Otherwise the corpus becomes an allowlist and every
new hazard is legal until it hurts someone.

**Observe is the default.** The gap between what the guard *did* and what it
*would have done* (`decision` vs `intended` in every receipt) is measurable
before anything is enforced. That gap is the honest way to argue for turning it
on.

## Why lexical retrieval

Embeddings would match meaning better. They would also mean a model call or a
loaded model in front of every tool call in the session. The budget here is a few
milliseconds and zero network, so the trade is: worse recall, no dependency, no
latency, no service to keep running, works offline on a laptop.

Measured on a low-end machine: ~0.1 ms when no hazard class matches (retrieval is
skipped entirely), ~4 ms when it runs against the shipped corpus. A test asserts
the per-call budget so a future change cannot quietly blow it.

If the corpus ever grows past a few hundred incidents, the index is the thing to
replace — not the interface around it.

## Threat model

In scope: accidents, overconfident automation, and delegated processes acting
outside their mandate. Those are the failures that actually happen and the ones
the corpus is made of.

Out of scope: an adversary with shell access. Classification is regex over a
command string and loses to trivial obfuscation. Claiming otherwise would be the
same fabrication the corpus warns about in
`corpus/fabricated-verification-report.md`.

## Receipts

Every decision appends one JSON line: timestamp, tool, redacted action, decision,
what it would have been when enforcing, hazard classes, cited incidents with
scores, latency, session and agent identifiers. Reasons for keeping them:

- A block you cannot audit later is an obstacle, not a control.
- `guard stats` turns the ledger into an argument: how often the guard fires,
  which incidents are load-bearing, which have never been cited once (candidates
  for deletion — a corpus that only grows is a corpus nobody trusts).
- The `agent` field is what makes per-agent policy possible later without
  changing the format.

Redaction runs before anything is written. A guard that leaks the credential it
was protecting is worse than no guard.

## The feedback the guard already had and was throwing away

A guard has no ground truth. It cannot tell a good block from a bad one, so it
either gets tuned by whoever wrote it or not at all.

Except the ground truth is generated every day, by the person being protected.
`PostToolUse` fires only after a tool succeeds. So for every call the guard
questioned there are exactly two possible worlds: an outcome line exists, meaning
the human overruled the guard, or no line was ever written, meaning the human
agreed with it. **The absence of a record is the record.** No model, no network,
no extra prompt, and nothing added to the pre-execution budget, because the
outcome line is written after the call already ran.

What that buys, in order of how much it matters:

1. A hit rate. `guard stats` reports agreed / overruled, which is the only claim
   about a guard that is not the guard's own opinion of itself.
2. Per-incident attribution. An incident cited nine times that never once stopped
   anybody is not a rule, it is noise — and the report names the file to edit.
3. A path to `guard learn --from-ledger`: the guard drafting a corpus change and
   a human committing it.

The thing it deliberately does **not** buy is automatic relaxation. Being
overruled is exactly the input an attacker — or an impatient afternoon — would
use to talk the guard down, and the resulting weakening would be invisible. So
the loop stops at a report. The corpus is edited by a person, in git, where the
change has an author and a date.

## Per-agent ceilings

The `agent` field has been in every receipt since the first version. It now does
something: callers matching `strict_agents` get every hazard class escalated one
level, because a delegated producer working from a narrow mandate has less
license than the orchestrator that chose the command. The direction is one-way.
Naming an agent can only raise its floor, never lower it — otherwise the config
becomes an allowlist keyed on a string the caller supplies.

## Direction

1. **Operations RAG.** The corpus is already retrieval over operational memory.
   The next step is ingesting the ledger back into it: a receipt that led to a
   real incident becomes an incident file, with `guard learn --from-ledger`. The
   outcome loop is what makes that draft worth reading — it can point at the
   calls you refused that no incident explains yet.
2. **Orchestration.** Briefing on delegation, and per-agent policy beyond a
   single escalation step.
3. **Better recall without a service.** Synonym expansion over tags before
   anything heavier gets considered.
