# Contributing

## Running tests

### Python

```bash
pip install -e .
pip install pytest pytest-subtests
pytest -q
```

### Rust

```bash
cd alliedcore
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Building the Rust extension

The Rust core is **optional**. The Python package works without it.

To build the Python extension module:

```bash
cd alliedcore
cargo build --release --features python
cp target/release/liballiedcore.so ../alliedcore.so
```

Set `ALLIED_BACKEND=rust` to use it. `ALLIED_BACKEND=python` (default) runs the pure-Python classifier.

## Commit style

This project uses Conventional Commits:

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation only
- `test:` adding or correcting tests
- `refactor:` code change that neither fixes a bug nor adds a feature

Subject line: 50 characters or fewer. One atomic change per commit.

## The rule that matters most

A change that alters what the guard decides **must** come with:

- An incident in `corpus/` that justifies the change, **or**
- A test that demonstrates the case.

"A better idea" is not a reason to change a security decision. The corpus is the source of truth for what the guard blocks and why.

## Secrets

No secret, key, token, credential, or personal path enters an issue, PR, test, or corpus file. Mask before pasting.

## Build artifacts

Never commit `target/`, `.pyd`, `.so`, `__pycache__/`, or any generated file.

## Writing a corpus incident

Use the Incident report issue template (`.github/ISSUE_TEMPLATE/incident_report.md`). It mirrors the exact front matter and prose format used in `corpus/*.md`. A maintainer will move it into the corpus.
