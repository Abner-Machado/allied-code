## Checklist

- [ ] Tests pass locally (`pytest -q`)
- [ ] If Rust code changed: `cargo test` and `cargo clippy --all-targets -- -D warnings` pass in `alliedcore/`
- [ ] Existing behavior preserved
- [ ] No secrets, keys, tokens, or personal paths in the diff
- [ ] No build artifacts committed (`target/`, `.pyd`, `.so`, `__pycache__/`)
- [ ] If the change alters a guard decision: which incident in `corpus/` justifies it?
