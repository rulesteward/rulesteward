# Summary

<!-- One paragraph: what changed and why. Link to the spec section, handoff, or issue this implements. -->

## Module / crate touched

<!-- e.g. rulesteward-fapolicyd, rulesteward-cli, CI -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup
- [ ] Docs / templates
- [ ] CI / build / release tooling

## Checklist

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace --locked` passes
- [ ] Read-only by default - any new mutation flag is opt-in
- [ ] No telemetry, no phone-home
- [ ] No AI-attribution trailers in commits (`Co-Authored-By: Claude` etc.)

## Notes for reviewer

<!-- Anything specific to look at, design trade-offs, deferred work. -->
