# Saltminer

An offline hash identifier and password-storage auditor. Point it at a
hash and it tells you what algorithm likely produced it — and whether
that choice is still considered secure.

Built in Rust as a learning project. One core engine, exposed as a CLI,
a desktop GUI, and a Python package.

## Status
Early development, following a 14-day build plan.

## Develop
- `just test` — run the tests
- `just lint` — clippy + format check
- `just build` — build everything

## License
MIT
