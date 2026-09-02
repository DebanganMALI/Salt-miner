# Saltminer command runner. Type `just` to see this list.

set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

default:
    @just --list

test:
    cargo nextest run

lint:
    cargo clippy --all-targets -- -D warnings
    cargo fmt --all --check

fmt:
    cargo fmt --all

build:
    cargo build --all-targets

run *ARGS:
    cargo run -p saltminer-cli -- {{ARGS}}

gui:
    cargo run --manifest-path crates/saltminer-gui/Cargo.toml
