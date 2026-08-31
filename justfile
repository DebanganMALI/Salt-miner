# Saltminer command runner. Type `just` to see this list.

# On Windows, run recipes through PowerShell (there is no `sh`).
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# list all recipes
default:
    @just --list

# run the test suite (fast, pretty)
test:
    cargo nextest run

# lint: fail on any warning, then check formatting
lint:
    cargo clippy --all-targets -- -D warnings
    cargo fmt --all --check

# auto-format the whole workspace
fmt:
    cargo fmt --all

# build everything
build:
    cargo build --all-targets

# identify a hash, e.g. just run 5f4dcc3b5aa765d61d8327deb882cf99
run *ARGS:
    cargo run -p saltminer-cli -- {{ARGS}}
