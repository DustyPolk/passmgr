#!/usr/bin/env bash
# The repo gate. Every commit passes it; loop.sh and CI run exactly this.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --all-targets -q -- -D warnings
cargo test -q
