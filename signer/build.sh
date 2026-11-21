#!/usr/bin/env bash
# Builds the signing canister so its module hash does not depend on where the
# sources or the cargo registry sit, and prints that hash.
#
# Why this exists rather than a plain `dfx build`: rustc writes absolute source
# paths into panic metadata, so without remapping the local cargo registry
# location ends up inside the wasm. The module then hashes differently
# for every builder, which would make the recorded hash — the one the deployed
# canister reports — reproducible only on the machine that made it.
#
# `[profile.release] trim-paths = "all"` would express this in Cargo.toml and is
# the tidier route. It is not stabilised in Cargo 1.93.1, the version
# rust-toolchain.toml pins, so the equivalent rustc flag is set here instead.
#
# One prefix is remapped: CARGO_HOME -> /cargo. That is the only one that
# reaches the module. Remapping the repository root as well was measured to
# change nothing: with only that flag the hash is the same as with no remapping
# at all, because the local crate's recorded paths are relative. It also broke
# the build whenever the checkout path contained a space.
#
# The flag goes in CARGO_ENCODED_RUSTFLAGS rather than RUSTFLAGS, because cargo
# splits RUSTFLAGS on whitespace: a CARGO_HOME containing a space would be torn
# in half and rustc would reject the fragment.
#
# Both run-checks.sh and the README use this script, so the flag lives in one
# place and cannot drift apart.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
cargo_home=${CARGO_HOME:-$HOME/.cargo}
# Normalise, because the remapping matches the prefix literally: a trailing
# slash or an unresolved symlink would simply fail to match and leave the real
# path in the module.
if [ -d "$cargo_home" ]; then
  cargo_home=$(cd "$cargo_home" && pwd)
fi

cd "$here"
# dfx writes its build log and the dependency audit to stdout; send both to
# stderr, so that the only thing on stdout is the hash.
CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$cargo_home=/cargo" \
  dfx build --check signer >&2

wasm=$here/.dfx/local/canisters/signer/signer.wasm
[ -s "$wasm" ] || { echo "build produced no wasm at $wasm" >&2; exit 2; }
sha256sum "$wasm" | cut -d' ' -f1
