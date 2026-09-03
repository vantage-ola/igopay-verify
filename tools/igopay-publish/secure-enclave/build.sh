#!/usr/bin/env bash
# Build the Secure Enclave signer helper.
#
# Separate from `cargo build` because it is Swift and macOS-only: the Enclave is reached through
# CryptoKit, and no Rust crate can do it. That is the point of `igopay-publish --signer` being a
# command rather than a library — custody can be whatever the platform offers, and the publisher
# stays the same code.
#
# Produces: target/igopay-publish-se
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/../target/igopay-publish-se"
mkdir -p "$(dirname "$out")"

if ! command -v swiftc > /dev/null; then
    echo "swiftc not found — this needs the Xcode toolchain, and works only on macOS." >&2
    exit 1
fi

swiftc -O "$here/main.swift" -o "$out"
echo "built $out"
echo
echo "Generate the publication key (asks for Touch ID on every signature afterwards):"
echo "  $out create ./issuer-key.se"
