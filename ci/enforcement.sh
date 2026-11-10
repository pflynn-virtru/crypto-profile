#!/usr/bin/env bash
# Every profile's cargo-deny configuration (crypto-profile/enforcement) accepts both backends'
# dependency trees, and refuses fixtures that bring in cryptography the profile does not govern,
# at any depth of the tree, in a second version or behind a feature. The fixtures are offline path
# crates named after the crates they stand for.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
dir="$root/crypto-profile/enforcement"
deny() { cargo deny "$@" check bans -A unused-wrapper; }

for profile in unrestricted preferred cnsa2 cnsa1 bsi fips1403 fips1402; do
  deny --manifest-path "$root/Cargo.toml" --locked --config "$dir/deny-$profile.toml"
  deny --manifest-path "$root/crypto-profile-awslc3/Cargo.toml" --locked --config "$dir/deny-$profile.toml"
done

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
# crate <dir> <name> <version> [manifest lines...]
crate() {
  local d="$work/$1"
  mkdir -p "$d/src"
  : > "$d/src/lib.rs"
  { printf '[package]\nname = "%s"\nversion = "%s"\nedition = "2021"\n' "$2" "$3"; shift 3; printf '%s\n' "$@"; } > "$d/Cargo.toml"
}
# expect <profile> <fixture> accept|<diagnostic>
expect() {
  local out
  if out="$(deny --manifest-path "$work/$2/Cargo.toml" --offline --config "$dir/deny-$1.toml" 2>&1)"; then
    if [ "$3" != accept ]; then printf '%s\n' "$out"; echo "deny-$1.toml accepted $2"; exit 1; fi
  elif [ "$3" = accept ] || ! grep -qF -- "$3" <<<"$out"; then
    printf '%s\n' "$out"; echo "deny-$1.toml: $2 did not end with $3"; exit 1
  fi
}

crate ring ring 0.17.14
crate p256 p256 0.13.2
crate x25519 x25519-dalek 2.0.1
crate aws-lc-rs aws-lc-rs 1.19.0
crate rustls-23 rustls 0.23.46 '[features]' 'ring = []'
crate rustls-22 rustls 0.22.4
crate backend crypto-profile-awslc4 0.10.0 '[dependencies]' 'aws-lc-rs = { path = "../aws-lc-rs" }'
for dep in ring p256 x25519 aws-lc-rs rustls-22; do
  crate "mid-$dep" "mid-$dep" 0.1.0 '[dependencies]' "inner = { package = \"$(sed -n 's/^name = "\(.*\)"$/\1/p' "$work/$dep/Cargo.toml")\", path = \"../$dep\" }"
  crate "app-$dep" "app-$dep" 0.1.0 '[dependencies]' "mid = { package = \"mid-$dep\", path = \"../mid-$dep\" }" 'rustls = { path = "../rustls-23" }'
done
crate app-backend app-backend 0.1.0 '[dependencies]' 'backend = { package = "crypto-profile-awslc4", path = "../backend" }'
crate app-feature app-feature 0.1.0 '[dependencies]' 'rustls = { path = "../rustls-23", features = ["ring"] }'
crate app-optional app-optional 0.1.0 '[dependencies]' 'ring = { path = "../ring", optional = true }'

# Another cryptographic library two levels down, under the profile that admits the most.
expect unrestricted app-ring 'crate = "ring"'
# A crate for one algorithm, refused only where the profile does not admit it.
expect cnsa2 app-p256 'crate = "p256"'
expect preferred app-p256 accept
expect unrestricted app-p256 accept
# X25519 inside a hybrid group does not admit it on its own.
expect preferred app-x25519 'crate = "x25519-dalek"'
expect fips1403 app-x25519 'crate = "x25519-dalek"'
expect unrestricted app-x25519 accept
# aws-lc-rs through a backend, and not through anything else.
expect cnsa2 app-backend accept
expect unrestricted app-aws-lc-rs 'crate = "aws-lc-rs"'
# A second rustls, pulled in by a dependency.
expect unrestricted app-rustls-22 "found 2 duplicate entries for crate 'rustls'"
# rustls's own provider, and a library only a feature brings in.
expect unrestricted app-feature 'feature-banned'
expect unrestricted app-optional 'crate = "ring"'
echo "enforcement: every profile accepts both backends and refuses every fixture"
