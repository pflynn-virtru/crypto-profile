---
name: using-crypto-profile
description: Use when adding crypto-profile, crypto-profile-awslc4 or crypto-profile-awslc3 to a Rust project, or when adding TLS, HTTP, database or other dependencies, cargo-deny, clippy or CI to a project that depends on them.
---

# Using crypto-profile

A profile governs only code that calls the backend. Everything else in the dependency tree is checked at build time, by files the crate generates from the profile. Don't hand-write that ban list: the generated one covers crates a hand-written list misses (aws-lc-rs used directly, rustls-webpki's providers, single-algorithm crates such as `p256` or `x25519-dalek`, `md5`, `sha1`, `des`).

Read the documentation for the version in `Cargo.lock` (`docs.rs/crypto-profile-awslc4/<version>`, and the crate source's `docs/usage.md` section numbers below).

## Setup

1. **One backend**, pinned exactly (`= "x.y.z"`): `crypto-profile-awslc4` (AWS-LC FIPS 4.x) or `crypto-profile-awslc3` (3.x, no ML-DSA). usage §1, §3, §8. Write `use crypto_profile_awslc4 as crypto;`.
2. **Toolchain:** the crate's `rust-version` in `rust-toolchain.toml`. Build host: C/C++ compiler, CMake, Go, Perl, clang (usage §4).
3. **If the build panics with `expected aws_lc_fips_0_14_2_crypto, aws-lc-rs reported [...]`**, run `cargo update -p aws-lc-fips-sys --precise <the version it expects>` and commit `Cargo.lock`.
4. **Linkage is a module choice:** static and dynamic are separate certificates (usage §2). Set `AWS_LC_FIPS_SYS_STATIC` explicitly in CI and release builds. A dynamic binary loads `libaws_lc_fips_*_crypto` at run time: `cargo run` finds it, a deployed binary needs it shipped.

## Code

- Start-up: `crypto::fips::assert_fips_module()?`, then `let r = crypto::resolve(Profile::Cnsa2, options)?;`. `Options` is `#[non_exhaustive]`: start from `Options::default()` and set fields on it.
- TLS through `crypto::tls::client_builder(&r.tls)` / `server_builder`, or, with `peer_certificates_match_profile`, the strict builders and verifier builders (usage §6). Use the re-exported `crypto::rustls`; never call rustls's `ClientConfig::builder()` family.
- A library that takes a `ClientConfig` gets the crate-built one, with its own TLS features off (reqwest: `default-features = false, features = ["rustls-no-provider"]`, then `use_preconfigured_tls`). One that uses rustls's process default needs `crypto::tls::install_default(&r.tls)` first, which does not enforce the peer-certificate rule.
- `cnsa2` peers need ML-DSA-87 certificates: public web PKI roots cannot complete a `cnsa2` handshake.
- Random bytes, hashing, AEAD, HMAC, KDF, ECDH and signatures come from the backend's modules (usage §13-19), not from RustCrypto crates.

## Build-time checks

The generated files are `crypto::enforcement::deny_toml(profile)` and `crypto::enforcement::clippy_toml()` (usage §20). Add this test; `REGENERATE=1 cargo test --test enforcement` writes `deny-<profile>.toml`, and the test fails when an upgrade changes it:

```rust
// tests/enforcement.rs
use crypto_profile_awslc4 as crypto;
use crypto::{enforcement, Profile};
use std::{env, fs, path::Path};

const PROFILE: Profile = Profile::Cnsa2; // the profile the application resolves

#[test]
fn deny_file_is_the_profiles() {
    let want = enforcement::deny_toml(PROFILE)
        // Each exception is reviewed here: tokio-postgres's MD5 password authentication.
        .replace(r#"{ crate = "md-5", reason"#, r#"{ crate = "md-5", wrappers = ["postgres-protocol"], reason"#);
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("deny-{PROFILE}.toml"));
    if env::var_os("REGENERATE").is_some() {
        fs::write(&path, &want).unwrap();
    }
    assert_eq!(fs::read_to_string(&path).unwrap(), want, "rerun with REGENERATE=1 and review the diff");
}

#[test]
fn clippy_toml_carries_the_list() {
    let have = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("clippy.toml")).unwrap();
    for line in enforcement::clippy_toml().lines().filter(|l| l.trim_start().starts_with("{ path")) {
        assert!(have.contains(line), "clippy.toml lacks {line}");
    }
}
```

When the profile's file refuses a crate a dependency needs, add a `wrappers` exception in the test as above, naming the crate that pulls it in. Never delete the entry or drop the file.

CI runs, beside your own `deny.toml` (advisories, licenses, sources; aws-lc-fips-sys needs `OpenSSL` in the license allow-list):

- `cargo deny --config deny-<profile>.toml check bans -A unused-wrapper`
- `cargo clippy --all-targets --locked -- -D warnings`, with the list merged into `clippy.toml`
- `cargo test --locked`
- the binary itself, so `assert_fips_module` runs on the linkage you ship

## Common mistakes

| Mistake | Fix |
|---|---|
| A direct `rustls`, `tokio-rustls` or `reqwest` with default features | Their defaults add rustls's own provider. Check `cargo tree -e features -i rustls` (usage §5). |
| `all-features = true` fails to resolve | Your features choose between backends: set `all-features = false` in your copy (usage §20). |
| Treating a passing check as FIPS approval | The checks are per crate. Module approval is `assert_module_approves` (usage §8). |

## Done when

All four CI commands above pass locally, with the generated files committed.
