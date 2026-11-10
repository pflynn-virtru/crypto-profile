# 0018: Build-time enforcement generated from the profiles

Date: 2026-11-10. Status: proposed.

## Context

A profile governs only code that calls a backend. Rust binds cryptography at compile time, so there is no registry, like Java's provider list, through which a profile could reach a dependency that brings its own. That includes:

- another library, such as ring or OpenSSL;
- aws-lc-rs used directly;
- rustls's own providers, which a feature brings back (`docs/usage.md` §5);
- a second rustls, whose process default `tls::install_default` does not set;
- a crate written for one algorithm, such as `x25519-dalek` or `sha1`.

What a build can refuse is the dependency graph. Each consumer writes that list by hand today, as maknae's `deny.toml` and `clippy.toml` do, and the list drifts from the profiles.

## Decision

1. **The core crate generates the checks from the profiles.**
   - `enforcement::deny_toml(profile)` is a standalone cargo-deny configuration.
   - `enforcement::clippy_toml()` is this repository's `disallowed-methods` list.
   - Crate refusals follow `Profile::spec()`. A test checks that no Option admits a primitive its profile lacks.
   - The output for every profile is committed under `crypto-profile/enforcement/`. A test fails when a committed file differs from the generator, and another fails when the clippy list differs from the repository's own `clippy.toml`.
2. **The cargo-deny configuration covers the whole shipped tree:** every target, every workspace feature, transitive and build dependencies. It leaves out the workspace's dev-dependencies. Bans name no version, so they match every version. It refuses:
   - other cryptographic libraries, under every profile;
   - aws-lc-rs, its sys crates and rcgen, except as a dependency of a backend. These are `wrappers` entries. cargo-deny takes no `deny-multiple-versions` beside `wrappers`, and none is needed: a second version would need a second backend, which Cargo refuses (`links`);
   - a second version of rustls or rustls-webpki;
   - rustls's and rustls-webpki's provider features, the ones `ci/shipped-graph.sh` keeps out of the backends' own graphs;
   - crates written only for algorithms the profile does not admit;
   - crates for algorithms no profile admits.
3. **A crate is admitted by primitive.** A crate written for P-256, P-384, P-521, X25519, Ed25519, RSA, ChaCha20-Poly1305, SHA-3, ML-KEM or ML-DSA passes when any entry of the profile, in any family, uses that primitive.
   - A hybrid group admits ML-KEM only, because a single-curve crate offers that curve on its own. `preferred` and `fips1403` list X25519MLKEM768 but exclude X25519 on its own, so they refuse `x25519-dalek`.
   - An ECDHE-RSA suite uses RSA; an ECDHE-ECDSA suite names no curve.
4. **CI** (`ci/enforcement.sh`) runs every profile's configuration against both backends' trees, which must pass. It also runs offline fixtures, which must be refused: a library two levels down, a single-algorithm crate (accepted where admitted), aws-lc-rs through a non-backend, a second rustls pulled in by a dependency, rustls's `ring` feature, and a library only a feature brings in.

## Consequences

- A consumer runs the profile's configuration beside its own cargo-deny configuration, and an upgrade that changes the file shows up in its diff.
- The checks are per crate and prove nothing at run time. A crate that offers any admitted algorithm passes, such as `sha2`, `aes-gcm`, `hmac` and `hkdf` under every profile, though its implementation is not the module's. A profile is an algorithm set, not a validation claim.
- A refusal a consumer accepts, such as `sha1` for a WebSocket handshake, needs the consumer's own edited copy.
- `all-features = true` fails to resolve in a workspace whose features choose between backends. Such a workspace sets it to false in its copy.
- Configurations for other ecosystems (OpenSSL, Java, Go) and run-time enforcement are out of scope.
