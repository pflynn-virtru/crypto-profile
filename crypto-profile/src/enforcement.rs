//! Build-time configurations that carry a profile to code that does not call this crate
//! (decision 0018).
//!
//! A profile governs what goes through a backend. A dependency with its own cryptography does not:
//! another library such as ring or OpenSSL, aws-lc-rs used directly, rustls's own providers, or a
//! crate written for one algorithm. [`deny_toml`] is a cargo-deny configuration that refuses those
//! in a build, for one profile, and [`clippy_toml`] the `disallowed-methods` this repository lints
//! its own code with, for a consumer's code. `crypto-profile/enforcement/` holds their output for
//! every profile.
//!
//! The checks are per crate. A crate that implements any algorithm the profile admits passes:
//! `sha2`, `aes-gcm`, `hmac` and `hkdf` pass under every profile, though their implementations are
//! not the module's. Neither file has any effect at run time.

use crate::algorithm::{
    AeadAlgorithm as A, Algorithm, CipherSuite as C, HashAlgorithm as H,
    KeyAgreementAlgorithm as E, KxGroup as K, SignatureAlgorithm as S, TlsSignatureScheme as T,
};
use crate::profile::{Profile, ProfileSpec};

/// A primitive a crate below is written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Primitive {
    P256,
    P384,
    P521,
    X25519,
    Ed25519,
    Rsa,
    ChaCha20Poly1305,
    Sha3,
    MlKem,
    MlDsa,
}
use Primitive as P;

/// The primitives `a` admits a crate for, among those in [`Primitive`]. A hybrid group admits
/// ML-KEM only: a profile that lists X25519MLKEM768 but not X25519 excludes X25519 on its own
/// (`preferred`), and a crate for one curve offers it on its own. A TLS 1.2 ECDHE-RSA suite uses
/// RSA; an ECDHE-ECDSA suite names no curve.
fn primitives(a: Algorithm) -> &'static [Primitive] {
    match a {
        Algorithm::Signature(s) => match s {
            S::MlDsa87 => &[P::MlDsa],
            S::EcdsaP256Sha256 => &[P::P256],
            S::EcdsaP384Sha384 => &[P::P384],
            S::EcdsaP521Sha384 | S::EcdsaP521Sha512 => &[P::P521],
            S::Ed25519 => &[P::Ed25519],
            S::Rsa2048Sha384
            | S::Rsa3072Sha384
            | S::Rsa4096Sha384
            | S::Rsa2048Sha384Pss
            | S::Rsa3072Sha384Pss
            | S::Rsa4096Sha384Pss => &[P::Rsa],
        },
        Algorithm::Scheme(t) => match t {
            T::EcdsaNistp256Sha256 => &[P::P256],
            T::EcdsaNistp384Sha384 => &[P::P384],
            T::EcdsaNistp521Sha512 => &[P::P521],
            T::Ed25519 => &[P::Ed25519],
            T::RsaPssSha256
            | T::RsaPssSha384
            | T::RsaPssSha512
            | T::RsaPkcs1Sha256
            | T::RsaPkcs1Sha384
            | T::RsaPkcs1Sha512 => &[P::Rsa],
            T::MlDsa87 => &[P::MlDsa],
        },
        Algorithm::Kx(k) => match k {
            K::MlKem1024 => &[P::MlKem],
            K::Secp384r1MlKem1024 | K::X25519MlKem768 | K::Secp256r1MlKem768 => &[P::MlKem],
            K::Secp384r1 => &[P::P384],
            K::Secp256r1 => &[P::P256],
            K::X25519 => &[P::X25519],
        },
        Algorithm::Cipher(c) => match c {
            C::Tls13Chacha20Poly1305Sha256 | C::Tls12EcdheEcdsaChacha20Poly1305Sha256 => {
                &[P::ChaCha20Poly1305]
            }
            C::Tls12EcdheRsaChacha20Poly1305Sha256 => &[P::Rsa, P::ChaCha20Poly1305],
            C::Tls12EcdheRsaAes256GcmSha384 | C::Tls12EcdheRsaAes128GcmSha256 => &[P::Rsa],
            C::Tls13Aes256GcmSha384
            | C::Tls13Aes128GcmSha256
            | C::Tls12EcdheEcdsaAes256GcmSha384
            | C::Tls12EcdheEcdsaAes128GcmSha256 => &[],
        },
        Algorithm::Hash(h) => match h {
            H::Sha3_256 | H::Sha3_384 | H::Sha3_512 => &[P::Sha3],
            H::Sha256 | H::Sha384 | H::Sha512 => &[],
        },
        Algorithm::KeyAgreement(e) => match e {
            E::EcdhP256 => &[P::P256],
            E::EcdhP384 => &[P::P384],
            E::EcdhP521 => &[P::P521],
            E::X25519 => &[P::X25519],
        },
        Algorithm::Aead(x) => match x {
            A::Chacha20Poly1305 => &[P::ChaCha20Poly1305],
            A::Aes128Gcm | A::Aes256Gcm => &[],
        },
        Algorithm::Protocol(_) | Algorithm::Mac(_) | Algorithm::Kdf(_) => &[],
    }
}

/// Every entry of `spec`, in every family.
fn algorithms(spec: &ProfileSpec) -> impl Iterator<Item = Algorithm> + '_ {
    (spec.versions.iter().map(|v| Algorithm::Protocol(*v)))
        .chain(spec.cipher_suites.iter().map(|c| Algorithm::Cipher(*c)))
        .chain(spec.kx_groups.iter().map(|k| Algorithm::Kx(*k)))
        .chain(spec.signature_schemes.iter().map(|t| Algorithm::Scheme(*t)))
        .chain(spec.key_algorithms.iter().map(|s| Algorithm::Signature(*s)))
        .chain(spec.macs.iter().map(|m| Algorithm::Mac(*m)))
        .chain(spec.kdfs.iter().map(|k| Algorithm::Kdf(*k)))
        .chain(
            spec.key_agreements
                .iter()
                .map(|e| Algorithm::KeyAgreement(*e)),
        )
        .chain(spec.aeads.iter().map(|x| Algorithm::Aead(*x)))
        .chain(spec.hashes.iter().map(|h| Algorithm::Hash(*h)))
        .chain(spec.signatures.iter().map(|s| Algorithm::Signature(*s)))
}

/// Whether any entry of `spec` uses `p`.
fn admits(spec: &ProfileSpec, p: Primitive) -> bool {
    algorithms(spec).any(|a| primitives(a).contains(&p))
}

/// Cryptographic libraries beside the AWS-LC FIPS module, refused under every profile.
const OTHER_LIBRARIES: &[(&str, &str)] = &[
    ("ring", "ring"),
    ("openssl", "OpenSSL"),
    ("openssl-sys", "OpenSSL"),
    ("native-tls", "the platform's TLS library"),
    ("boring", "BoringSSL"),
    ("boring-sys", "BoringSSL"),
    ("botan", "Botan"),
    ("botan-sys", "Botan"),
    ("mbedtls", "Mbed TLS"),
    ("mbedtls-sys-auto", "Mbed TLS"),
    ("wolfssl", "wolfSSL"),
    ("wolfssl-sys", "wolfSSL"),
    ("libsodium-sys", "libsodium"),
    ("libsodium-sys-stable", "libsodium"),
    ("sodiumoxide", "libsodium"),
    ("graviola", "graviola"),
    ("rustls-rustcrypto", "a RustCrypto provider for rustls"),
    ("rustls-openssl", "an OpenSSL provider for rustls"),
];

/// The FIPS module and rcgen, refused under every profile except as a dependency of the listed
/// crates. rcgen's `aws_lc_rs` feature reaches aws-lc-rs. None of them can come in a second version
/// without failing its wrappers, since Cargo refuses two backends in one build (`links =
/// "crypto-profile-backend"`); cargo-deny does not take `deny-multiple-versions` beside `wrappers`.
const WRAPPED: &[(&str, &[&str], &str)] = &[
    (
        "aws-lc-rs",
        &["crypto-profile-awslc4", "crypto-profile-awslc3", "rcgen"],
        "the AWS-LC FIPS module's own API; reach it through a crypto-profile backend",
    ),
    (
        "aws-lc-fips-sys",
        &["aws-lc-rs"],
        "the AWS-LC FIPS module; reach it through a crypto-profile backend",
    ),
    (
        "aws-lc-sys",
        &["aws-lc-rs"],
        "AWS-LC outside its FIPS module; reach it through a crypto-profile backend",
    ),
    (
        "rcgen",
        &["crypto-profile-awslc4", "crypto-profile-awslc3"],
        "certificate generation with its own signers; use the backend's csr module",
    ),
];

/// Crates the backends use, refused in more than one version: a second version, which any
/// dependency in the tree can pull in, is a TLS stack the profile does not govern.
const ONE_VERSION: &[(&str, &str)] = &[
    (
        "rustls",
        "a second rustls, whose default provider the profile does not set",
    ),
    (
        "rustls-webpki",
        "a second rustls-webpki, outside the profile's verifiers",
    ),
];

/// Crates written for the listed primitives only, refused where a profile admits none of them.
const ALGORITHM_CRATES: &[(&str, &[Primitive], &str)] = &[
    ("p256", &[P::P256], "ECDSA and ECDH on P-256"),
    ("p384", &[P::P384], "ECDSA and ECDH on P-384"),
    ("p521", &[P::P521], "ECDSA and ECDH on P-521"),
    ("x25519-dalek", &[P::X25519], "X25519"),
    ("ed25519-dalek", &[P::Ed25519], "Ed25519"),
    ("ed25519", &[P::Ed25519], "Ed25519"),
    (
        "curve25519-dalek",
        &[P::X25519, P::Ed25519],
        "Curve25519, for X25519 and Ed25519",
    ),
    ("rsa", &[P::Rsa], "RSA"),
    (
        "chacha20poly1305",
        &[P::ChaCha20Poly1305],
        "ChaCha20-Poly1305",
    ),
    ("chacha20", &[P::ChaCha20Poly1305], "ChaCha20"),
    ("poly1305", &[P::ChaCha20Poly1305], "Poly1305"),
    ("sha3", &[P::Sha3], "SHA-3"),
    ("ml-kem", &[P::MlKem], "ML-KEM"),
    ("ml-dsa", &[P::MlDsa], "ML-DSA"),
];

/// Crates for algorithms no profile admits, refused under every profile.
const UNLISTED_CRATES: &[(&str, &str)] = &[
    ("md-5", "MD5"),
    ("md5", "MD5"),
    ("md4", "MD4"),
    ("md2", "MD2"),
    ("sha1", "SHA-1"),
    ("sha-1", "SHA-1"),
    ("sha1_smol", "SHA-1"),
    ("ripemd", "RIPEMD"),
    ("des", "DES and Triple DES"),
    ("rc2", "RC2"),
    ("rc4", "RC4"),
    ("blowfish", "Blowfish"),
    ("cast5", "CAST5"),
    ("idea", "IDEA"),
    ("tiger", "Tiger"),
    ("whirlpool", "Whirlpool"),
    ("sm3", "SM3"),
    ("sm4", "SM4"),
    ("streebog", "Streebog"),
    ("dsa", "DSA"),
];

/// The features that give rustls and rustls-webpki their own providers, refused under every
/// profile, as `ci/shipped-graph.sh` refuses them in the backends' own graphs.
const PROVIDER_FEATURES: &[(&str, &[&str])] = &[
    ("rustls", &["aws_lc_rs", "aws-lc-rs", "fips", "ring"]),
    (
        "rustls-webpki",
        &["aws-lc-rs", "aws-lc-rs-fips", "aws-lc-rs-unstable", "ring"],
    ),
];

fn quoted(items: &[&str]) -> String {
    let quoted: Vec<String> = items.iter().map(|i| format!("\"{i}\"")).collect();
    quoted.join(", ")
}

fn entry(out: &mut String, krate: &str, wrappers: &[&str], one_version: bool, reason: &str) {
    out.push_str(&format!("  {{ crate = \"{krate}\", "));
    if !wrappers.is_empty() {
        out.push_str(&format!("wrappers = [{}], ", quoted(wrappers)));
    }
    if one_version {
        out.push_str("deny-multiple-versions = true, ");
    }
    out.push_str(&format!("reason = \"{reason}\" }},\n"));
}

/// A cargo-deny configuration that refuses, anywhere in a build's shipped dependency tree, on every
/// target and with every feature, the cryptography `profile` does not govern: other cryptographic
/// libraries; the FIPS module and rcgen except through a backend; a second version of rustls or
/// rustls-webpki; rustls's and rustls-webpki's own providers;
/// crates written only for algorithms `profile` does not admit; and crates for algorithms no
/// profile admits. A refusal names every version of a crate. It is standalone: `cargo deny --config <file> check bans -A unused-wrapper`, where `-A
/// unused-wrapper` silences the backend a build does not use.
///
/// The crates follow `profile.spec()`, before Options: no Option admits a primitive its profile
/// lacks.
pub fn deny_toml(profile: Profile) -> String {
    let name = profile.as_str();
    let spec = profile.spec();
    let mut out = format!(
        "# cargo-deny bans for the `{name}` profile, generated by\n\
         # `crypto_profile::enforcement::deny_toml`. Regenerate it on every crypto-profile upgrade.\n\
         # Check with: cargo deny --config deny-{name}.toml check bans -A unused-wrapper\n\
         \n\
         [graph]\n\
         all-features = true\n\
         exclude-dev = true\n\
         \n\
         [bans]\n\
         multiple-versions = \"allow\"\n\
         deny = [\n  # Cryptographic libraries beside the AWS-LC FIPS module.\n"
    );
    for (krate, what) in OTHER_LIBRARIES {
        entry(
            &mut out,
            krate,
            &[],
            false,
            &format!("{what}, beside the AWS-LC FIPS module"),
        );
    }
    out.push_str("  # The FIPS module and rcgen, only through a crypto-profile backend.\n");
    for (krate, wrappers, why) in WRAPPED {
        entry(&mut out, krate, wrappers, false, why);
    }
    out.push_str("  # One version of each stack crate.\n");
    for (krate, why) in ONE_VERSION {
        entry(&mut out, krate, &[], true, why);
    }
    let refused: Vec<_> = ALGORITHM_CRATES
        .iter()
        .filter(|(_, uses, _)| !uses.iter().any(|p| admits(spec, *p)))
        .collect();
    if !refused.is_empty() {
        out.push_str(&format!("  # Algorithms `{name}` does not admit.\n"));
    }
    for (krate, _, what) in refused {
        entry(
            &mut out,
            krate,
            &[],
            false,
            &format!("{what}, which {name} does not admit"),
        );
    }
    out.push_str("  # Algorithms no profile admits.\n");
    for (krate, what) in UNLISTED_CRATES {
        entry(
            &mut out,
            krate,
            &[],
            false,
            &format!("{what}, which no profile admits"),
        );
    }
    out.push_str("]\n");
    for (krate, features) in PROVIDER_FEATURES {
        out.push_str(&format!(
            "\n# {krate}'s own providers: use the crypto-profile backend's.\n\
             [[bans.features]]\n\
             crate = \"{krate}\"\n\
             deny = [{}]\n",
            quoted(features)
        ));
    }
    out
}

/// The `disallowed-methods` of this repository's `clippy.toml`, verbatim.
const DISALLOWED_METHODS: &str = r#"disallowed-methods = [
  { path = "rustls::crypto::aws_lc_rs::default_provider", allow-invalid = true, reason = "build providers with crypto_profile_awslc4::tls::crypto_provider(&Policy)" },
  { path = "rustls::crypto::default_fips_provider", allow-invalid = true, reason = "build providers with crypto_profile_awslc4::tls::crypto_provider(&Policy)" },
  { path = "rustls::ClientConfig::builder", reason = "installs the stock provider; use tls::client_builder(&Policy)" },
  { path = "rustls::ClientConfig::builder_with_protocol_versions", reason = "installs the stock provider; use tls::client_builder(&Policy)" },
  { path = "rustls::ServerConfig::builder", reason = "installs the stock provider; use tls::server_builder(&Policy)" },
  { path = "rustls::ServerConfig::builder_with_protocol_versions", reason = "installs the stock provider; use tls::server_builder(&Policy)" },
  { path = "rustls::server::WebPkiClientVerifier::builder", reason = "installs the stock provider; use tls::client_cert_verifier_builder" },
  { path = "rustls::client::WebPkiServerVerifier::builder", reason = "installs the stock provider; use tls::server_cert_verifier_builder" },
  { path = "rustls::crypto::SupportedKxGroup::start", reason = "cryptography goes through crypto-profile" },
  { path = "rustls::crypto::hpke::Hpke::setup_sealer", reason = "cryptography goes through crypto-profile" },
  { path = "rustls::crypto::hpke::Hpke::setup_opener", reason = "cryptography goes through crypto-profile" },
  { path = "rustls::crypto::hpke::Hpke::seal", reason = "cryptography goes through crypto-profile" },
  { path = "rustls::crypto::hpke::Hpke::open", reason = "cryptography goes through crypto-profile" },
  { path = "rustls::crypto::SecureRandom::fill", reason = "cryptography goes through crypto-profile" },
  { path = "rustls::crypto::KeyProvider::load_private_key", reason = "use tls::load_private_key" },
  { path = "rustls::ClientConfig::builder_with_provider", reason = "use tls::client_builder(&Policy)" },
  { path = "rustls::ServerConfig::builder_with_provider", reason = "use tls::server_builder(&Policy)" },
  { path = "rustls::server::WebPkiClientVerifier::builder_with_provider", reason = "use tls::client_cert_verifier_builder" },
  { path = "rustls::client::WebPkiServerVerifier::builder_with_provider", reason = "use tls::server_cert_verifier_builder" },
  { path = "rustls::crypto::aws_lc_rs::sign::any_supported_type", allow-invalid = true, reason = "use tls::load_private_key" },
  { path = "rustls::crypto::aws_lc_rs::sign::any_ecdsa_type", allow-invalid = true, reason = "use tls::load_private_key" },
  { path = "rustls::crypto::aws_lc_rs::sign::any_eddsa_type", allow-invalid = true, reason = "use tls::load_private_key" },
]
"#;

/// A clippy `disallowed-methods` list for a consumer's own code: the list this repository lints
/// its own code with, refusing rustls's stock builders and verifiers and direct calls into a
/// provider. Merge it into the `clippy.toml` beside the consumer's `Cargo.toml`. Clippy lints only
/// the crates it is run on, never their dependencies. The list is the same for every profile.
pub fn clippy_toml() -> String {
    format!(
        "# clippy `disallowed-methods` for code that uses crypto-profile, generated by\n\
         # `crypto_profile::enforcement::clippy_toml`. Merge it into your clippy.toml.\n\
         {DISALLOWED_METHODS}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::{KdfAlgorithm, MacAlgorithm, TlsVersion};
    use crate::capability::{Linkage, Module, ModuleLine};
    use crate::profile::{Options, select, select_admitted};
    use std::path::PathBuf;

    fn every_algorithm() -> Vec<Algorithm> {
        (S::ALL.iter().map(|x| Algorithm::Signature(*x)))
            .chain(T::ALL.iter().map(|x| Algorithm::Scheme(*x)))
            .chain(K::ALL.iter().map(|x| Algorithm::Kx(*x)))
            .chain(C::ALL.iter().map(|x| Algorithm::Cipher(*x)))
            .chain(H::ALL.iter().map(|x| Algorithm::Hash(*x)))
            .chain(TlsVersion::ALL.iter().map(|x| Algorithm::Protocol(*x)))
            .chain(MacAlgorithm::ALL.iter().map(|x| Algorithm::Mac(*x)))
            .chain(KdfAlgorithm::ALL.iter().map(|x| Algorithm::Kdf(*x)))
            .chain(E::ALL.iter().map(|x| Algorithm::KeyAgreement(*x)))
            .chain(A::ALL.iter().map(|x| Algorithm::Aead(*x)))
            .collect()
    }

    /// The primitives an algorithm's name spells, a derivation independent of `primitives`. A
    /// hybrid group's name spells ML-KEM and its curve; it admits ML-KEM only.
    fn by_name(a: Algorithm) -> Vec<Primitive> {
        let name = format!("{a:?}").to_lowercase();
        if name.contains("mlkem") {
            return vec![P::MlKem];
        }
        [
            ("p256", P::P256),
            ("p384", P::P384),
            ("p521", P::P521),
            ("x25519", P::X25519),
            ("ed25519", P::Ed25519),
            ("rsa", P::Rsa),
            ("chacha", P::ChaCha20Poly1305),
            ("sha3_", P::Sha3),
            ("mlkem", P::MlKem),
            ("mldsa", P::MlDsa),
        ]
        .into_iter()
        .filter(|(spelled, _)| name.contains(spelled))
        .map(|(_, p)| p)
        .collect()
    }

    #[test]
    fn every_algorithm_uses_the_primitives_its_name_spells() {
        let all = every_algorithm();
        assert_eq!(all.len(), 63);
        for a in all {
            let mut got = primitives(a).to_vec();
            let mut want = by_name(a);
            got.sort_by_key(|p| *p as u8);
            want.sort_by_key(|p| *p as u8);
            assert_eq!(got, want, "{a:?}");
        }
    }

    fn refused(profile: Profile) -> Vec<&'static str> {
        ALGORITHM_CRATES
            .iter()
            .filter(|(_, uses, _)| !uses.iter().any(|p| admits(profile.spec(), *p)))
            .map(|(krate, _, _)| *krate)
            .collect()
    }

    #[test]
    fn each_profile_refuses_the_crates_for_algorithms_it_does_not_admit() {
        let cases: [(Profile, &[&str]); 7] = [
            (Profile::Unrestricted, &[]),
            (
                Profile::Preferred,
                &[
                    "x25519-dalek",
                    "ed25519-dalek",
                    "ed25519",
                    "curve25519-dalek",
                    "chacha20poly1305",
                    "chacha20",
                    "poly1305",
                    "sha3",
                ],
            ),
            (
                Profile::Cnsa2,
                &[
                    "p256",
                    "p384",
                    "p521",
                    "x25519-dalek",
                    "ed25519-dalek",
                    "ed25519",
                    "curve25519-dalek",
                    "rsa",
                    "chacha20poly1305",
                    "chacha20",
                    "poly1305",
                    "sha3",
                ],
            ),
            (
                Profile::Cnsa1,
                &[
                    "p256",
                    "p521",
                    "x25519-dalek",
                    "ed25519-dalek",
                    "ed25519",
                    "curve25519-dalek",
                    "chacha20poly1305",
                    "chacha20",
                    "poly1305",
                    "sha3",
                    "ml-kem",
                    "ml-dsa",
                ],
            ),
            (
                Profile::Bsi,
                &[
                    "x25519-dalek",
                    "ed25519-dalek",
                    "ed25519",
                    "curve25519-dalek",
                    "chacha20poly1305",
                    "chacha20",
                    "poly1305",
                    "ml-kem",
                    "ml-dsa",
                ],
            ),
            (
                Profile::Fips1403,
                &["x25519-dalek", "chacha20poly1305", "chacha20", "poly1305"],
            ),
            (
                Profile::Fips1402,
                &[
                    "x25519-dalek",
                    "ed25519-dalek",
                    "ed25519",
                    "curve25519-dalek",
                    "chacha20poly1305",
                    "chacha20",
                    "poly1305",
                    "ml-kem",
                    "ml-dsa",
                ],
            ),
        ];
        for (profile, want) in cases {
            assert_eq!(refused(profile), want, "{profile}");
        }
    }

    fn admitted(algorithms: impl IntoIterator<Item = Algorithm>) -> Vec<Primitive> {
        let mut out: Vec<Primitive> = Vec::new();
        for a in algorithms {
            for p in primitives(a) {
                if !out.contains(p) {
                    out.push(*p);
                }
            }
        }
        out
    }

    #[test]
    fn no_option_admits_a_primitive_its_profile_lacks() {
        let modules = [ModuleLine::AwsLcFips3, ModuleLine::AwsLcFips4]
            .into_iter()
            .flat_map(|line| {
                [Linkage::Static, Linkage::Dynamic].map(|linkage| Module { line, linkage })
            });
        let mut checked = 0;
        for module in modules {
            for profile in Profile::ALL.iter().copied() {
                let base = admitted(algorithms(profile.spec()));
                for bits in 0..8u8 {
                    let options = Options {
                        pq_key_exchange_required: bits & 1 != 0,
                        peer_certificates_match_profile: bits & 2 != 0,
                        cnsa1_unclassified_nss: bits & 4 != 0,
                    };
                    let mut seen: Vec<Algorithm> = Vec::new();
                    if let Ok(s) = select(profile, options, module) {
                        seen.extend(s.versions.iter().map(|x| Algorithm::Protocol(*x)));
                        seen.extend(s.cipher_suites.iter().map(|x| Algorithm::Cipher(*x)));
                        seen.extend(s.kx_groups.iter().map(|x| Algorithm::Kx(*x)));
                        seen.extend(s.signature_schemes.iter().map(|x| Algorithm::Scheme(*x)));
                        seen.extend(s.key_algorithms.iter().map(|x| Algorithm::Signature(*x)));
                        checked += 1;
                    }
                    let a = select_admitted(profile, options, module);
                    seen.extend(a.macs.iter().map(|x| Algorithm::Mac(*x)));
                    seen.extend(a.kdfs.iter().map(|x| Algorithm::Kdf(*x)));
                    seen.extend(a.key_agreements.iter().map(|x| Algorithm::KeyAgreement(*x)));
                    seen.extend(a.aeads.iter().map(|x| Algorithm::Aead(*x)));
                    seen.extend(a.hashes.iter().map(|x| Algorithm::Hash(*x)));
                    seen.extend(a.signatures.iter().map(|x| Algorithm::Signature(*x)));
                    for p in admitted(seen) {
                        assert!(base.contains(&p), "{profile} {options} {module:?}: {p:?}");
                    }
                }
            }
        }
        assert!(checked > 0);
    }

    fn committed(file: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("enforcement")
            .join(file)
    }

    /// Compares a committed file with the generator, or rewrites it when
    /// `CRYPTO_PROFILE_REGENERATE` is set.
    fn check(file: &str, generated: &str) {
        let path = committed(file);
        if std::env::var_os("CRYPTO_PROFILE_REGENERATE").is_some() {
            std::fs::write(&path, generated).unwrap();
            return;
        }
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            on_disk == generated,
            "{} differs from the generator; run CRYPTO_PROFILE_REGENERATE=1 cargo test -p crypto-profile enforcement",
            path.display()
        );
    }

    #[test]
    fn the_committed_files_are_the_generators_output() {
        for profile in Profile::ALL.iter().copied() {
            check(&format!("deny-{profile}.toml"), &deny_toml(profile));
        }
        check("clippy.toml", &clippy_toml());
    }

    #[test]
    fn the_clippy_list_is_the_one_this_repository_lints_itself_with() {
        let ours = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../clippy.toml");
        let ours = std::fs::read_to_string(ours).unwrap();
        assert!(ours.ends_with(DISALLOWED_METHODS));
    }

    #[test]
    fn every_profile_refuses_the_same_libraries_wrappers_and_features() {
        for profile in Profile::ALL.iter().copied() {
            let toml = deny_toml(profile);
            assert!(toml.contains(
                "{ crate = \"ring\", reason = \"ring, beside the AWS-LC FIPS module\" },"
            ));
            assert!(toml.contains("{ crate = \"aws-lc-rs\", wrappers = [\"crypto-profile-awslc4\", \"crypto-profile-awslc3\", \"rcgen\"], reason = "));
            assert!(toml.contains("{ crate = \"rustls\", deny-multiple-versions = true, "));
            assert!(toml.contains("[graph]\nall-features = true\nexclude-dev = true\n"));
            assert!(
                toml.contains("{ crate = \"md-5\", reason = \"MD5, which no profile admits\" },")
            );
            assert!(toml.contains("[[bans.features]]\ncrate = \"rustls\"\ndeny = [\"aws_lc_rs\", \"aws-lc-rs\", \"fips\", \"ring\"]\n"));
        }
    }
}
