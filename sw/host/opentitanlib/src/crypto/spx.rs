// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, anyhow, bail, ensure};
// opentitanlib does not depend on `pkcs8`/`spki` directly; use the copies
// re-exported through `ecdsa` so that all of the key handling in this crate
// agrees on one version of the `der` crate family.
use ecdsa::elliptic_curve::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use serde::{Deserialize, Serialize};
use serde_annotate::Annotate;
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;
use zeroize::Zeroizing;

use super::Error;
use sphincsplus::{DecodeKey, EncodeKey, SphincsPlus, SpxPublicKey, SpxSecretKey};

/// Every algorithm that can appear in a key file, in the order in which the
/// loaders try them.  This must list all of the `SphincsPlus` variants; the
/// `with_slh_dsa_params!` dispatch below will fail to compile if a variant is
/// added without being handled here as well.
const ALGORITHMS: &[SphincsPlus] = &[SphincsPlus::Shake128sSimple, SphincsPlus::Sha2128sSimple];

/// Evaluates `$body` with the type name `$params` bound to the `slh_dsa`
/// parameter set that corresponds to the `SphincsPlus` variant `$algorithm`.
///
/// Since this expands to a `match`, every arm has to produce the same type:
/// `$body` can use the (algorithm dependent) `slh_dsa` key types, but must
/// convert them to something algorithm independent before yielding them.
macro_rules! with_slh_dsa_params {
    ($algorithm:expr, |$params:ident| $body:block) => {
        match $algorithm {
            SphincsPlus::Shake128sSimple => {
                type $params = slh_dsa::Shake128s;
                $body
            }
            SphincsPlus::Sha2128sSimple => {
                type $params = slh_dsa::Sha2_128s;
                $body
            }
        }
    };
}

#[derive(
    Default,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum SpxKeyFormat {
    /// Proprietary OpenTitan RAW PEM format.
    #[default]
    #[serde(rename = "pem")]
    Pem,
    /// Standard PEM format: PKCS#8 for private keys, SubjectPublicKeyInfo for public keys.
    #[serde(rename = "pkcs8-pem")]
    Pkcs8Pem,
    /// Standard DER format: PKCS#8 for private keys, SubjectPublicKeyInfo for public keys.
    #[serde(rename = "pkcs8-der")]
    Pkcs8Der,
}

impl std::fmt::Display for SpxKeyFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pem => write!(f, "pem"),
            Self::Pkcs8Pem => write!(f, "pkcs8-pem"),
            Self::Pkcs8Der => write!(f, "pkcs8-der"),
        }
    }
}

impl SpxKeyFormat {
    /// Standard file extension for a private key in this format ("pem" or "der").
    pub fn ext(&self) -> &'static str {
        match self {
            Self::Pem | Self::Pkcs8Pem => "pem",
            Self::Pkcs8Der => "der",
        }
    }
    /// Standard file extension for a public key in this format ("pub.pem" or "pub.der").
    pub fn pub_ext(&self) -> &'static str {
        match self {
            Self::Pem | Self::Pkcs8Pem => "pub.pem",
            Self::Pkcs8Der => "pub.der",
        }
    }
}

/// Returns `data` as a string if it looks like a PEM document.
fn as_pem(data: &[u8]) -> Option<&str> {
    let s = std::str::from_utf8(data).ok()?;
    s.trim_start().starts_with("-----BEGIN").then_some(s)
}

/// Builds the error message for a key that no supported format could decode.
///
/// Since the format is discovered by trial and error, a bare "unsupported
/// format" would hide the reason each attempt failed, which for a PEM file is
/// usually as specific as "bad public key length" or a mismatched label.
fn parse_failure(kind: &str, data: &[u8], attempts: &[String]) -> String {
    let description = match as_pem(data) {
        // The label alone often identifies the problem, e.g. an ECDSA key that
        // was passed where an SPX key was expected.
        Some(pem) => format!("{:?}", pem.lines().next().unwrap_or_default().trim()),
        None => format!("{} bytes of non-PEM data", data.len()),
    };
    let mut message =
        format!("Failed to parse SPHINCS+/SLH-DSA {kind} key from {description}; tried:");
    for attempt in attempts {
        message.push_str("\n  ");
        message.push_str(attempt);
    }
    message
}

/// Decodes a PKCS#8 (PEM or DER) secret key of the given algorithm.
fn secret_key_from_pkcs8(algorithm: SphincsPlus, data: &[u8]) -> Result<SpxSecretKey> {
    // `slh_dsa` 0.0.3 does not zeroize its own key material, so this only
    // covers the copy that opentitanlib is responsible for.
    let key = with_slh_dsa_params!(algorithm, |Params| {
        let sk = match as_pem(data) {
            Some(pem) => slh_dsa::SigningKey::<Params>::from_pkcs8_pem(pem),
            None => slh_dsa::SigningKey::<Params>::from_pkcs8_der(data),
        }?;
        Zeroizing::new(sk.to_bytes().to_vec())
    });
    SpxSecretKey::from_bytes(algorithm, &key).map_err(|e| anyhow!(e))
}

/// Decodes a SubjectPublicKeyInfo (PEM or DER) public key of the given algorithm.
fn public_key_from_spki(algorithm: SphincsPlus, data: &[u8]) -> Result<SpxPublicKey> {
    let key = with_slh_dsa_params!(algorithm, |Params| {
        let vk = match as_pem(data) {
            Some(pem) => slh_dsa::VerifyingKey::<Params>::from_public_key_pem(pem),
            None => slh_dsa::VerifyingKey::<Params>::from_public_key_der(data),
        }?;
        vk.to_bytes().to_vec()
    });
    SpxPublicKey::from_bytes(algorithm, &key).map_err(|e| anyhow!(e))
}

/// Load a SPHINCS+/SLH-DSA secret key from a file.
/// Supports OpenTitan proprietary PEM format, standard PKCS#8 PEM, and standard PKCS#8 DER.
pub fn load_spx_secret_key(path: impl AsRef<Path>) -> Result<SpxSecretKey> {
    let path = path.as_ref();
    let data = std::fs::read(path).with_context(|| format!("Failed to read file: {path:?}"))?;
    load_spx_secret_key_from_bytes(&data)
        .with_context(|| format!("Failed to load SPHINCS+/SLH-DSA secret key from {path:?}"))
}

/// Load a SPHINCS+/SLH-DSA secret key from a byte slice.
/// Supports OpenTitan proprietary PEM format, standard PKCS#8 PEM, and standard PKCS#8 DER.
pub fn load_spx_secret_key_from_bytes(data: &[u8]) -> Result<SpxSecretKey> {
    let mut attempts = Vec::new();
    if let Some(pem) = as_pem(data) {
        match SpxSecretKey::from_pem(pem) {
            Ok(key) => return Ok(key),
            Err(e) => attempts.push(format!("proprietary PEM: {e}")),
        }
    }
    for &algorithm in ALGORITHMS {
        match secret_key_from_pkcs8(algorithm, data) {
            Ok(key) => return Ok(key),
            Err(e) => attempts.push(format!("PKCS#8 {algorithm}: {e}")),
        }
    }
    bail!("{}", parse_failure("secret", data, &attempts));
}

/// Load a SPHINCS+/SLH-DSA public key from a file.
/// Supports OpenTitan proprietary PEM format, standard PKCS#8 PEM, standard PKCS#8 DER,
/// and extracting a public key from a secret key file in any supported format.
pub fn load_spx_public_key(path: impl AsRef<Path>) -> Result<SpxPublicKey> {
    let path = path.as_ref();
    let data = std::fs::read(path).with_context(|| format!("Failed to read file: {path:?}"))?;
    load_spx_public_key_from_bytes(&data)
        .with_context(|| format!("Failed to load SPHINCS+/SLH-DSA public key from {path:?}"))
}

/// Load a SPHINCS+/SLH-DSA public key from a byte slice.
/// Supports OpenTitan proprietary PEM format, standard PKCS#8 PEM, standard PKCS#8 DER,
/// and extracting a public key from a secret key in any supported format.
pub fn load_spx_public_key_from_bytes(data: &[u8]) -> Result<SpxPublicKey> {
    let mut attempts = Vec::new();
    // This also covers the proprietary PEM secret key (which embeds the public
    // key) and the ASN.1 form emitted by some HSMs, which the sphincsplus crate
    // recognizes by its HashSLH-DSA OID.
    if let Some(pem) = as_pem(data) {
        match SpxPublicKey::from_pem(pem) {
            Ok(key) => return Ok(key),
            Err(e) => attempts.push(format!("proprietary PEM: {e}")),
        }
    }
    for &algorithm in ALGORITHMS {
        match public_key_from_spki(algorithm, data) {
            Ok(key) => return Ok(key),
            Err(e) => attempts.push(format!("SubjectPublicKeyInfo {algorithm}: {e}")),
        }
    }
    // Fallback: a PKCS#8 secret key also carries its public key.
    for &algorithm in ALGORITHMS {
        match secret_key_from_pkcs8(algorithm, data) {
            Ok(sk) => return Ok(SpxPublicKey::from(&sk)),
            Err(e) => attempts.push(format!("PKCS#8 secret key {algorithm}: {e}")),
        }
    }
    bail!("{}", parse_failure("public", data, &attempts));
}

/// Save a SPHINCS+/SLH-DSA secret key to a file in the specified format.
pub fn save_spx_secret_key(
    key: &SpxSecretKey,
    path: impl AsRef<Path>,
    format: SpxKeyFormat,
) -> Result<()> {
    let path = path.as_ref();
    if format == SpxKeyFormat::Pem {
        return key
            .write_pem_file(path)
            .with_context(|| format!("Failed to write proprietary PEM to {path:?}"));
    }
    with_slh_dsa_params!(key.algorithm(), |Params| {
        let sk = slh_dsa::SigningKey::<Params>::try_from(key.as_bytes())
            .map_err(|e| anyhow!("Failed to convert to slh_dsa SigningKey: {e:?}"))?;
        match format {
            SpxKeyFormat::Pkcs8Pem => sk.write_pkcs8_pem_file(path, LineEnding::default()),
            SpxKeyFormat::Pkcs8Der => sk.write_pkcs8_der_file(path),
            SpxKeyFormat::Pem => unreachable!("handled above"),
        }
        .with_context(|| format!("Failed to write {format} to {path:?}"))
    })
}

/// Save a SPHINCS+/SLH-DSA public key to a file in the specified format.
pub fn save_spx_public_key(
    key: &SpxPublicKey,
    path: impl AsRef<Path>,
    format: SpxKeyFormat,
) -> Result<()> {
    let path = path.as_ref();
    if format == SpxKeyFormat::Pem {
        return key
            .write_pem_file(path)
            .with_context(|| format!("Failed to write proprietary PEM to {path:?}"));
    }
    with_slh_dsa_params!(key.algorithm(), |Params| {
        let vk = slh_dsa::VerifyingKey::<Params>::try_from(key.as_bytes())
            .map_err(|e| anyhow!("Failed to convert to slh_dsa VerifyingKey: {e:?}"))?;
        match format {
            SpxKeyFormat::Pkcs8Pem => vk.write_public_key_pem_file(path, LineEnding::default()),
            SpxKeyFormat::Pkcs8Der => vk.write_public_key_der_file(path),
            SpxKeyFormat::Pem => unreachable!("handled above"),
        }
        .with_context(|| format!("Failed to write {format} to {path:?}"))
    })
}

#[derive(Debug, Serialize, Deserialize, Annotate, PartialEq)]
pub struct SpxRawPublicKey {
    #[serde(with = "serde_bytes")]
    #[annotate(format = hexstr)]
    pub key: Vec<u8>,
}

impl Default for SpxRawPublicKey {
    fn default() -> Self {
        Self { key: vec![0; 32] }
    }
}

impl TryFrom<&sphincsplus::SpxPublicKey> for SpxRawPublicKey {
    type Error = Error;
    fn try_from(v: &SpxPublicKey) -> Result<Self, Self::Error> {
        Ok(Self {
            key: v.as_bytes().to_vec(),
        })
    }
}

impl TryFrom<sphincsplus::SpxPublicKey> for SpxRawPublicKey {
    type Error = Error;
    fn try_from(v: SpxPublicKey) -> Result<Self, Self::Error> {
        (&v).try_into()
    }
}

impl FromStr for SpxRawPublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key = load_spx_public_key(s)
            .with_context(|| format!("Failed to load {s}"))
            .map_err(Error::Other)?;
        SpxRawPublicKey::try_from(&key)
    }
}

impl SpxRawPublicKey {
    pub const SIZE: usize = 32;
    pub fn read(src: &mut impl Read) -> Result<Self> {
        let mut key = Self::default();
        key.key.resize(32, 0);
        src.read_exact(&mut key.key)?;
        Ok(key)
    }
    pub fn write(&self, dest: &mut impl Write) -> Result<()> {
        ensure!(
            self.key.len() == Self::SIZE,
            Error::InvalidPublicKey(anyhow!("bad key length: {}", self.key.len()))
        );
        dest.write_all(&self.key)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::util::tmpfilename;
    use sphincsplus::SpxDomain;

    /// A throwaway SLH-DSA-SHA2-128s key pair in the proprietary OpenTitan PEM
    /// format, as written by `opentitantool spx key generate --format pem`.
    const PROPRIETARY_SK_PEM: &str = "-----BEGIN RAW:SLH_DSA_SHA2_128s PRIVATE KEY-----\n\
        6bjY0UDbmzL4TnTVYwINqOCrxxyGNC8hJXMzKB9WDNfaSaVWNOfNyXSDc9opKeh2\n\
        dNVIlMTKhAWCYUnLhZ0gsw==\n\
        -----END RAW:SLH_DSA_SHA2_128s PRIVATE KEY-----\n";
    const PROPRIETARY_PK_PEM: &str = "-----BEGIN RAW:SLH_DSA_SHA2_128s PUBLIC KEY-----\n\
        2kmlVjTnzcl0g3PaKSnodnTVSJTEyoQFgmFJy4WdILM=\n\
        -----END RAW:SLH_DSA_SHA2_128s PUBLIC KEY-----\n";
    /// The same public key as a SubjectPublicKeyInfo whose AlgorithmIdentifier
    /// carries the HashSLH-DSA-SHA2-128s-with-SHA256 OID
    /// (2.16.840.1.101.3.4.3.35), which is what some HSMs hand out.
    const HSM_SPKI_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MDAwCwYJYIZIAWUDBAMjAyEA2kmlVjTnzcl0g3PaKSnodnTVSJTEyoQFgmFJy4Wd\n\
        ILM=\n\
        -----END PUBLIC KEY-----\n";
    const PK_HEX: &str = "da49a55634e7cdc9748373da2929e87674d54894c4ca8405826149cb859d20b3";

    #[test]
    fn test_proprietary_pem_vectors() -> Result<()> {
        let pk = load_spx_public_key_from_bytes(PROPRIETARY_PK_PEM.as_bytes())?;
        assert_eq!(pk.algorithm(), SphincsPlus::Sha2128sSimple);
        assert_eq!(hex::encode(pk.as_bytes()), PK_HEX);

        // A secret key embeds its public key, so either file names the same key.
        let sk = load_spx_secret_key_from_bytes(PROPRIETARY_SK_PEM.as_bytes())?;
        assert_eq!(SpxPublicKey::from(&sk), pk);
        assert_eq!(
            load_spx_public_key_from_bytes(PROPRIETARY_SK_PEM.as_bytes())?,
            pk
        );

        // The keys checked into sw/device/silicon_creator were written before
        // the algorithm's display name changed and still use the old label.
        let legacy =
            |pem: &str| pem.replace("RAW:SLH_DSA_SHA2_128s", "RAW:SPHINCS+_SHA2_128s_simple");
        assert_eq!(
            load_spx_public_key_from_bytes(legacy(PROPRIETARY_PK_PEM).as_bytes())?,
            pk
        );
        assert_eq!(
            load_spx_secret_key_from_bytes(legacy(PROPRIETARY_SK_PEM).as_bytes())?,
            sk
        );

        // A public key must not satisfy a request for a secret key.
        assert!(load_spx_secret_key_from_bytes(PROPRIETARY_PK_PEM.as_bytes()).is_err());
        Ok(())
    }

    #[test]
    fn test_hsm_spki_vector() -> Result<()> {
        let pk = load_spx_public_key_from_bytes(HSM_SPKI_PEM.as_bytes())?;
        assert_eq!(pk.algorithm(), SphincsPlus::Sha2128sSimple);
        assert_eq!(hex::encode(pk.as_bytes()), PK_HEX);

        // The pure SLH-DSA OIDs do not cover this key, so it is the sphincsplus
        // ASN.1 fallback rather than the slh_dsa decoder that accepts it.
        assert!(
            public_key_from_spki(SphincsPlus::Sha2128sSimple, HSM_SPKI_PEM.as_bytes()).is_err()
        );
        Ok(())
    }

    #[test]
    fn test_spx_format_roundtrip() -> Result<()> {
        for algorithm in [SphincsPlus::Shake128sSimple, SphincsPlus::Sha2128sSimple] {
            let (sk, pk) = SpxSecretKey::new_keypair(algorithm)?;

            for format in [
                SpxKeyFormat::Pem,
                SpxKeyFormat::Pkcs8Pem,
                SpxKeyFormat::Pkcs8Der,
            ] {
                let sk_path = tmpfilename(&format!("test_sk_{:?}.{}", algorithm, format.ext()));
                let pk_path = tmpfilename(&format!("test_pk_{:?}.{}", algorithm, format.pub_ext()));

                save_spx_secret_key(&sk, &sk_path, format)?;
                save_spx_public_key(&pk, &pk_path, format)?;

                let loaded_sk = load_spx_secret_key(&sk_path)?;
                let loaded_pk = load_spx_public_key(&pk_path)?;

                assert_eq!(loaded_sk, sk);
                assert_eq!(loaded_pk, pk);

                // Test extracting public key from secret key file
                let extracted_pk = load_spx_public_key(&sk_path)?;
                assert_eq!(extracted_pk, pk);
            }
        }
        Ok(())
    }

    #[test]
    fn test_reject_non_spx_key() {
        // A key of the wrong algorithm should say so, rather than reporting a
        // bare "unsupported format".
        let error = load_spx_public_key_from_bytes(
            b"-----BEGIN EC PRIVATE KEY-----\nAA==\n-----END EC PRIVATE KEY-----\n",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("EC PRIVATE KEY"), "{error}");
        assert!(error.contains("proprietary PEM"), "{error}");

        let error = load_spx_secret_key_from_bytes(&[0u8; 64])
            .unwrap_err()
            .to_string();
        assert!(error.contains("64 bytes of non-PEM data"), "{error}");
    }

    #[test]
    fn test_pkcs8_sign_verify() -> Result<()> {
        let algorithm = SphincsPlus::Shake128sSimple;
        let (sk, pk) = SpxSecretKey::new_keypair(algorithm)?;

        let sk_path = tmpfilename("test_pkcs8_sk.der");
        let pk_path = tmpfilename("test_pkcs8_pk.der");

        save_spx_secret_key(&sk, &sk_path, SpxKeyFormat::Pkcs8Der)?;
        save_spx_public_key(&pk, &pk_path, SpxKeyFormat::Pkcs8Der)?;

        let loaded_sk = load_spx_secret_key(&sk_path)?;
        let loaded_pk = load_spx_public_key(&pk_path)?;

        let msg = b"OpenTitan SLH-DSA PKCS#8 test message";
        let sig = loaded_sk.sign(SpxDomain::Pure, msg)?;
        loaded_pk.verify(SpxDomain::Pure, &sig, msg)?;
        Ok(())
    }
}
