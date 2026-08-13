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
    /// Standard PKCS#8 PEM format.
    #[serde(rename = "pkcs8-pem")]
    Pkcs8Pem,
    /// Standard PKCS#8 DER format.
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
    if let Some(pem) = as_pem(data) {
        if let Ok(key) = SpxSecretKey::from_pem(pem) {
            return Ok(key);
        }
    }
    for &algorithm in ALGORITHMS {
        if let Ok(key) = secret_key_from_pkcs8(algorithm, data) {
            return Ok(key);
        }
    }
    bail!(
        "Failed to parse SPHINCS+/SLH-DSA secret key (supported formats: proprietary PEM, PKCS#8 PEM, PKCS#8 DER)"
    );
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
    // This also covers the ASN.1 form emitted by some HSMs, which the
    // sphincsplus crate recognizes by its HashSLH-DSA OID.
    if let Some(pem) = as_pem(data) {
        if let Ok(key) = SpxPublicKey::from_pem(pem) {
            return Ok(key);
        }
    }
    for &algorithm in ALGORITHMS {
        if let Ok(key) = public_key_from_spki(algorithm, data) {
            return Ok(key);
        }
    }
    // Fallback: try loading as a secret key and converting to public key
    if let Ok(sk) = load_spx_secret_key_from_bytes(data) {
        return Ok(SpxPublicKey::from(&sk));
    }
    bail!(
        "Failed to parse SPHINCS+/SLH-DSA public key (supported formats: proprietary PEM, PKCS#8 PEM, PKCS#8 DER)"
    );
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
