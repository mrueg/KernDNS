//! DNSSEC key pairs read from BIND-style key files (`K<name>+<alg>+<id>.key`
//! and `.private`), and RRSIG creation. Shared by `dnssec` and `sign`.
//!
//! Port of `plugin/dnssec/dnskey.go` (`ParseKeyFile`) and miekg/dns's
//! `ReadPrivateKey` and `RRSIG.Sign`. The cryptography is ring's, the same
//! library hickory-proto (`dnssec-ring`) and rustls use.

use std::path::Path;
use std::sync::Arc;

use kerndns_core::proto::dnssec::rdata::sig::SigInput;
use kerndns_core::proto::dnssec::rdata::{DNSKEY, DNSSECRData, RRSIG};
use kerndns_core::proto::dnssec::{Algorithm, PublicKey, TBS};
use kerndns_core::proto::rr::{Name, RData, Record, RecordType, SerialNumber};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair, RsaKeyPair};

use crate::file::zonefile::new_rr;

/// A private key that can sign.
enum PrivateKey {
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
    Rsa(RsaKeyPair, &'static dyn signature::RsaEncoding),
    /// Always fails (tests).
    #[cfg(test)]
    Broken,
}

/// A DNSSEC key pair: the public DNSKEY record and its private key, like
/// `dnssec.DNSKEY` and `sign.Pair`.
#[derive(Clone)]
pub struct Key {
    /// The DNSKEY record as read from the `.key` file.
    pub record: Record,
    pub tag: u16,
    private: Arc<PrivateKey>,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("name", &self.record.name)
            .field("flags", &self.flags())
            .field("tag", &self.tag)
            .finish()
    }
}

impl Key {
    pub fn dnskey(&self) -> &DNSKEY {
        match &self.record.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(k)) => k,
            _ => unreachable!("Key always holds a DNSKEY"),
        }
    }

    pub fn flags(&self) -> u16 {
        self.dnskey().flags()
    }

    pub fn algorithm(&self) -> Algorithm {
        self.dnskey().public_key().algorithm()
    }

    /// A zone key with the SEP bit unset (RFC 4034 2.1.1), `isZSK`.
    pub fn is_zsk(&self) -> bool {
        self.flags() & (1 << 8) != 0 && self.flags() & 1 == 0
    }

    /// A zone key with the SEP bit set (RFC 4034 2.1.1), `isKSK`.
    pub fn is_ksk(&self) -> bool {
        self.flags() & (1 << 8) != 0 && self.flags() & 1 == 1
    }

    /// This key with a private key that always fails to sign (tests).
    #[cfg(test)]
    pub fn broken(&self) -> Key {
        Key {
            record: self.record.clone(),
            tag: self.tag.wrapping_add(1),
            private: Arc::new(PrivateKey::Broken),
        }
    }

    fn sign_bytes(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let rng = SystemRandom::new();
        match &*self.private {
            PrivateKey::Ecdsa(k) => k
                .sign(&rng, data)
                .map(|s| s.as_ref().to_vec())
                .map_err(|_| "ECDSA signing failed".to_string()),
            PrivateKey::Ed25519(k) => Ok(k.sign(data).as_ref().to_vec()),
            PrivateKey::Rsa(k, enc) => {
                let mut sig = vec![0; k.public().modulus_len()];
                k.sign(*enc, &rng, data, &mut sig)
                    .map_err(|_| "RSA signing failed".to_string())?;
                Ok(sig)
            }
            #[cfg(test)]
            PrivateKey::Broken => Err("simulated signing failure".to_string()),
        }
    }

    /// Sign `rrs` (one RRset) like miekg/dns's `RRSIG.Sign`: the RRSIG gets
    /// the RRset's owner and class, `ttl` as its own TTL and `orig_ttl` as
    /// the Original TTL, and its label count excludes a leading wildcard.
    pub fn sign(
        &self,
        rrs: &[Record],
        signer: &Name,
        ttl: u32,
        orig_ttl: u32,
        inception: u32,
        expiration: u32,
    ) -> Result<Record, String> {
        let first = rrs.first().ok_or("no records to sign")?;
        let input = SigInput {
            type_covered: first.record_type(),
            algorithm: self.algorithm(),
            num_labels: first.name.num_labels(),
            original_ttl: orig_ttl,
            sig_expiration: SerialNumber::new(expiration),
            sig_inception: SerialNumber::new(inception),
            key_tag: self.tag,
            signer_name: signer.clone(),
        };
        let tbs = TBS::from_input(&first.name, first.dns_class, &input, rrs.iter()).map_err(|e| e.to_string())?;
        let sig = self.sign_bytes(tbs.as_ref())?;
        let mut r = Record::from_rdata(
            first.name.clone(),
            ttl,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, sig))),
        );
        r.dns_class = first.dns_class;
        Ok(r)
    }
}

/// `ParseKeyFile`: read the DNSKEY in `public` and the private key in
/// `private`.
pub fn parse_key_file(public: &Path, private: &Path) -> Result<Key, String> {
    let pubtext = std::fs::read_to_string(public).map_err(|e| open_error(public, &e))?;
    let record = new_rr(&pubtext)
        .map_err(|e| format!("{}: {e}", public.display()))?
        .filter(|r| r.record_type() == RecordType::DNSKEY)
        .ok_or_else(|| "no public key found".to_string())?;
    let privtext = std::fs::read_to_string(private).map_err(|e| open_error(private, &e))?;
    key_from_parts(record, &privtext)
}

fn open_error(path: &Path, e: &std::io::Error) -> String {
    let msg = match e.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        _ => e.to_string(),
    };
    format!("open {}: {msg}", path.display())
}

/// Combine a DNSKEY record with the private key text (`Private-key-format:
/// v1.x`), like miekg/dns's `DNSKEY.ReadPrivateKey`.
pub fn key_from_parts(record: Record, private: &str) -> Result<Key, String> {
    let RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) = &record.data else {
        return Err("no public key found".into());
    };
    let tag = dnskey.calculate_key_tag().map_err(|e| e.to_string())?;
    let m = read_private_fields(private)?;
    let alg = dnskey.public_key().algorithm();
    if m.get("private-key-format").is_none_or(|v| !v.starts_with("v1.")) {
        return Err("bad private key".into());
    }
    let file_alg: u8 = m
        .get("algorithm")
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .ok_or("bad private key")?;
    if file_alg != u8::from(alg) {
        return Err("bad private key".into());
    }
    let b64 = |k: &str| -> Result<Vec<u8>, String> {
        let v = m.get(k).ok_or("bad private key")?;
        data_encoding::BASE64
            .decode(v.as_bytes())
            .map_err(|_| "bad private key".to_string())
    };
    let public = dnskey.public_key().public_bytes();
    let rng = SystemRandom::new();
    let private = match alg {
        Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => {
            let ring_alg = if alg == Algorithm::ECDSAP256SHA256 {
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING
            } else {
                &signature::ECDSA_P384_SHA384_FIXED_SIGNING
            };
            let mut point = vec![4u8];
            point.extend_from_slice(public);
            let k = EcdsaKeyPair::from_private_key_and_public_key(ring_alg, &b64("privatekey")?, &point, &rng)
                .map_err(|e| format!("bad private key: {e}"))?;
            PrivateKey::Ecdsa(k)
        }
        Algorithm::ED25519 => {
            let k = Ed25519KeyPair::from_seed_and_public_key(&b64("privatekey")?, public)
                .map_err(|e| format!("bad private key: {e}"))?;
            PrivateKey::Ed25519(k)
        }
        Algorithm::RSASHA256 | Algorithm::RSASHA512 => {
            let enc: &'static dyn signature::RsaEncoding = if alg == Algorithm::RSASHA256 {
                &signature::RSA_PKCS1_SHA256
            } else {
                &signature::RSA_PKCS1_SHA512
            };
            let comps = ring::rsa::KeyPairComponents {
                public_key: ring::rsa::PublicKeyComponents {
                    n: b64("modulus")?,
                    e: b64("publicexponent")?,
                },
                d: b64("privateexponent")?,
                p: b64("prime1")?,
                q: b64("prime2")?,
                dP: b64("exponent1")?,
                dQ: b64("exponent2")?,
                qInv: b64("coefficient")?,
            };
            let k = RsaKeyPair::from_components(&comps)
                .map_err(|e| format!("bad private key: {e} (ring signs with 2048 to 8192-bit RSA keys)"))?;
            PrivateKey::Rsa(k, enc)
        }
        other => {
            return Err(format!(
                "unsupported algorithm {} ({}) for signing: KernDNS signs with RSASHA256, RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384 and ED25519",
                u8::from(other),
                other.as_str()
            ));
        }
    };
    Ok(Key {
        record,
        tag,
        private: Arc::new(private),
    })
}

/// The `Key: value` lines of a private key file, keys lowercased.
fn read_private_fields(text: &str) -> Result<std::collections::HashMap<String, String>, String> {
    let mut m = std::collections::HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            return Err("bad private key".into());
        };
        m.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
    }
    Ok(m)
}

/// `RRSIG.ValidityPeriod`: is `t` (Unix seconds) within the signature's
/// inception and expiration, with RFC 1982 serial arithmetic?
pub fn validity_period(sig: &RRSIG, t: i64) -> bool {
    const YEAR68: i64 = 1 << 31;
    let incep = i64::from(sig.input().sig_inception.get());
    let expir = i64::from(sig.input().sig_expiration.get());
    let modi = (incep - t) / YEAR68;
    let mode = (expir - t) / YEAR68;
    let ti = incep + modi * YEAR68;
    let te = expir + mode * YEAR68;
    ti <= t && t <= te
}
