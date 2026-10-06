//! NIP-01, NIP-19, NIP-OA, NIP-42 and NIP-98, without transport I/O.

use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use bech32::{Bech32, Hrp, primitives::decode::CheckedHrpstring};
use hkdf::Hkdf;
use k256::schnorr::{Signature, SigningKey, VerifyingKey, signature::hazmat::PrehashSigner};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A validated scalar. Debug deliberately never reveals key material.
#[derive(Clone)]
pub struct SecretKey(k256::SecretKey);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

impl SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        k256::SecretKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| anyhow!("invalid secp256k1 secret key"))
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_slice(&self.0.to_bytes()).expect("validated scalar")
    }
}

pub fn canonical_name(name: &str, device: &str) -> Result<String> {
    if name.is_empty() || name.chars().any(identity_whitespace) {
        bail!("hcom name must be non-empty and contain no whitespace");
    }
    if !name.is_ascii() || name.contains(['|', '&', ';', '$', '`', '<', '>']) {
        bail!("hcom name contains a character hcom rejects");
    }
    Ok(format!("{name}@{}", device_label(device)?))
}

// Python str.isspace also treats the ASCII information separators as space.
fn identity_whitespace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

pub fn device_label(value: &str) -> Result<String> {
    let label = value.trim_matches(identity_whitespace).to_lowercase();
    if label.is_empty()
        || label.len() > 63
        || !label
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        || label.starts_with('-')
        || label.ends_with('-')
    {
        bail!("device name must be a lowercase dns-style label (a-z, 0-9, hyphen)");
    }
    Ok(label)
}

pub fn derive_secret(seed: &[u8; 32], canonical: &str) -> SecretKey {
    let mut material = [0; 32];
    let info = format!("zagcom/hcom-identity/v1:{canonical}");
    Hkdf::<Sha256>::new(None, seed)
        .expand(info.as_bytes(), &mut material)
        .expect("32 bytes fit HKDF-SHA256");
    SecretKey::from_bytes(&reduce_scalar(material)).expect("reduced scalar is in [1,n-1]")
}

// Python uses (material % (n - 1)) + 1, not reduction modulo n. A 256-bit
// material needs at most one subtraction because 2 * (n - 1) exceeds 2^256.
fn reduce_scalar(mut material: [u8; 32]) -> [u8; 32] {
    const N_MINUS_ONE: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x40,
    ];
    if material >= N_MINUS_ONE {
        let mut borrow = false;
        for (byte, modulus) in material.iter_mut().zip(N_MINUS_ONE).rev() {
            let (difference, first) = byte.overflowing_sub(modulus);
            let (difference, second) = difference.overflowing_sub(u8::from(borrow));
            *byte = difference;
            borrow = first || second;
        }
    }
    for byte in material.iter_mut().rev() {
        let (incremented, carry) = byte.overflowing_add(1);
        *byte = incremented;
        if !carry {
            break;
        }
    }
    material
}

pub fn public_hex(key: &SecretKey) -> String {
    hex(&key.signing_key().verifying_key().to_bytes())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

fn unhex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut bytes = [0; N];
    for (out, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let digit = |c: u8| (c as char).to_digit(16).map(|n| n as u8);
        *out = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Some(bytes)
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

#[derive(Debug, Clone)]
pub struct UnsignedEvent {
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

fn event_digest(
    pubkey: &str,
    created_at: u64,
    kind: u16,
    tags: &[Vec<String>],
    content: &str,
) -> [u8; 32] {
    // serde_json emits compact UTF-8 and NIP-01's required JSON escapes.
    let canonical = serde_json::to_vec(&(0, pubkey, created_at, kind, tags, content))
        .expect("event fields serialize");
    Sha256::digest(canonical).into()
}

pub fn sign(unsigned: UnsignedEvent, key: &SecretKey) -> Event {
    let signing = key.signing_key();
    let pubkey = hex(&signing.verifying_key().to_bytes());
    let digest = event_digest(
        &pubkey,
        unsigned.created_at,
        unsigned.kind,
        &unsigned.tags,
        &unsigned.content,
    );
    let signature: Signature = signing.sign_prehash(&digest).expect("BIP-340 signing");
    Event {
        id: hex(&digest),
        pubkey,
        created_at: unsigned.created_at,
        kind: unsigned.kind,
        tags: unsigned.tags,
        content: unsigned.content,
        sig: hex(&signature.to_bytes()),
    }
}

pub fn verify(event: &Event) -> bool {
    let Some(id) = unhex::<32>(&event.id) else {
        return false;
    };
    id == event_digest(
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    ) && verify_signature(&event.pubkey, &event.sig, &id)
}

fn verify_signature(pubkey: &str, signature: &str, digest: &[u8; 32]) -> bool {
    let Some(pubkey) = unhex::<32>(pubkey) else {
        return false;
    };
    let Some(signature) = unhex::<64>(signature) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&pubkey.into()) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(signature.as_slice()) else {
        return false;
    };
    key.verify_raw(digest, &signature).is_ok()
}

pub fn auth_tag(owner: &SecretKey, agent_pubkey_hex: &str, conditions: &str) -> [String; 4] {
    let signing = owner.signing_key();
    let digest = Sha256::digest(format!("nostr:agent-auth:{agent_pubkey_hex}:{conditions}"));
    let signature: Signature = signing.sign_prehash(&digest).expect("BIP-340 signing");
    [
        "auth".into(),
        hex(&signing.verifying_key().to_bytes()),
        conditions.into(),
        hex(&signature.to_bytes()),
    ]
}

fn valid_conditions(conditions: &str) -> bool {
    conditions.is_empty()
        || conditions.split('&').all(|clause| {
            let (decimal, max) = if let Some(n) = clause.strip_prefix("kind=") {
                (n, u16::MAX as u64)
            } else if let Some(n) = clause
                .strip_prefix("created_at<")
                .or_else(|| clause.strip_prefix("created_at>"))
            {
                (n, u32::MAX as u64)
            } else {
                return false;
            };
            !decimal.is_empty()
                && decimal.bytes().all(|c| c.is_ascii_digit())
                && (decimal == "0" || !decimal.starts_with('0'))
                && decimal.parse::<u64>().is_ok_and(|n| n <= max)
        })
}

/// Verifies the credential's signature and grammar; event conditions must be
/// evaluated separately by callers that use it as event provenance.
pub fn verify_auth_tag(tag: &[String], agent_pubkey_hex: &str) -> bool {
    let lowercase_hex = |value: &str, len| {
        value.len() == len
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    };
    if tag.len() != 4
        || tag[0] != "auth"
        || tag[1] == agent_pubkey_hex
        || !lowercase_hex(&tag[1], 64)
        || !lowercase_hex(agent_pubkey_hex, 64)
        || !lowercase_hex(&tag[3], 128)
        || !valid_conditions(&tag[2])
    {
        return false;
    }
    let digest = Sha256::digest(format!("nostr:agent-auth:{agent_pubkey_hex}:{}", tag[2]));
    verify_signature(&tag[1], &tag[3], &digest.into())
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after unix epoch")
        .as_secs()
}

pub fn auth_event(
    key: &SecretKey,
    relay_url: &str,
    challenge: &str,
    tag: Option<[String; 4]>,
) -> Event {
    let mut tags = vec![
        vec!["relay".into(), relay_url.into()],
        vec!["challenge".into(), challenge.into()],
    ];
    if let Some(tag) = tag {
        tags.push(tag.into());
    }
    sign(
        UnsignedEvent {
            created_at: now(),
            kind: 22242,
            tags,
            content: String::new(),
        },
        key,
    )
}

pub fn http_auth_header(key: &SecretKey, url: &str, method: &str, body: &[u8]) -> String {
    let tags = vec![
        vec!["u".into(), url.into()],
        vec!["method".into(), method.into()],
        // The relay rejects repeated auth IDs. Match Python's per-request nonce.
        vec!["nonce".into(), uuid::Uuid::new_v4().to_string()],
        vec!["payload".into(), sha256_hex(body)],
    ];
    let event = sign(
        UnsignedEvent {
            created_at: now(),
            kind: 27235,
            tags,
            content: String::new(),
        },
        key,
    );
    format!(
        "Nostr {}",
        STANDARD.encode(serde_json::to_vec(&event).expect("event serializes"))
    )
}

pub fn encode_npub(pubkey_hex: &str) -> Result<String> {
    let bytes = unhex::<32>(pubkey_hex).ok_or_else(|| anyhow!("invalid npub public key"))?;
    VerifyingKey::from_bytes(&bytes.into()).map_err(|_| anyhow!("invalid npub public key"))?;
    Ok(bech32::encode::<Bech32>(Hrp::parse("npub")?, &bytes)?)
}

pub fn decode_npub(encoded: &str) -> Result<String> {
    let bytes = decode_bech32(encoded, "npub")?;
    VerifyingKey::from_bytes(&bytes.into()).map_err(|_| anyhow!("invalid npub public key"))?;
    Ok(hex(&bytes))
}

pub fn encode_nsec(key: &SecretKey) -> String {
    bech32::encode::<Bech32>(Hrp::parse("nsec").expect("static hrp"), &key.0.to_bytes())
        .expect("fixed size nsec")
}

pub fn decode_nsec(encoded: &str) -> Result<SecretKey> {
    SecretKey::from_bytes(&decode_bech32(encoded, "nsec")?)
}

fn decode_bech32(encoded: &str, expected: &str) -> Result<[u8; 32]> {
    let decoded =
        CheckedHrpstring::new::<Bech32>(encoded).map_err(|_| anyhow!("invalid bech32 key"))?;
    if decoded.hrp().as_str() != expected {
        bail!("incorrect bech32 key prefix");
    }
    decoded
        .validate_segwit_padding()
        .map_err(|_| anyhow!("invalid bech32 key padding"))?;
    let bytes: Vec<_> = decoded.byte_iter().collect();
    bytes
        .try_into()
        .map_err(|_| anyhow!("bech32 key must be 32 bytes"))
}

pub fn load_seed(path: impl AsRef<Path>) -> Result<[u8; 32]> {
    let mut file = File::open(path).map_err(|_| anyhow!("cannot open seed file"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file
            .metadata()
            .map_err(|_| anyhow!("cannot inspect seed file"))?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            bail!("seed file mode must be 0600");
        }
    }
    let mut bytes = [0; 32];
    file.read_exact(&mut bytes)
        .map_err(|_| anyhow!("seed file must be exactly 32 bytes"))?;
    let mut extra = [0];
    if file
        .read(&mut extra)
        .map_err(|_| anyhow!("cannot read seed file"))?
        != 0
    {
        bail!("seed file must be exactly 32 bytes");
    }
    Ok(bytes)
}

pub fn load_owner_key(path: impl AsRef<Path>) -> Result<SecretKey> {
    let file = File::open(path).map_err(|_| anyhow!("cannot open owner key file"))?;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|_| anyhow!("cannot read owner key file"))?;
        let stripped = line.trim_matches(identity_whitespace);
        if stripped.starts_with('#') {
            continue;
        }
        let Some((name, value)) = stripped.split_once('=') else {
            continue;
        };
        if name.trim_matches(identity_whitespace) != "BUZZ_PRIVATE_KEY" {
            continue;
        }
        let value = value
            .trim_matches(identity_whitespace)
            .trim_matches(['\'', '"']);
        return if value.starts_with("nsec1") {
            decode_nsec(value)
        } else {
            // bytes.fromhex permits whitespace between bytes, not nibbles.
            let mut compact = String::with_capacity(64);
            for part in value.split_ascii_whitespace() {
                if part.len() % 2 != 0 {
                    bail!("owner key must be valid 32-byte hex or nsec");
                }
                compact.push_str(part);
            }
            let raw = unhex::<32>(&compact)
                .ok_or_else(|| anyhow!("owner key must be valid 32-byte hex or nsec"))?;
            SecretKey::from_bytes(&raw)
        };
    }
    bail!("owner key file does not define BUZZ_PRIVATE_KEY")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_seed() -> [u8; 32] {
        std::array::from_fn(|i| (i + 1) as u8)
    }
    fn test_owner() -> SecretKey {
        let mut bytes = [0; 32];
        bytes[31] = 3;
        SecretKey::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn python_cross_implementation_vectors() {
        // Generated once with the deployed bridge's Python implementation,
        // seed bytes 01..20 and TEST owner scalar 3. Python uses random aux.
        for (canonical, expected) in [
            (
                "nami@mbai",
                "adff7d31500e89334f7bf0ebfbc1423d0effdee269615cd40738ff3f7e3235ec",
            ),
            (
                "luna@boxe",
                "402ebef2e884a3b448aea75c0a2105cf1a343fde2078c826aef3c95bfbb93b33",
            ),
            (
                "buzz@mbai",
                "1013f494e3bb1e0089547fcf87d1dd12c60a13c15f1524a301e93d80077c1f8c",
            ),
        ] {
            assert_eq!(
                public_hex(&derive_secret(&test_seed(), canonical)),
                expected
            );
        }
        let key = derive_secret(&test_seed(), "nami@mbai");
        let mut event = sign(
            UnsignedEvent {
                created_at: 1700000000,
                kind: 9,
                tags: vec![vec!["h".into(), "test-channel".into()]],
                content: "café 日本語 🎉\n\"\\\t\u{1}".into(),
            },
            &key,
        );
        assert_eq!(
            event.id,
            "e06b9c1b7e70fa5a3e5211767c4bf4afc05a44a79db35718fbbdde7bdb12dc3a"
        );
        assert!(verify(&event));
        event.sig = "d7383c9c16d3413ac5efc0d7f9c32f238ec2cd421b37cebd01c0ec46d69e4eefefab65f29514005c4897611913ea01006d513885c2c8869a7436af4bf3e616aa".into();
        assert!(verify(&event), "Python-produced event signature");
        let tag = [
            "auth".into(), public_hex(&test_owner()), "".into(),
            "67ad6d842bbfaae44ad0102e73da2b5d06401234022d909dd2996a24008682ecf4ebfafc5b1133bea005b17e5c34c9fc733189eeb48d73ca6a13339c1a304ca7".into(),
        ];
        assert!(
            verify_auth_tag(&tag, &event.pubkey),
            "Python-produced attestation"
        );
        let rust_tag = auth_tag(&test_owner(), &event.pubkey, "");
        assert!(verify_auth_tag(&rust_tag, &event.pubkey));
        assert_eq!(
            sha256_hex(br#"{"content":"fixed test body"}"#),
            "19368209efef1739df7608028c00685adfdfecc18c0b253030de516af4096e28"
        );
    }

    #[test]
    fn canonical_names_match_python_rules() {
        assert_eq!(
            canonical_name("infra[2]", " MbAi ").unwrap(),
            "infra[2]@mbai"
        );
        assert_eq!(canonical_name("nami:BOXE", "b").unwrap(), "nami:BOXE@b");
        for bad in [
            "",
            " nami",
            "nami ",
            "na mi",
            "na\tmi",
            "nami;evil",
            "námí",
            "a|b",
            "a&b",
            "a$b",
            "a`b",
            "a<b",
            "a>b",
            "a\u{1c}b",
        ] {
            assert!(canonical_name(bad, "mbai").is_err(), "{bad:?}");
        }
        for bad in ["", "-mbai", "mbai-", "mb ai", "m_bai", "é", &"a".repeat(64)] {
            assert!(device_label(bad).is_err(), "{bad:?}");
        }
        assert_eq!(device_label(&"a".repeat(63)).unwrap(), "a".repeat(63));
        assert_eq!(device_label("\u{1c}MBAI\u{1f}").unwrap(), "mbai");
    }

    #[test]
    fn hkdf_rfc5869_and_scalar_boundaries() {
        let salt = unhex::<13>("000102030405060708090a0b0c").unwrap();
        let info = unhex::<10>("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let mut output = [0; 42];
        Hkdf::<Sha256>::new(Some(&salt), &[0x0b; 22])
            .expand(&info, &mut output)
            .unwrap();
        assert_eq!(
            hex(&output),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        let mut one = [0; 32];
        one[31] = 1;
        assert_eq!(reduce_scalar([0; 32]), one);
        let modulus =
            unhex::<32>("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
                .unwrap();
        assert_eq!(reduce_scalar(modulus), one);
        let mut below = modulus;
        below[31] -= 1;
        assert_eq!(reduce_scalar(below), modulus);
        assert!(SecretKey::from_bytes(&reduce_scalar([0xff; 32])).is_ok());
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper_rejection() {
        let key = test_owner();
        let event = sign(
            UnsignedEvent {
                created_at: 1700000000,
                kind: 9,
                tags: vec![vec!["h".into(), "channel".into()]],
                content: "hello".into(),
            },
            &key,
        );
        assert!(verify(&event));
        for field in 0..6 {
            let mut tampered = event.clone();
            match field {
                0 => tampered.content.push('!'),
                1 => tampered.created_at += 1,
                2 => tampered.kind += 1,
                3 => tampered.tags[0][1] = "other".into(),
                4 => tampered.id = "ff".repeat(32),
                _ => tampered.sig.truncate(100),
            }
            assert!(!verify(&tampered), "tampered field {field}");
        }
        let mut malformed = event;
        malformed.pubkey = "ab".repeat(32);
        assert!(!verify(&malformed));
    }

    #[test]
    fn nip_oa_deployed_spec_and_python_test_vectors() {
        let agent = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        let tag = [
            "auth".into(),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
            "kind=1&created_at<1713957000".into(),
            "8b7df2575caf0a108374f8471722b233c53f9ff827a8b0f91861966c3b9dd5cb2e189eae9f49d72187674c2f5bd244145e10ff86c9f257ffe65a1ee5f108b369".into(),
        ];
        assert!(verify_auth_tag(&tag, agent));
        let tag = [
            "auth".into(), public_hex(&test_owner()), "".into(),
            "20105c618d6e5d8f559cffb6f0d7a7b4f44f3a567e1be94c96378d45ac3625da34c2e7357ea1d3ce980978334546b3e740c155e81b833ebe140d519d39ed8867".into(),
        ];
        assert!(verify_auth_tag(&tag, &"a".repeat(64)));
        assert!(!verify_auth_tag(&tag[..3], &"a".repeat(64)));
        assert!(!verify_auth_tag(&tag, &tag[1]));
        assert!(!verify_auth_tag(&tag, &"b".repeat(64)));
        for condition in [
            "kind=01",
            "kind=1&",
            "kind=65536",
            "created_at<4294967296",
            "kind= 1",
            "&kind=1",
            "unknown=1",
        ] {
            let invalid = auth_tag(&test_owner(), agent, condition);
            assert!(!verify_auth_tag(&invalid, agent), "{condition}");
        }
        let valid = auth_tag(
            &test_owner(),
            agent,
            "kind=0&created_at>0&created_at<4294967295",
        );
        assert!(verify_auth_tag(&valid, agent));
        let mut reordered = valid;
        reordered[2] = "created_at>0&kind=0&created_at<4294967295".into();
        assert!(!verify_auth_tag(&reordered, agent));
    }

    #[test]
    fn nip98_payload_binding_and_replay_unique_headers() {
        let body = br#"{"content":"fixed test body"}"#;
        let key = test_owner();
        let decode = |header: String| -> Event {
            serde_json::from_slice(
                &STANDARD
                    .decode(header.strip_prefix("Nostr ").unwrap())
                    .unwrap(),
            )
            .unwrap()
        };
        let first = decode(http_auth_header(
            &key,
            "https://relay.test/events",
            "POST",
            body,
        ));
        let second = decode(http_auth_header(
            &key,
            "https://relay.test/events",
            "POST",
            body,
        ));
        assert!(verify(&first));
        assert_eq!(first.kind, 27235);
        assert!(
            first
                .tags
                .contains(&vec!["u".into(), "https://relay.test/events".into()])
        );
        assert!(first.tags.contains(&vec!["method".into(), "POST".into()]));
        assert!(first.tags.contains(&vec![
            "payload".into(),
            "19368209efef1739df7608028c00685adfdfecc18c0b253030de516af4096e28".into()
        ]));
        assert_ne!(
            first.id, second.id,
            "same-second requests must not trip replay protection"
        );
    }

    #[test]
    fn bech32_keys_roundtrip_and_reject_invalid_encodings() {
        let key = test_owner();
        let npub = encode_npub(&public_hex(&key)).unwrap();
        assert_eq!(decode_npub(&npub).unwrap(), public_hex(&key));
        let nsec = encode_nsec(&key);
        assert_eq!(encode_nsec(&decode_nsec(&nsec).unwrap()), nsec);
        assert!(decode_nsec(&npub).is_err());
        assert!(decode_npub(&nsec).is_err());
        let mut corrupt = nsec;
        corrupt.pop();
        corrupt.push('q');
        assert!(decode_nsec(&corrupt).is_err());
        let bech32m =
            bech32::encode::<bech32::Bech32m>(Hrp::parse("nsec").unwrap(), &[3; 32]).unwrap();
        assert!(decode_nsec(&bech32m).is_err());
        assert!(SecretKey::from_bytes(&[0; 32]).is_err());
        assert_eq!(format!("{key:?}"), "SecretKey([REDACTED])");
    }

    #[test]
    fn key_loaders_validate_files_without_disclosing_material() {
        let mut seed = tempfile::NamedTempFile::new().unwrap();
        seed.write_all(&test_seed()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            seed.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        assert_eq!(load_seed(seed.path()).unwrap(), test_seed());
        seed.write_all(&[0]).unwrap();
        assert!(load_seed(seed.path()).is_err());
        seed.as_file().set_len(31).unwrap();
        assert!(load_seed(seed.path()).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            seed.as_file().set_len(32).unwrap();
            for mode in [0o644, 0o400, 0o700] {
                seed.as_file()
                    .set_permissions(std::fs::Permissions::from_mode(mode))
                    .unwrap();
                assert!(load_seed(seed.path()).is_err());
            }
        }
        let mut owner = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            owner,
            "# ignored\nOTHER=not-a-key\n BUZZ_PRIVATE_KEY = '{}'\nBUZZ_PRIVATE_KEY=not-used",
            encode_nsec(&test_owner())
        )
        .unwrap();
        assert_eq!(
            public_hex(&load_owner_key(owner.path()).unwrap()),
            public_hex(&test_owner())
        );
        let mut bad = tempfile::NamedTempFile::new().unwrap();
        writeln!(bad, "BUZZ_PRIVATE_KEY=INVALID_TEST_PRIVATE_VALUE").unwrap();
        assert!(
            !load_owner_key(bad.path())
                .unwrap_err()
                .to_string()
                .contains("INVALID_TEST_PRIVATE_VALUE")
        );
        let mut hex_key = tempfile::NamedTempFile::new().unwrap();
        writeln!(hex_key, "BUZZ_PRIVATE_KEY=\"{}03\"", "00".repeat(31)).unwrap();
        assert_eq!(
            public_hex(&load_owner_key(hex_key.path()).unwrap()),
            public_hex(&test_owner())
        );
    }
}
