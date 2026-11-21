//! Derives an Internet Computer threshold Ed25519 public key offline.
//!
//! The IC's key derivation is a pure function of a master public key and a
//! derivation path, so the published key can be re-derived without deploying a
//! canister, without cycles and without touching the network. The interface
//! specification names this as a design requirement: new public keys can be
//! computed client-side from a master public key without interaction with the
//! IC.
//!
//! Per path element, with the chain code starting at 32 zero bytes:
//!
//!     okm = HKDF-SHA512(salt = chain_code, ikm = encode(K) ‖ element,
//!                       info = "Ed25519", 96 bytes)
//!     K   = K + [ big-endian(okm[0..64]) mod L ] · B
//!     chain_code = okm[64..96]
//!
//! For `schnorr_public_key` with an empty derivation path the path is the
//! calling canister's principal bytes, one element.
//!
//! HMAC and HKDF are implemented here rather than taken from a crate, for the
//! same reason the Blake2b side is: the repository should not need a dependency
//! to be checkable. Only `sha2` and `curve25519-dalek` are used, both already
//! required by the other binaries.
//!
//! Usage:
//!     derive-key <master-pubkey-hex> <canister-id>
//!
//! Exit codes: 0 derived, 2 malformed input.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

const SHA512_BLOCK: usize = 128;

fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut k = [0u8; SHA512_BLOCK];
    if key.len() > SHA512_BLOCK {
        k[..64].copy_from_slice(&Sha512::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; SHA512_BLOCK];
    let mut opad = [0x5cu8; SHA512_BLOCK];
    for i in 0..SHA512_BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha512::new()
        .chain_update(ipad)
        .chain_update(msg)
        .finalize();
    let outer = Sha512::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&outer);
    out
}

/// HKDF-SHA512 expand to 96 bytes: 64 for the scalar, 32 for the next chain code.
fn hkdf_sha512_96(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 96] {
    let prk = hmac_sha512(salt, ikm);
    let mut out = [0u8; 96];
    let mut prev: Vec<u8> = Vec::new();
    let mut written = 0usize;
    let mut counter = 1u8;
    while written < out.len() {
        let mut msg = prev.clone();
        msg.extend_from_slice(info);
        msg.push(counter);
        let block = hmac_sha512(&prk, &msg);
        let take = core::cmp::min(block.len(), out.len() - written);
        out[written..written + take].copy_from_slice(&block[..take]);
        prev = block.to_vec();
        written += take;
        counter += 1;
    }
    out
}

/// RFC 4648 base32 without padding, dashes ignored, case-insensitive.
fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for ch in text.chars().filter(|c| *c != '-') {
        let c = ch.to_ascii_lowercase();
        let v = match c {
            'a'..='z' => (c as u8 - b'a') as u64,
            '2'..='7' => (c as u8 - b'2' + 26) as u64,
            _ => return None,
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// CRC-32 (IEEE), bitwise so no table is needed.
fn crc32(data: &[u8]) -> u32 {
    let mut c: u32 = 0xFFFF_FFFF;
    for &byte in data {
        c ^= byte as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// A principal's raw bytes: base32 payload minus its leading big-endian CRC-32,
/// with that checksum verified so a mistyped id cannot derive a wrong key quietly.
fn principal_bytes(text: &str) -> Result<Vec<u8>, String> {
    let raw = base32_decode(text).ok_or_else(|| "not base32".to_string())?;
    if raw.len() < 5 {
        return Err("too short for a principal".into());
    }
    let (checksum, body) = raw.split_at(4);
    let expected = crc32(body).to_be_bytes();
    if checksum != expected {
        return Err(format!(
            "CRC mismatch: id carries {}, body hashes to {}",
            hex_upper(checksum),
            hex_upper(&expected)
        ));
    }
    Ok(body.to_vec())
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn derive(master: &[u8; 32], path: &[Vec<u8>]) -> Result<[u8; 32], String> {
    let mut point = CompressedEdwardsY(*master)
        .decompress()
        .ok_or_else(|| "master public key does not decompress".to_string())?;
    let mut chain_code = [0u8; 32];

    for element in path {
        let mut ikm = point.compress().to_bytes().to_vec();
        ikm.extend_from_slice(element);
        let okm = hkdf_sha512_96(&chain_code, &ikm, b"Ed25519");

        // The 64-byte tweak is read big-endian; from_bytes_mod_order_wide
        // expects little-endian, hence the reversal.
        let mut wide = [0u8; 64];
        for (i, b) in okm[..64].iter().rev().enumerate() {
            wide[i] = *b;
        }
        point += Scalar::from_bytes_mod_order_wide(&wide) * ED25519_BASEPOINT_POINT;
        chain_code.copy_from_slice(&okm[64..]);
    }

    Ok(point.compress().to_bytes())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        eprintln!("usage: derive-key <master-pubkey-hex> <canister-id>");
        std::process::exit(2);
    }

    let master_bytes = match hex::decode(args[0].trim()) {
        Ok(b) if b.len() == 32 => b,
        Ok(b) => {
            println!("ERROR   master public key is {} bytes, want 32", b.len());
            std::process::exit(2);
        }
        Err(e) => {
            println!("ERROR   master public key is not hex: {e}");
            std::process::exit(2);
        }
    };
    let mut master = [0u8; 32];
    master.copy_from_slice(&master_bytes);

    let element = match principal_bytes(&args[1]) {
        Ok(b) => b,
        Err(e) => {
            println!("ERROR   canister id: {e}");
            std::process::exit(2);
        }
    };

    match derive(&master, std::slice::from_ref(&element)) {
        Ok(derived) => {
            println!("path element  {}", hex_upper(&element));
            println!("derived key   {}", hex_upper(&derived));
        }
        Err(e) => {
            println!("ERROR   {e}");
            std::process::exit(2);
        }
    }
}
