//! Derives the Nano address belonging to a public key, so the test vector can
//! name the account without anyone taking it on trust.
//!
//! Self-contained: Nano's base32 alphabet and its Blake2b-40 checksum are
//! implemented here rather than imported, for the same reason the Blake2b
//! verifier is.
//!
//! Usage: pubkey-to-address <pubkey_hex>

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use std::process::ExitCode;

/// Nano's base32 alphabet: the usual 32 characters minus 0, 2, l and v.
const ALPHABET: &[u8; 32] = b"13456789abcdefghijkmnopqrstuwxyz";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: {} <pubkey_hex>", args[0]);
        return ExitCode::from(2);
    }

    let bytes = match hex::decode(args[1].trim()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("not valid hex: {e}");
            return ExitCode::from(2);
        }
    };
    let pubkey: [u8; 32] = match bytes.try_into() {
        Ok(k) => k,
        Err(_) => {
            eprintln!("public key must be 32 bytes");
            return ExitCode::from(2);
        }
    };

    println!(
        "nano_{}{}",
        encode_pubkey(&pubkey),
        encode_checksum(&pubkey)
    );
    ExitCode::SUCCESS
}

/// 260 bits — four zero bits followed by the key — as 52 base32 characters.
fn encode_pubkey(pubkey: &[u8; 32]) -> String {
    let mut padded = [0u8; 33];
    padded[1..].copy_from_slice(pubkey);
    // The four pad bits sit in the top nibble of the first byte, which is
    // already zero, so the 260 bits start at bit offset 4.
    base32(&padded, 4, 52)
}

/// The checksum is Blake2b with a five-byte output over the key, byte-reversed,
/// written as eight base32 characters.
fn encode_checksum(pubkey: &[u8; 32]) -> String {
    let mut hasher = Blake2bVar::new(5).expect("5 is a valid Blake2b output length");
    hasher.update(pubkey);
    let mut digest = [0u8; 5];
    hasher
        .finalize_variable(&mut digest)
        .expect("output length matches");
    digest.reverse();
    base32(&digest, 0, 8)
}

/// Reads `count` groups of five bits starting at `bit_offset` and maps each to
/// a character of the alphabet.
fn base32(bytes: &[u8], bit_offset: usize, count: usize) -> String {
    (0..count)
        .map(|i| {
            let mut value = 0u8;
            for bit in 0..5 {
                let position = bit_offset + i * 5 + bit;
                let byte = bytes[position / 8];
                let is_set = (byte >> (7 - position % 8)) & 1;
                value = (value << 1) | is_set;
            }
            ALPHABET[value as usize] as char
        })
        .collect()
}
