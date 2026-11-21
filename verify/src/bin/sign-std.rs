//! Local standard-Ed25519 signer — a cost-free stand-in for the ICP canister.
//!
//! Produces the same scheme `sign_with_schnorr` produces (an RFC 8032 signature
//! over the raw message), from a fixed seed so the run is reproducible. Used to
//! rehearse checks 1 and 2 before spending cycles on the real thing.
//!
//! Usage: sign-std <seed_hex_32B> <message_hex>
//! Prints the public key and the signature, hex, one per line.

use ed25519_dalek::{Signer, SigningKey};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <seed_hex_32B> <message_hex>", args[0]);
        return ExitCode::from(2);
    }

    let seed: [u8; 32] = match hex::decode(args[1].trim()).map(TryInto::try_into) {
        Ok(Ok(s)) => s,
        _ => {
            eprintln!("seed must be 32 bytes of hex");
            return ExitCode::from(2);
        }
    };
    let message = match hex::decode(args[2].trim()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("message is not valid hex: {e}");
            return ExitCode::from(2);
        }
    };

    let key = SigningKey::from_bytes(&seed);
    println!("{}", hex::encode_upper(key.verifying_key().to_bytes()));
    println!("{}", hex::encode_upper(key.sign(&message).to_bytes()));
    ExitCode::SUCCESS
}
