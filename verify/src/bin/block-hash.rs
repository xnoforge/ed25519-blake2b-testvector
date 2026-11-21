//! Recomputes the hash of the Nano mainnet genesis block from its fields.
//!
//! The genesis block is a legacy `open` block, so its hash is
//! `Blake2b-256(source ‖ representative ‖ account)` with all three fields set to
//! the genesis account's public key. Shipping this means the message used in the
//! vector is derived in front of the reader rather than pasted in.
//!
//! Usage: block-hash <pubkey_hex>

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: {} <pubkey_hex>", args[0]);
        return ExitCode::from(2);
    }

    let pubkey = match hex::decode(args[1].trim()) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            eprintln!("ERROR   public key must be 32 bytes of hex");
            return ExitCode::from(2);
        }
    };

    let mut hasher = Blake2bVar::new(32).expect("32 is a valid Blake2b output length");
    for _ in 0..3 {
        hasher.update(&pubkey);
    }
    let mut digest = [0u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .expect("output length matches");

    println!("{}", hex::encode_upper(digest));
    ExitCode::SUCCESS
}
