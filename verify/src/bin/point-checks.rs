//! Reports the structural properties of a key and a signature, so that a failed
//! verification can be told apart from malformed input.
//!
//! The README claims that both failing checks fail at the verification equation
//! and not at decoding, at a non-canonical S, or at a torsion component. This
//! binary is how that claim is checked rather than asserted.
//!
//! With `--assert` the binary exits non-zero if any of the properties it
//! reports is missing, so the claim can be enforced in CI rather than read off
//! a screen.
//!
//! Usage: point-checks <pubkey_hex> [signature_hex] [--assert]
//! Exit:  0 = all reported properties hold, 1 = one does not (--assert only),
//!        2 = malformed input

use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use std::process::ExitCode;

fn main() -> ExitCode {
    let all: Vec<String> = std::env::args().collect();
    let assert_mode = all.iter().any(|a| a == "--assert");
    let args: Vec<String> = all.into_iter().filter(|a| a != "--assert").collect();
    if args.len() < 2 || args.len() > 3 {
        eprintln!("usage: {} <pubkey_hex> [signature_hex] [--assert]", args[0]);
        return ExitCode::from(2);
    }
    let mut all_hold = true;

    let pubkey: [u8; 32] = match hex::decode(args[1].trim())
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(k) => k,
        None => {
            eprintln!("ERROR   public key must be 32 bytes of hex");
            return ExitCode::from(2);
        }
    };

    let a = CompressedEdwardsY(pubkey).decompress();
    all_hold &= report("public key   decompresses", a.is_some());
    match &a {
        Some(point) => {
            // is_torsion_free() computes [L]·A and compares it with the identity.
            all_hold &= report("             torsion free", point.is_torsion_free());
            // Small order is the one property that must be absent, so it is
            // folded in inverted.
            all_hold &= report("             not small order", !point.is_small_order());
        }
        None => println!("             (further checks skipped)"),
    }

    if args.len() == 3 {
        let signature: [u8; 64] = match hex::decode(args[2].trim())
            .ok()
            .and_then(|b| b.try_into().ok())
        {
            Some(s) => s,
            None => {
                eprintln!("ERROR   signature must be 64 bytes of hex");
                return ExitCode::from(2);
            }
        };
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&signature[..32]);
        s_bytes.copy_from_slice(&signature[32..]);

        let r = CompressedEdwardsY(r_bytes).decompress();
        all_hold &= report("R            decompresses", r.is_some());
        match &r {
            // Reported for the same reason the public key is: a torsion
            // component in either one can make a cofactored verifier disagree
            // with a cofactorless one.
            Some(point) => {
                all_hold &= report("             torsion free", point.is_torsion_free());
                all_hold &= report("             not small order", !point.is_small_order());
            }
            None => println!("             (further checks skipped)"),
        }
        let s_canonical = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)).is_some();
        all_hold &= report("S            canonical (S < L)", s_canonical);
    }

    if assert_mode && !all_hold {
        eprintln!("ERROR   at least one property does not hold");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// Prints one property and passes its value through, so the caller can fold all
/// of them together for `--assert`.
fn report(label: &str, holds: bool) -> bool {
    println!("{label}: {}", if holds { "yes" } else { "no" });
    holds
}
