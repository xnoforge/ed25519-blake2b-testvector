//! Standard Ed25519 (RFC 8032) verification — SHA-512 in the challenge step.
//!
//! Usage: verify-std <pubkey_hex> <message_hex> <signature_hex>
//! Exit:  0 = VALID, 1 = INVALID, 2 = ERROR (malformed input)

use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "usage: {} <pubkey_hex> <message_hex> <signature_hex>",
            args[0]
        );
        return ExitCode::from(2);
    }

    let pubkey = match decode_fixed::<32>(&args[1], "public key") {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    let message = match hex::decode(args[2].trim()) {
        Ok(v) => v,
        Err(e) => return fail(&format!("message is not valid hex: {e}")),
    };
    let signature = match decode_fixed::<64>(&args[3], "signature") {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };

    // Malformed input is kept apart from a failed equation, so the test vector
    // cannot be dismissed as an encoding accident. The same three structural
    // checks run here as in verify-blake2b, so both schemes answer ERROR and
    // INVALID for the same reasons.
    let key = match VerifyingKey::from_bytes(&pubkey) {
        Ok(k) => k,
        Err(e) => return fail(&format!("public key is not a valid curve point: {e}")),
    };

    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    s_bytes.copy_from_slice(&signature[32..]);

    if CompressedEdwardsY(r_bytes).decompress().is_none() {
        return fail("R is not a valid curve point");
    }
    if Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)).is_none() {
        return fail("S is not canonical (S >= L)");
    }

    match key.verify(&message, &Signature::from_bytes(&signature)) {
        Ok(()) => {
            println!("VALID   (Ed25519, RFC 8032, SHA-512 challenge)");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("INVALID (Ed25519, RFC 8032, SHA-512 challenge) — {e}");
            ExitCode::from(1)
        }
    }
}

fn decode_fixed<const N: usize>(arg: &str, label: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(arg.trim()).map_err(|e| format!("{label} is not valid hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} must be {N} bytes"))
}

fn fail(message: &str) -> ExitCode {
    println!("ERROR   {message}");
    ExitCode::from(2)
}
