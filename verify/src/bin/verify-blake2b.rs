//! Ed25519-Blake2b verification as Nano does it — Blake2b-512 in the challenge
//! step, everything else identical to RFC 8032.
//!
//! Implemented here from the curve primitives on purpose. A test vector that
//! can only be checked with the author's own library proves very little, so
//! this file does the arithmetic in the open:
//!
//!   k  = Blake2b-512(R ‖ A ‖ M)  reduced mod L
//!   R' = [S]·B − [k]·A
//!   the signature is valid iff R' encodes to the same 32 bytes as R
//!
//! That is the cofactorless form, which is what Nano's node implementation
//! (ed25519-donna with Blake2b) and ed25519-dalek both apply.
//!
//! `--donna-compat` switches to this file's model of what nano-node accepts,
//! written from the lines cited below, instead of the stricter rule above,
//! which is not the same thing. `ed25519_sign_open`
//! (`crypto/ed25519-donna/ed25519.c:111`) tests only the top three bits of the
//! last byte of `S` and then reduces mod L, and it never decompresses `R` — it
//! re-encodes the recomputed point and compares bytes. So a node accepts
//! signatures with `S` in `[L, 2^253)` that the strict path below rejects as
//! malformed. That divergence is consensus-critical, so it is a mode you can
//! run rather than a paragraph you have to believe.
//!
//! `--cofactored` keeps the same parse rules and swaps the equation for RFC
//! 8032 §5.1.7's cofactored form, `[8][S]·B == [8]R + [8][k]·A`. Nano, donna and
//! dalek all use the cofactorless form. `vectors.json` carries a signature the
//! two forms answer differently.
//!
//! Usage: verify-blake2b <pubkey_hex> <message_hex> <signature_hex> [--donna-compat | --cofactored]
//! Exit:  0 = VALID, 1 = INVALID, 2 = ERROR (malformed input)

use blake2::{Blake2b512, Digest};
use curve25519_dalek::{edwards::CompressedEdwardsY, edwards::EdwardsPoint, scalar::Scalar};
use std::process::ExitCode;

fn main() -> ExitCode {
    let all: Vec<String> = std::env::args().collect();
    let donna = all.iter().any(|a| a == "--donna-compat");
    let cofactored = all.iter().any(|a| a == "--cofactored");
    let args: Vec<String> = all
        .iter()
        .filter(|a| *a != "--donna-compat" && *a != "--cofactored")
        .cloned()
        .collect();
    if args.len() != 4 {
        eprintln!(
            "usage: {} <pubkey_hex> <message_hex> <signature_hex> [--donna-compat | --cofactored]",
            args[0]
        );
        return ExitCode::from(2);
    }
    // Refused rather than silently resolved: donna's rule is cofactorless by
    // construction, so there is no such thing as a cofactored donna mode.
    if donna && cofactored {
        return fail("--donna-compat and --cofactored are different rules");
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

    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    s_bytes.copy_from_slice(&signature[32..]);

    // Malformed input is kept apart from a failed equation, so the vector
    // cannot be dismissed as an encoding accident.
    let a_point = match CompressedEdwardsY(pubkey).decompress() {
        Some(p) => p,
        None => return fail("public key is not a valid curve point"),
    };
    // donna never unpacks R, so neither does the compatibility mode. The
    // cofactored rule needs R as a point, not as bytes, so it is kept here.
    let r_point = CompressedEdwardsY(r_bytes).decompress();
    if !donna && r_point.is_none() {
        return fail("R is not a valid curve point");
    }
    let s_scalar = if donna {
        // ed25519.c:111 — the only test donna applies to S, followed by a
        // reduction mod L in expand256_modm.
        if s_bytes[31] & 224 != 0 {
            return fail("S has high bits set (donna rejects this too)");
        }
        Scalar::from_bytes_mod_order(s_bytes)
    } else {
        match Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) {
            Some(s) => s,
            None => return fail("S is not canonical (S >= L)"),
        }
    };

    // The only difference from RFC 8032: Blake2b-512 instead of SHA-512.
    let mut hasher = Blake2b512::new();
    hasher.update(r_bytes);
    hasher.update(pubkey);
    hasher.update(&message);
    let mut challenge = [0u8; 64];
    challenge.copy_from_slice(&hasher.finalize());
    let k = Scalar::from_bytes_mod_order_wide(&challenge);

    // R' = [S]·B − [k]·A, computed as (−k)·A + S·B.
    let r_prime = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(-a_point), &s_scalar);

    let mode = if donna {
        "Ed25519-Blake2b, nano-node compatible"
    } else if cofactored {
        "Ed25519-Blake2b, cofactored equation"
    } else {
        "Ed25519-Blake2b, Nano, Blake2b-512 challenge"
    };
    // RFC 8032 §5.1.7 prescribes the cofactored form and permits the other. The
    // cofactored one compares the two
    // points after multiplying both by 8, so a difference of small order is
    // sent to zero and accepted; the cofactorless one compares the encodings.
    let holds = match (cofactored, r_point) {
        (true, Some(r)) => r_prime.mul_by_cofactor() == r.mul_by_cofactor(),
        _ => r_prime.compress().to_bytes() == r_bytes,
    };
    if holds {
        println!("VALID   ({mode})");
        ExitCode::SUCCESS
    } else {
        println!("INVALID ({mode}) — verification equation does not hold");
        ExitCode::from(1)
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
