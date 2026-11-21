//! A deterministic Ed25519-Blake2b signer, implemented from the curve
//! primitives so that new test vectors can be generated rather than copied.
//!
//! **This is not byte-for-byte what nano-node produces, and the difference is
//! in the nonce.** nano-node patched ed25519-donna to randomise it: its signing
//! path (`crypto/ed25519-donna/ed25519.c:69-83`, tag V27.0) computes
//! `r = H(extsk[32..63] ‖ 32 random bytes ‖ 64 zero bytes ‖ M)`, where the
//! randomness comes from `ed25519_randombytes_unsafe`
//! (`nano/crypto_lib/interface.cpp:6-9`, backed by nano's CSPRNG) and the zero
//! padding puts the message in its own hash block — the source comment names
//! side channels as the reason. Signing the same message twice on a Nano node
//! therefore yields two different signatures.
//!
//! This binary uses the RFC 8032 nonce instead, `r = H(prefix ‖ M)`, because a
//! known-answer test needs a reproducible answer. The signatures it produces
//! are **valid** Nano signatures — any `(R, S)` satisfying the verification
//! equation is accepted, and `verify-blake2b` confirms each one — but an
//! implementation that follows nano-node will not reproduce these exact bytes,
//! and should not be expected to.
//!
//! Everything apart from the nonce is RFC 8032 Ed25519 with Blake2b-512 in
//! place of SHA-512, which is what nano-node gets by compiling ed25519-donna
//! against `ed25519-hash-custom.h` (`typedef blake2b_state
//! ed25519_hash_context`, with `ed25519_hash_init` defined as
//! `blake2b_init(ctx, 64)` in `nano/crypto_lib/interface.cpp:10-13`):
//!
//!     extsk    = Blake2b-512(privkey)
//!     a        = clamp(extsk[0..32])        reduced mod L
//!     A        = [a]·B                      the public key
//!     r        = Blake2b-512(extsk[32..64] ‖ M)  reduced mod L
//!     R        = [r]·B
//!     k        = Blake2b-512(R ‖ A ‖ M)     reduced mod L
//!     S        = r + k·a                    mod L
//!     signature = R ‖ S
//!
//! Clamping clears the low three bits of the first byte, clears the top bit of
//! the last and sets the one below it — the three masking lines further down —
//! exactly as `ed25519_extsk` does. The clamped value exceeds L, so
//! it is reduced; donna reduces it the same way with `expand256_modm(a, extsk,
//! 32)`, and [a mod L]·B = [a]·B, so the public key is unaffected.
//!
//! Both nano-node and ICP's threshold signer are randomised; this tool is the
//! odd one out, deliberately. Determinism here is a property of this binary,
//! chosen so the vectors are reproducible — not a property of either scheme.
//!
//! `--intermediates` additionally prints every value above; a pass/fail
//! outcome does not localise a mistake.
//!
//! Usage: sign-blake2b <privkey_hex> <message_hex> [--intermediates]

use blake2::{Blake2b512, Digest};
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let usage = format!(
        "usage: {} <privkey_hex> <message_hex> [--intermediates]",
        args[0]
    );
    let mut intermediates = false;
    let mut positional: Vec<&String> = Vec::new();
    for arg in &args[1..] {
        match arg.as_str() {
            "--intermediates" => intermediates = true,
            other if other.starts_with('-') => {
                eprintln!("ERROR   unknown option {other}");
                eprintln!("{usage}");
                return ExitCode::from(2);
            }
            _ => positional.push(arg),
        }
    }
    if positional.len() != 2 {
        eprintln!(
            "ERROR   expected 2 positional arguments, got {}",
            positional.len()
        );
        eprintln!("{usage}");
        return ExitCode::from(2);
    }

    let privkey: [u8; 32] = match hex::decode(positional[0].trim())
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(k) => k,
        None => {
            eprintln!("ERROR   private key must be 32 bytes of hex");
            return ExitCode::from(2);
        }
    };
    let message = match hex::decode(positional[1].trim()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ERROR   message is not valid hex: {e}");
            return ExitCode::from(2);
        }
    };

    // extsk = Blake2b-512(privkey); the first half becomes the scalar, the
    // second half is the nonce prefix and never leaves this function.
    let mut extsk = [0u8; 64];
    extsk.copy_from_slice(&Blake2b512::digest(privkey));
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(&extsk[..32]);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    let a = Scalar::from_bytes_mod_order(clamped);
    let a_point = &a * ED25519_BASEPOINT_TABLE;
    let pubkey = a_point.compress().to_bytes();

    // r = Blake2b-512(prefix ‖ M): the RFC 8032 nonce, not nano-node's
    // randomised one. See the note at the top of this file.
    let mut hasher = Blake2b512::new();
    hasher.update(&extsk[32..]);
    hasher.update(&message);
    let mut nonce = [0u8; 64];
    nonce.copy_from_slice(&hasher.finalize());
    let r = Scalar::from_bytes_mod_order_wide(&nonce);
    let r_point = &r * ED25519_BASEPOINT_TABLE;
    let r_bytes = r_point.compress().to_bytes();

    // k = Blake2b-512(R ‖ A ‖ M), the one step that differs from RFC 8032.
    let mut hasher = Blake2b512::new();
    hasher.update(r_bytes);
    hasher.update(pubkey);
    hasher.update(&message);
    let mut challenge = [0u8; 64];
    challenge.copy_from_slice(&hasher.finalize());
    let k = Scalar::from_bytes_mod_order_wide(&challenge);

    let s = r + k * a;

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r_bytes);
    signature[32..].copy_from_slice(s.as_bytes());

    println!("public key   {}", hex_upper(&pubkey));
    println!("message      {}", hex_upper(&message));
    println!("signature    {}", hex_upper(&signature));
    if intermediates {
        println!("  clamped a  {}", hex_upper(&clamped));
        println!("  a mod L    {}", hex_upper(a.as_bytes()));
        println!("  nonce hash {}", hex_upper(&nonce));
        println!("  r          {}", hex_upper(r.as_bytes()));
        println!("  R          {}", hex_upper(&r_bytes));
        println!("  challenge  {}", hex_upper(&challenge));
        println!("  k          {}", hex_upper(k.as_bytes()));
        println!("  S          {}", hex_upper(s.as_bytes()));
    }
    ExitCode::SUCCESS
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}
