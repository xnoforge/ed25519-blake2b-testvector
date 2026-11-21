//! Minimal canister that produces ICP threshold-Ed25519 test material.
//!
//! Nothing here is meant to be reusable — it exists to obtain one public key
//! and one signature from the subnet so they can be verified off-chain against
//! both Ed25519 variants.
//!
//! Two invariants matter for the test to mean anything:
//!
//! * `KEY_NAME` and `derivation_path()` supply *both* endpoints alike.
//!   If the key id or the path differed between them, the public key would not
//!   match the signature and a failure would prove nothing.
//! * The derivation path is empty rather than caller-derived (which is what the
//!   DFINITY examples do), so anyone can reproduce the exact same key.

use ic_cdk::management_canister::{
    schnorr_public_key, sign_with_schnorr, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgs,
    SignWithSchnorrArgs,
};

/// The key the vector was produced with. Change this to `dfx_test_key` when
/// deploying to a local replica — mainnet does not know that name, and a local
/// replica does not know `test_key_1`.
const KEY_NAME: &str = "test_key_1";

fn key_id() -> SchnorrKeyId {
    SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Ed25519,
        name: KEY_NAME.to_string(),
    }
}

fn derivation_path() -> Vec<Vec<u8>> {
    vec![]
}

/// Reports the parameters the signatures were produced under, so the published
/// vector can state them without anyone having to read the source.
#[ic_cdk::query]
fn config() -> String {
    format!(
        "algorithm=ed25519 key_name={} derivation_path=[] canister_id={}",
        KEY_NAME,
        ic_cdk::api::canister_self().to_text()
    )
}

/// The subnet-derived public key, hex encoded.
///
/// Passing a canister id returns the key the subnet derives for *that* canister
/// rather than for this one. That is what makes the published vector checkable
/// by a third party: deploy this canister yourself, call it with the id stated
/// in the README, and the key must come back byte for byte. `schnorr_public_key`
/// carries no cycle cost; the caller still pays for its own execution.
#[ic_cdk::update]
async fn get_public_key(canister_id: Option<candid::Principal>) -> Result<String, String> {
    let args = SchnorrPublicKeyArgs {
        canister_id,
        derivation_path: derivation_path(),
        key_id: key_id(),
    };

    match schnorr_public_key(&args).await {
        Ok(result) => Ok(hex::encode_upper(result.public_key)),
        Err(e) => Err(format!("schnorr_public_key failed: {e}")),
    }
}

/// Signs the given hex-encoded message and returns the 64-byte signature, hex.
///
/// `sign_with_schnorr` takes the full message, not a digest of it (unlike
/// `sign_with_ecdsa`). We pass a 32-byte Nano block hash as the message, which
/// is exactly what a Nano signer signs.
#[ic_cdk::update]
async fn sign(message_hex: String) -> Result<String, String> {
    let message =
        hex::decode(message_hex.trim()).map_err(|e| format!("message is not hex: {e}"))?;

    let args = SignWithSchnorrArgs {
        message,
        derivation_path: derivation_path(),
        key_id: key_id(),
        aux: None,
    };

    // ic-cdk 0.19 computes the fee and attaches the cycles itself; unused
    // cycles are refunded.
    match sign_with_schnorr(&args).await {
        Ok(result) => Ok(hex::encode_upper(result.signature)),
        Err(e) => Err(format!("sign_with_schnorr failed: {e}")),
    }
}
