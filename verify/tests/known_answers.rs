//! Known answers that do not depend on run-checks.sh, so `cargo test` alone
//! catches a regression in the tools.

use std::process::Command;

const GENESIS_PK: &str = "E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA";
const GENESIS_HASH: &str = "991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948";
const GENESIS_SIG: &str = "9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02";
const ICP_PK: &str = "0CB17E3D5171C41E2CE62A90996167EBD6ED0176CC7C569A5FF638746C1EB534";
const ICP_SIG: &str = "6E171132DF40BA82E3FE76FB6AFF28CD6EA9666560425DBCD214348E0375A6E1A2DD2888F4E7DE15CEB07BEA27C23C41D55D8F8321E37F09C5FE769A65DCCA04";

fn run(bin: &str, args: &[&str]) -> (String, i32) {
    let out = Command::new(bin).args(args).output().expect("binary runs");
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (text, out.status.code().unwrap_or(-1))
}

#[test]
fn addresses_match_published_pairs() {
    // Pairs that exist outside this repository: the burn address, the genesis
    // account, and the example from the Nano documentation.
    let pairs = [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "nano_1111111111111111111111111111111111111111111111111111hifc8npp",
        ),
        (
            GENESIS_PK,
            "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
        ),
        (
            "3068BB1CA04525BB0E416C485FE6A67FD52540227D267CC8B6E8DA958A7FA039",
            "nano_1e5aqegc1jb7qe964u4adzmcezyo6o146zb8hm6dft8tkp79za3sxwjym5rx",
        ),
    ];
    for (pubkey, address) in pairs {
        let (got, code) = run(env!("CARGO_BIN_EXE_pubkey-to-address"), &[pubkey]);
        assert_eq!(code, 0, "address derivation exited {code}");
        assert_eq!(got, address, "wrong address for {pubkey}");
    }
}

#[test]
fn genesis_hash_is_derived_not_pasted() {
    let (got, code) = run(env!("CARGO_BIN_EXE_block-hash"), &[GENESIS_PK]);
    assert_eq!(code, 0);
    assert_eq!(got, GENESIS_HASH, "genesis block hash does not recompute");
}

#[test]
fn the_four_cross_checks() {
    let cases = [
        ("verify-std", ICP_PK, ICP_SIG, 0, "VALID"),
        ("verify-blake2b", ICP_PK, ICP_SIG, 1, "INVALID"),
        ("verify-blake2b", GENESIS_PK, GENESIS_SIG, 0, "VALID"),
        ("verify-std", GENESIS_PK, GENESIS_SIG, 1, "INVALID"),
    ];
    for (tool, pubkey, signature, expected_code, expected_word) in cases {
        let bin = match tool {
            "verify-std" => env!("CARGO_BIN_EXE_verify-std"),
            _ => env!("CARGO_BIN_EXE_verify-blake2b"),
        };
        let (text, code) = run(bin, &[pubkey, GENESIS_HASH, signature]);
        assert_eq!(code, expected_code, "{tool} on {pubkey}: {text}");
        assert!(
            text.starts_with(expected_word),
            "{tool} said {text:?}, expected it to start with {expected_word}"
        );
    }
}

#[test]
fn malformed_input_is_not_reported_as_invalid() {
    let not_a_point = format!("02{}", "00".repeat(31));
    for bin in [
        env!("CARGO_BIN_EXE_verify-std"),
        env!("CARGO_BIN_EXE_verify-blake2b"),
    ] {
        let (_, code) = run(bin, &[&not_a_point, GENESIS_HASH, ICP_SIG]);
        assert_eq!(code, 2, "a non-point key must be ERROR, not INVALID");
    }
}

#[test]
fn point_checks_rejects_a_small_order_key() {
    // A small-order point (order 4): a valid encoding, but not usable as a
    // public key.
    let small_order = "0000000000000000000000000000000000000000000000000000000000000080";
    let (_, code) = run(
        env!("CARGO_BIN_EXE_point-checks"),
        &[small_order, "--assert"],
    );
    assert_eq!(code, 1, "--assert must fail on a small-order key");
}

/// Reads `vectors.json` and re-runs every case in it through the tools.
///
/// The file is the machine-readable form of this repository's claims, meant to
/// be dropped into another implementation's test suite. Checking it here is
/// what stops it drifting from the binaries that produced it.
#[test]
fn vectors_json_matches_the_tools() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors.json");
    let text = std::fs::read_to_string(path).expect("vectors.json is readable");
    let doc: serde_json::Value = serde_json::from_str(&text).expect("vectors.json parses");

    let outcome = |code: i32| match code {
        0 => "valid",
        1 => "invalid",
        _ => "error",
    };

    let verify_cases = doc["verify"].as_array().expect("verify is an array");
    assert_eq!(verify_cases.len(), 4, "verify case count changed");
    for case in verify_cases {
        let name = case["name"].as_str().unwrap();
        let pk = case["public_key"].as_str().unwrap();
        let msg = case["message"].as_str().unwrap();
        let sig = case["signature"].as_str().unwrap();
        for (field, bin) in [
            ("rfc8032", env!("CARGO_BIN_EXE_verify-std")),
            ("ed25519_blake2b", env!("CARGO_BIN_EXE_verify-blake2b")),
        ] {
            let (_, code) = run(bin, &[pk, msg, sig]);
            assert_eq!(
                outcome(code),
                case[field].as_str().unwrap(),
                "{name}: {field} outcome differs from vectors.json"
            );
        }

        // The cofactored equation. Among the cases in this file it differs from
        // the strict one for the order-8 case. Without this the choice of
        // equation would be a sentence in the file rather than something a
        // consumer can run.
        let (_, cof) = run(
            env!("CARGO_BIN_EXE_verify-blake2b"),
            &[pk, msg, sig, "--cofactored"],
        );
        assert_eq!(
            outcome(cof),
            case["ed25519_blake2b_cofactored"].as_str().unwrap(),
            "{name}: cofactored outcome differs from vectors.json"
        );

        // The node's own rule, which differs from the strict one for S + L.
        // Without this the divergence would live only in a free-text note, and
        // a consumer dropping the file into their suite would encode the
        // opposite of what nano-node does.
        let (_, donna) = run(
            env!("CARGO_BIN_EXE_verify-blake2b"),
            &[pk, msg, sig, "--donna-compat"],
        );
        assert_eq!(
            outcome(donna),
            case["ed25519_blake2b_donna"].as_str().unwrap(),
            "{name}: donna-compatible outcome differs from vectors.json"
        );
    }

    let sign_cases = doc["sign_blake2b"]
        .as_array()
        .expect("sign_blake2b is an array");
    assert_eq!(sign_cases.len(), 6, "signing case count changed");
    for case in sign_cases {
        let name = case["name"].as_str().unwrap();
        let priv_key = case["private_key"].as_str().unwrap();
        let msg = case["message"].as_str().unwrap();
        let (out, code) = run(env!("CARGO_BIN_EXE_sign-blake2b"), &[priv_key, msg]);
        assert_eq!(code, 0, "{name}: signing exited {code}");

        let field = |label: &str| {
            out.lines()
                .find(|l| l.starts_with(label))
                .unwrap_or_else(|| panic!("{name}: no {label} line"))
                .split_whitespace()
                .last()
                .unwrap()
                .to_string()
        };
        assert_eq!(
            field("public key"),
            case["public_key"].as_str().unwrap(),
            "{name}: public key"
        );
        let signature = field("signature");
        assert_eq!(
            signature,
            case["signature"].as_str().unwrap(),
            "{name}: signature"
        );

        // Every intermediate is re-derived too. These are the reason the file
        // exists — an implementer uses them to localise a mistake — so leaving
        // them unchecked would be the one place drift could hide.
        let (verbose, vcode) = run(
            env!("CARGO_BIN_EXE_sign-blake2b"),
            &[priv_key, msg, "--intermediates"],
        );
        assert_eq!(vcode, 0, "{name}: --intermediates exited {vcode}");
        let recorded = case["intermediates"]
            .as_object()
            .unwrap_or_else(|| panic!("{name}: no intermediates object"));
        assert_eq!(recorded.len(), 8, "{name}: expected 8 intermediate values");
        for (key, want) in recorded {
            let line = verbose
                .lines()
                .map(str::trim_start)
                .find(|l| l.starts_with(key.as_str()))
                .unwrap_or_else(|| panic!("{name}: no line for intermediate {key}"));
            let got = line.split_whitespace().last().unwrap();
            assert_eq!(
                got,
                want.as_str().unwrap(),
                "{name}: intermediate {key} differs from vectors.json"
            );
        }

        // Every recorded signature must verify as Nano and fail as RFC 8032.
        let pk = case["public_key"].as_str().unwrap();
        let (_, nano) = run(env!("CARGO_BIN_EXE_verify-blake2b"), &[pk, msg, &signature]);
        assert_eq!(
            nano, 0,
            "{name}: own signature does not verify as Ed25519-Blake2b"
        );
        let (_, rfc) = run(env!("CARGO_BIN_EXE_verify-std"), &[pk, msg, &signature]);
        assert_eq!(
            rfc, 1,
            "{name}: own signature unexpectedly verifies as RFC 8032"
        );
    }
}

/// The signer reproduces a keypair published outside this repository.
///
/// docs.nano.org documents this private key, its public key and its account for
/// `key_expand`. Deriving the same public key confirms the Blake2b-512 key
/// expansion and the clamping against an external reference rather than against
/// this repository's own output.
#[test]
fn signer_reproduces_the_published_keypair() {
    const DOCS_PRIV: &str = "781186FB9EF17DB6E3D1056550D9FAE5D5BBADA6A6BC370E4CBB938B1DC71DA3";
    const DOCS_PUB: &str = "3068BB1CA04525BB0E416C485FE6A67FD52540227D267CC8B6E8DA958A7FA039";
    let (out, code) = run(env!("CARGO_BIN_EXE_sign-blake2b"), &[DOCS_PRIV, "00"]);
    assert_eq!(code, 0);
    let derived = out
        .lines()
        .find(|l| l.starts_with("public key"))
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap();
    assert_eq!(
        derived, DOCS_PUB,
        "key expansion does not match the published pair"
    );
}

/// Signing is deterministic, which is what makes these usable as known answers
/// — and is the one place the scheme differs observably from the threshold
/// signatures it is compared against, which are not.
#[test]
fn signing_is_deterministic() {
    const PRIV: &str = "781186FB9EF17DB6E3D1056550D9FAE5D5BBADA6A6BC370E4CBB938B1DC71DA3";
    let (first, _) = run(env!("CARGO_BIN_EXE_sign-blake2b"), &[PRIV, GENESIS_HASH]);
    let (second, _) = run(env!("CARGO_BIN_EXE_sign-blake2b"), &[PRIV, GENESIS_HASH]);
    assert_eq!(first, second, "signing the same message twice differed");
}

/// Both signers reproduce the pair docs.nano.org publishes side by side.
///
/// The Nano documentation illustrates the substitution with the all-zero key:
/// "Incorrect, SHA-512 has been used" gives `3B6A27BC…`, and "Correct,
/// Blake2b-512 digested the seed" gives `19D3D919…`. Hitting both values with
/// the two signers pins this repository's whole premise to an official Nano
/// source rather than to its own arithmetic.
#[test]
fn both_signers_match_the_published_substitution_example() {
    const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const SHA512_KEY: &str = "3B6A27BCCEB6A42D62A3A8D02A6F0D73653215771DE243A63AC048A18B59DA29";
    const BLAKE2B_KEY: &str = "19D3D919475DEED4696B5D13018151D1AF88B2BD3BCFF048B45031C1F36D1858";

    let (std_out, code) = run(env!("CARGO_BIN_EXE_sign-std"), &[ZERO, "00"]);
    assert_eq!(code, 0);
    assert_eq!(
        std_out.lines().next().unwrap(),
        SHA512_KEY,
        "SHA-512 expansion does not match the documented 'incorrect' value"
    );

    let (blake_out, code) = run(env!("CARGO_BIN_EXE_sign-blake2b"), &[ZERO, "00"]);
    assert_eq!(code, 0);
    let derived = blake_out
        .lines()
        .find(|l| l.starts_with("public key"))
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap();
    assert_eq!(
        derived, BLAKE2B_KEY,
        "Blake2b-512 expansion does not match the documented 'correct' value"
    );
}
