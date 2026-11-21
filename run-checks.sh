#!/usr/bin/env bash
# Re-runs the local verification outcomes this repository documents, comparing
# both the exit code and the output text against expectations hardcoded below.
# Exits non-zero if anything deviates, so it can be used in CI.
#
# It does NOT read the README's prose. It greps the page for the constants it
# pins, which catches a page left behind entirely, but a constant that occurs
# more than once survives having one occurrence corrupted, and a false sentence
# next to a correct number passes. This is a regression harness, not a proof.
#
# Output text is compared as well as exit codes: a tool that exits correctly
# while printing something else would otherwise pass.
#
# Provenance is covered, offline: derive-key re-derives the published key from
# the IC's master public key, so no canister and no network are needed.
set -u

cd "$(dirname "$0")/verify" || exit 2
cargo build --release --locked --quiet || exit 2
# Respect CARGO_TARGET_DIR instead of assuming ./target, which is set on many
# shared build setups and silently moves every binary.
TARGET_DIR=$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
  | tr ',' '\n' | grep -o '"target_directory":"[^"]*"' | cut -d'"' -f4)
BIN=${TARGET_DIR:-target}/release
[ -x "$BIN/verify-std" ] || { echo "cannot find the built binaries in $BIN" >&2; exit 2; }

ICP_PK=0CB17E3D5171C41E2CE62A90996167EBD6ED0176CC7C569A5FF638746C1EB534
MSG=991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948
ICP_SIG=6E171132DF40BA82E3FE76FB6AFF28CD6EA9666560425DBCD214348E0375A6E1A2DD2888F4E7DE15CEB07BEA27C23C41D55D8F8321E37F09C5FE769A65DCCA04
G_PK=E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA
G_SIG=9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02
GENESIS_ADDRESS=nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3
ICP_ADDRESS=nano_157jhryo4wg65rpgecnim7iphtypxn1qfm5wctf7zxjrgjp3xfbnc3jqsk6o
DOCS_PRIV=781186FB9EF17DB6E3D1056550D9FAE5D5BBADA6A6BC370E4CBB938B1DC71DA3
DOCS_PUB=3068BB1CA04525BB0E416C485FE6A67FD52540227D267CC8B6E8DA958A7FA039
NOT_A_POINT=02$(printf '00%.0s' $(seq 31))
SMALL_ORDER=0000000000000000000000000000000000000000000000000000000000000080
# A point of mixed order: the genesis key plus a point of small order. It is
# NOT torsion free and it is NOT of small order, so it is the one input that
# tells the two properties apart. Without it, a check that confused them — say
# one testing !is_small_order() where it means is_torsion_free() — would pass
# every other case here, and torsion freeness is what the uniqueness of k mod L
# rests on.
MIXED_ORDER=BC667ACA928625397FF4068F1847B2FBE18CA7D7B60DB4950D89927547D703D8
# The identity point: torsion free (order 1 divides L) but of small order. It
# is the mirror image of MIXED_ORDER and isolates the other property — without
# it, a check that dropped the small-order test entirely would still pass,
# because every other small-order input here also fails torsion.
IDENTITY=0100000000000000000000000000000000000000000000000000000000000000
EXPECTED_TESTS=9
CANISTER=n7vqs-xqaaa-aaaao-bbtzq-cai
SUBNET=o3ow2-2ipam-6fcjo-3j5vt-fzbge-2g7my-5fz2m-p4o2t-dwlc4-gt2q7-5ae
MODULE_HASH=ad8f4a4b2c7bd2bc116dc02217fb81f09b048cf35ae3d7513a92b200ec3b32f6
# The IC's mainnet master public keys. Key derivation is a pure function of a
# master key and the path, so the published key is re-derivable offline — no
# canister, no cycles, no network. The second one is the production key and is
# used as a negative control: a different master must give a different key.
MASTER_TEST_KEY_1=6c0824beb37621bcca6eecc237ed1bc4e64c9c59dcb85344aa7f9cc8278ee31f
MASTER_KEY_1=476374d9df3a8af28d3164dc2422cff894482eadd1295290b6d9ad92b2eeaa5c
# The genesis signature with S replaced by S + L. A node accepts it, a strict
# RFC 8032 verifier does not; both halves are checked below.
S_PLUS_L=${G_SIG:0:64}19E65D3BC8DF38BCC9F3DA1D99300ADA8E46DBA03E523A7B5A19E4B6EB12BB12

failures=0
skipped=0
pass() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n     %s\n' "$1" "$2"; failures=$((failures + 1)); }

# expect <label> <exit> <substring the output must contain> -- <command...>
expect() {
  local label=$1 want_code=$2 want_text=$3; shift 4
  local output; output=$("$@" 2>&1); local code=$?
  if [ "$code" != "$want_code" ]; then
    fail "$label" "expected exit $want_code, got $code: $(echo "$output" | head -1)"
  elif [ -n "$want_text" ] && ! grep -qF -- "$want_text" <<<"$output"; then
    fail "$label" "output does not contain '$want_text': $(echo "$output" | head -1)"
  else
    pass "$label"
  fi
}

# expect_count <label> <n> <substring> -- <command...>
# Some properties are printed once per object (the key and R), so presence is
# not enough — the number of occurrences is the claim.
expect_count() {
  local label=$1 want=$2 needle=$3; shift 4
  local output; output=$("$@" 2>&1)
  local got; got=$(grep -cF -- "$needle" <<<"$output")
  if [ "$got" = "$want" ]; then
    pass "$label"
  else
    fail "$label" "expected $want occurrences of '$needle', got $got"
  fi
}

echo "the four cross-checks"
expect "1 ICP signature / RFC 8032"       0 "VALID   (Ed25519, RFC 8032"            -- "$BIN"/verify-std     "$ICP_PK" "$MSG" "$ICP_SIG"
expect "2 ICP signature / Nano Blake2b"   1 "INVALID (Ed25519-Blake2b"              -- "$BIN"/verify-blake2b "$ICP_PK" "$MSG" "$ICP_SIG"
expect "3 genesis block / Nano Blake2b"   0 "VALID   (Ed25519-Blake2b"              -- "$BIN"/verify-blake2b "$G_PK"   "$MSG" "$G_SIG"
expect "4 genesis block / RFC 8032"       1 "INVALID (Ed25519, RFC 8032"            -- "$BIN"/verify-std     "$G_PK"   "$MSG" "$G_SIG"

echo "the message really is the genesis block hash"
expect "block hash recomputed"            0 "$MSG"                                  -- "$BIN"/block-hash "$G_PK"

echo "structural properties the README relies on"
expect "structure, ICP vector"            0 "torsion free: yes"                     -- "$BIN"/point-checks "$ICP_PK" "$ICP_SIG" --assert
expect "structure, genesis vector"        0 "torsion free: yes"                     -- "$BIN"/point-checks "$G_PK"   "$G_SIG"   --assert
# Both the key and R must be reported torsion free and not small order, so the
# count is asserted: a deleted line would otherwise still match the substring.
expect_count "ICP: 2 torsion-free objects"     2 "torsion free: yes"                -- "$BIN"/point-checks "$ICP_PK" "$ICP_SIG" --assert
expect_count "ICP: 2 not-small-order objects"  2 "not small order: yes"             -- "$BIN"/point-checks "$ICP_PK" "$ICP_SIG" --assert
expect_count "genesis: 2 torsion-free"         2 "torsion free: yes"                -- "$BIN"/point-checks "$G_PK"   "$G_SIG"   --assert
expect "assert rejects a non-point"       1 "decompresses: no"                      -- "$BIN"/point-checks "$NOT_A_POINT"  --assert
expect "assert rejects a small-order key" 1 "not small order: no"                   -- "$BIN"/point-checks "$SMALL_ORDER"  --assert
# Both lines are asserted, because the point of this input is the combination:
# torsion freeness must fail while small order passes. One line alone would not
# distinguish a tool that tests the wrong property.
mixed=$("$BIN"/point-checks "$MIXED_ORDER" 2>&1)
if ! grep -qF "torsion free: no" <<<"$mixed"; then
  fail "mixed-order key" "expected 'torsion free: no': $(head -2 <<<"$mixed" | tr '\n' ' ')"
elif ! grep -qF "not small order: yes" <<<"$mixed"; then
  fail "mixed-order key" "expected 'not small order: yes': $(head -3 <<<"$mixed" | tr '\n' ' ')"
else
  pass "mixed-order key is not torsion free but not small order either"
fi
expect "assert rejects a mixed-order key" 1 "torsion free: no"                      -- "$BIN"/point-checks "$MIXED_ORDER"  --assert
# Mirror control: torsion passes, small order fails. Both lines again, because
# the combination is the point.
ident=$("$BIN"/point-checks "$IDENTITY" "$G_SIG" 2>&1)
if ! grep -qF "torsion free: yes" <<<"$ident"; then
  fail "identity key" "expected 'torsion free: yes': $(head -3 <<<"$ident" | tr '\n' ' ')"
elif ! grep -qF "not small order: no" <<<"$ident"; then
  fail "identity key" "expected 'not small order: no': $(head -3 <<<"$ident" | tr '\n' ' ')"
else
  pass "identity key is torsion free but of small order"
fi
expect "assert rejects the identity key"  1 "not small order: no"                   -- "$BIN"/point-checks "$IDENTITY"     "$G_SIG" --assert
# Both isolating controls on the R side as well, since R is checked for the
# same properties as the key.
MIXED_R=${MIXED_ORDER}${G_SIG:64:64}
IDENTITY_R=${IDENTITY}${G_SIG:64:64}
expect "assert rejects a mixed-order R"   1 "torsion free: no"                      -- "$BIN"/point-checks "$G_PK" "$MIXED_R"    --assert
expect "assert rejects an identity R"     1 "not small order: no"                   -- "$BIN"/point-checks "$G_PK" "$IDENTITY_R" --assert
TORSION_R=${SMALL_ORDER}${G_SIG:64:64}
NONCANONICAL_S=${G_SIG:0:64}FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
expect "assert rejects a torsion R"       1 "torsion free: no"                      -- "$BIN"/point-checks "$G_PK" "$TORSION_R"      --assert
expect "assert rejects a non-point R"     1 "R            decompresses: no"         -- "$BIN"/point-checks "$G_PK" "${NOT_A_POINT}${G_SIG:64:64}" --assert
expect "assert rejects non-canonical S"   1 "canonical (S < L): no"                 -- "$BIN"/point-checks "$G_PK" "$NONCANONICAL_S" --assert

echo "malformed input is ERROR, not a failed signature — on both sides"
BAD_S=${ICP_SIG:0:64}FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
BAD_R=${NOT_A_POINT}${ICP_SIG:64:64}
expect "non-canonical S / RFC 8032"       2 "S is not canonical"                    -- "$BIN"/verify-std     "$ICP_PK"      "$MSG" "$BAD_S"
expect "non-canonical S / Nano Blake2b"   2 "S is not canonical"                    -- "$BIN"/verify-blake2b "$ICP_PK"      "$MSG" "$BAD_S"
expect "R not a curve point / RFC 8032"   2 "R is not a valid curve point"          -- "$BIN"/verify-std     "$ICP_PK"      "$MSG" "$BAD_R"
expect "R not a curve point / Nano"       2 "R is not a valid curve point"          -- "$BIN"/verify-blake2b "$ICP_PK"      "$MSG" "$BAD_R"
expect "key not a curve point / RFC 8032" 2 "not a valid curve point"               -- "$BIN"/verify-std     "$NOT_A_POINT" "$MSG" "$ICP_SIG"
expect "key not a curve point / Nano"     2 "not a valid curve point"               -- "$BIN"/verify-blake2b "$NOT_A_POINT" "$MSG" "$ICP_SIG"

echo "the consensus divergence at S + L"
# The README says a node accepts S + L while a strict verifier refuses it.
# Both halves are run here, so the claim cannot rot into prose — and the vector
# cannot be swapped for some other non-canonical S without this failing.
expect "S+L refused by the strict rule"   2 "S is not canonical"                    -- "$BIN"/verify-blake2b "$G_PK" "$MSG" "$S_PLUS_L"
expect "S+L accepted the way a node does" 0 "VALID   (Ed25519-Blake2b, nano-node"   -- "$BIN"/verify-blake2b "$G_PK" "$MSG" "$S_PLUS_L" --donna-compat
expect "donna mode still rejects garbage" 1 "INVALID"                               -- "$BIN"/verify-blake2b "$G_PK" "$MSG" "$ICP_SIG" --donna-compat
# donna never unpacks R; it recomputes R and compares the bytes. The observable
# consequence is the verdict on an R that is not a curve point: the strict path
# calls it malformed and stops, the node's rule runs on to the equation and
# calls it invalid. vectors.json states this property, so both answers are
# pinned here -- adding the decompression to donna mode has to fail.
BAD_R_G=${NOT_A_POINT}${G_SIG:64:64}
expect "strict refuses a non-point R"     2 "R is not a valid curve point"          -- "$BIN"/verify-blake2b "$G_PK" "$MSG" "$BAD_R_G"
expect "donna runs on to the equation"    1 "verification equation does not hold"   -- "$BIN"/verify-blake2b "$G_PK" "$MSG" "$BAD_R_G" --donna-compat
# donna rejects S when any of the top three bits of its last byte is set
# (RS[63] & 224). One case per bit, so weakening the mask to any narrower one
# fails here: S + 2L sets bit 5 (byte 63 = 0x22), S + 4L bit 6 (0x42) and
# S + 8L bit 7 (0x82). S + L, above, sets none of them and is accepted.
S_PLUS_8L=${G_SIG:0:64}94B116C68095B924A63DA092AF05236C8F46DBA03E523A7B5A19E4B6EB12BB82
S_PLUS_2L=${G_SIG:0:64}06BA5398E2424B14A090D2C0772AE9EE8E46DBA03E523A7B5A19E4B6EB12BB22
S_PLUS_4L=${G_SIG:0:64}E0613F52170970C44CCAC106351EA7188F46DBA03E523A7B5A19E4B6EB12BB42
expect "donna rejects bit 5 of S"         2 "S has high bits set"                   -- "$BIN"/verify-blake2b "$G_PK" "$MSG" "$S_PLUS_2L" --donna-compat
expect "donna rejects bit 6 of S"         2 "S has high bits set"                   -- "$BIN"/verify-blake2b "$G_PK" "$MSG" "$S_PLUS_4L" --donna-compat
expect "donna rejects bit 7 of S"         2 "S has high bits set"                   -- "$BIN"/verify-blake2b "$G_PK" "$MSG" "$S_PLUS_8L" --donna-compat
expect "and the strict rule rejects it"   2 "S is not canonical"                    -- "$BIN"/verify-blake2b "$G_PK" "$MSG" "$S_PLUS_8L"

echo "the cofactor divergence"
# The other classic Ed25519 split, besides non-canonical S. R here is rB plus a
# point of order 8, so [S]B - [k]A - R has order 8 instead of being the identity.
# Order 8 rather than 4 fixes the cofactor as well: a mode multiplying by 4
# rejects this signature, so the 8 cannot be weakened unnoticed.
# The cofactorless equation rejects that; the cofactored one, testing [8][S]B =
# [8]R + [8][k]A, accepts it. Both verdicts are asserted below, so the choice of
# equation is pinned from each side rather than only from the rejecting one: a
# cofactorless rule that started accepting fails the first line, and a
# --cofactored mode that stopped accepting fails the third. The key is the
# published docs.nano.org one, so the case rests on nothing local.
COFACTOR_SIG=D6FB15FA6CF2EB955BA5103501B8D79CE326C82FA044BA7B2C45A52FCFC712671A5EF4B6B139832616663C9CC0FEACEB24AEF0B42A7A4BBE8670369C00EDCC0E
expect "cofactorless rejects an order-8 R" 1 "INVALID"                                -- "$BIN"/verify-blake2b "$DOCS_PUB" "$MSG" "$COFACTOR_SIG"
expect "the node's rule rejects it too"    1 "INVALID"                                -- "$BIN"/verify-blake2b "$DOCS_PUB" "$MSG" "$COFACTOR_SIG" --donna-compat
expect "the cofactored rule accepts it"    0 "cofactored equation"                    -- "$BIN"/verify-blake2b "$DOCS_PUB" "$MSG" "$COFACTOR_SIG" --cofactored
# Not a parse failure: INVALID above, not ERROR. What is unusual about it is
# R's torsion component.
expect "its R is the order-8 carrier"      1 "torsion free: no"                       -- "$BIN"/point-checks "$DOCS_PUB" "$COFACTOR_SIG" --assert
# The two modes are different rules, so asking for both is refused rather than
# silently resolved to one of them.
expect "the two modes are exclusive"       2 "different rules"                        -- "$BIN"/verify-blake2b "$DOCS_PUB" "$MSG" "$COFACTOR_SIG" --donna-compat --cofactored
expect "they agree on the genesis vector"  0 "cofactored equation"                    -- "$BIN"/verify-blake2b "$G_PK" "$MSG" "$G_SIG" --cofactored
# --cofactored swaps the equation and nothing else, so the strict parse rules
# still apply: a non-point R is ERROR there too, not a failed equation. Without
# this line, dropping the decompression check from that mode passes the suite.
expect "cofactored keeps the parse rules" 2 "R is not a valid curve point"          -- "$BIN"/verify-blake2b "$G_PK" "$MSG" "$BAD_R_G" --cofactored

echo "address derivation"
expect "genesis account derives"          0 "$GENESIS_ADDRESS"                      -- "$BIN"/pubkey-to-address "$G_PK"
expect "ICP key derives its address"      0 "$ICP_ADDRESS"                          -- "$BIN"/pubkey-to-address "$ICP_PK"

echo "the signer reproduces Nano signatures"
# The derived key is checked against the pair published on docs.nano.org, so
# this does not only compare our own tools with each other.
expect "signer matches published keypair" 0 "$DOCS_PUB"                             -- "$BIN"/sign-blake2b "$DOCS_PRIV" "$MSG"
DOCS_SIG=$("$BIN"/sign-blake2b "$DOCS_PRIV" "$MSG" | awk '/signature/{print $2}')
expect "its signature verifies as Nano"   0 "VALID   (Ed25519-Blake2b"              -- "$BIN"/verify-blake2b "$DOCS_PUB" "$MSG" "$DOCS_SIG"
expect "and fails as RFC 8032"            1 "INVALID (Ed25519, RFC 8032"            -- "$BIN"/verify-std     "$DOCS_PUB" "$MSG" "$DOCS_SIG"

echo "the substitution, against Nano's own documentation"
# docs.nano.org prints both derivations for the all-zero key: SHA-512 gives
# 3B6A27BC…, Blake2b-512 gives 19D3D919…. Each signer must land on its own.
ZERO=0000000000000000000000000000000000000000000000000000000000000000
expect "SHA-512 hits the documented key"  0 "3B6A27BCCEB6A42D62A3A8D02A6F0D73653215771DE243A63AC048A18B59DA29" -- "$BIN"/sign-std      "$ZERO" "00"
expect "Blake2b hits the documented key"  0 "19D3D919475DEED4696B5D13018151D1AF88B2BD3BCFF048B45031C1F36D1858" -- "$BIN"/sign-blake2b "$ZERO" "00"

echo "the RFC 8032 signer the README documents"
# sign-std is in the tools table; without this nothing would notice if it
# started emitting garbage.
STD_SEED=0101010101010101010101010101010101010101010101010101010101010101
readarray -t std < <("$BIN"/sign-std "$STD_SEED" "$MSG")
expect "sign-std output verifies"         0 "VALID   (Ed25519, RFC 8032"            -- "$BIN"/verify-std "${std[0]}" "$MSG" "${std[1]}"
expect "and is rejected as Nano"          1 "INVALID (Ed25519-Blake2b"              -- "$BIN"/verify-blake2b "${std[0]}" "$MSG" "${std[1]}"

echo "unit tests"
# The count is asserted too: cargo test exits zero when there are no tests at
# all, so a deleted test file would otherwise pass unnoticed.
test_output=$(cargo test --release --locked 2>&1)
if grep -qF "test result: ok. $EXPECTED_TESTS passed" <<<"$test_output"; then
  pass "cargo test ($EXPECTED_TESTS tests)"
else
  fail "cargo test" "expected 'test result: ok. $EXPECTED_TESTS passed', got: $(grep -E 'test result' <<<"$test_output" | tail -1)"
fi

echo "the documents agree with the values tested here"
# The vectors are duplicated in four places: README.md, this script,
# vectors.json and the test file. These checks keep the four copies in step.
# They are presence checks only — they say nothing about the surrounding text.
# Whitespace is stripped first, because the README wraps signatures over two
# lines.
readme=$(tr -d '[:space:]' < ../README.md)
vectors=$(tr -d '[:space:]' < ../vectors.json)
tests=$(tr -d '[:space:]' < tests/known_answers.rs)
in_doc() {
  local label=$1 haystack=$2 needle=$3
  if grep -qF -- "$needle" <<<"$haystack"; then pass "$label"; else fail "$label" "not found: $needle"; fi
}
in_doc "README: ICP public key"           "$readme"  "$ICP_PK"
in_doc "README: ICP signature"            "$readme"  "$ICP_SIG"
in_doc "README: genesis public key"       "$readme"  "$G_PK"
in_doc "README: genesis signature"        "$readme"  "$G_SIG"
in_doc "README: message"                  "$readme"  "$MSG"
in_doc "README: genesis address"          "$readme"  "$GENESIS_ADDRESS"
in_doc "README: ICP address"              "$readme"  "$ICP_ADDRESS"
in_doc "README: canister id"              "$readme"  "$CANISTER"
in_doc "README: subnet"                   "$readme"  "$SUBNET"
in_doc "README: module hash"              "$readme"  "$MODULE_HASH"
in_doc "README: test_key_1 master"        "$readme"  "$MASTER_TEST_KEY_1"
in_doc "vectors.json: ICP public key"     "$vectors" "$ICP_PK"
in_doc "vectors.json: genesis public key" "$vectors" "$G_PK"
in_doc "vectors.json: message"            "$vectors" "$MSG"
in_doc "vectors.json: ICP signature"      "$vectors" "$ICP_SIG"
in_doc "vectors.json: genesis signature"  "$vectors" "$G_SIG"
in_doc "vectors.json: S+L case"           "$vectors" "$S_PLUS_L"
in_doc "vectors.json: cofactor case"      "$vectors" "$COFACTOR_SIG"
in_doc "vectors.json: cofactored column"  "$vectors" "ed25519_blake2b_cofactored"
in_doc "tests: ICP signature"             "$tests"   "$ICP_SIG"
in_doc "tests: genesis signature"         "$tests"   "$G_SIG"

echo "the published key derives offline from the subnet master key"
# The provenance half of the vector, and it needs nothing but arithmetic. If
# this passes, the published key really is the test_key_1 key of the canister
# named above — the trust anchor being DFINITY's published master key rather
# than a live reply from the subnet.
expect "key derives from test_key_1 master"  0 "$ICP_PK"  -- "$BIN"/derive-key "$MASTER_TEST_KEY_1" "$CANISTER"
# A negative control, so the check above cannot pass by printing anything at
# all: the production master must derive something else.
other=$("$BIN"/derive-key "$MASTER_KEY_1" "$CANISTER" 2>&1)
if grep -qF -- "$ICP_PK" <<<"$other"; then
  fail "production master" "derived the same key as test_key_1"
elif grep -q '^derived key   [0-9A-F]\{64\}$' <<<"$other"; then
  pass "production master derives a different key"
else
  fail "production master" "no derived key in output: $(head -1 <<<"$other")"
fi
# A mistyped canister id must be refused, not derived from. Last character
# changed, which breaks the principal's CRC.
expect "derive-key refuses a bad canister id" 2 "CRC mismatch" -- "$BIN"/derive-key "$MASTER_TEST_KEY_1" "${CANISTER%?}x"

echo "the signer rebuilds to the recorded module hash"
# If this fails after a change to signer/, that is expected, not a bug here:
# the hash moves whenever the line positions of the code move, whenever a string
# literal changes, and whenever signer.did changes, since dfx embeds it. Never "fix" the constant to match a new build; the
# recorded value is what the deployed canister reports on chain.
# Compares a local dfx build against MODULE_HASH above. That constant is the
# hash this repository records as deployed; the check does not contact the
# chain, so verifying that the canister still carries it is a separate step
# (dfx canister info, as the README shows). Skipped rather than failed when dfx
# is absent, so the suite needs nothing beyond cargo.
if command -v dfx >/dev/null 2>&1; then
  # signer/build.sh carries the path remapping that keeps this hash independent
  # of where the sources and the registry sit, and prints it. The README points
  # at the same script, so the flag exists in one place only.
  if built=$(../signer/build.sh 2>/dev/null); then
    if [ "$built" = "$MODULE_HASH" ]; then
      pass "signer rebuilds to the recorded module hash"
    else
      fail "module hash" "rebuilt $built, recorded $MODULE_HASH"
    fi
  else
    fail "module hash" "dfx build --check failed"
  fi
else
  printf 'skip %s\n' "module hash (dfx not installed)"
  skipped=$((skipped + 1))
fi

echo "the signing canister still builds"
if (cd ../signer && cargo check --locked --target wasm32-unknown-unknown --quiet >/dev/null 2>&1); then
  pass "signer compiles to wasm32"
else
  fail "signer" "cargo check failed"
fi

echo
if [ "$failures" != 0 ]; then
  echo "$failures check(s) deviated"
elif [ "$skipped" != 0 ]; then
  # A skip is not a pass. Saying so matters most in CI, which has no dfx and
  # therefore never runs the one check tying this source to the canister.
  echo "all checks behaved as documented, $skipped skipped"
else
  echo "all checks behaved as documented"
fi
exit $((failures > 0))
