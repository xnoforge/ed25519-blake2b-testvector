# Ed25519-Blake2b test vector: ICP threshold signatures vs. Nano

Nano signs with an Ed25519 variant that puts **Blake2b-512** where RFC 8032 puts
SHA-512. Same curve, same key format, same 64-byte signature layout — and yet
the Internet Computer's threshold Ed25519 cannot produce a signature a Nano node
accepts.

This repository is the worked example: a reproducible test vector, a reference
verifier for the Blake2b variant implemented from the curve primitives, and the
tooling to reproduce the results.

It is not an argument that the variant should be added, and it settles nothing
beyond what it measures. The incompatibility itself is not in dispute — this
page makes it reproducible and localises it to the one step where the two
schemes diverge. Everything else that using Nano from a canister would involve,
from chain integration to operating it, is outside what is measured here.
Nothing on this page should be taken as a statement by anyone but the author.

This repository is written by Bernhard Klingseisen, who runs Nano
infrastructure on the Internet Computer ([nanogate.run](https://nanogate.run)),
not by a neutral third party.

What this repository adds is the material rather than the argument: a worked
vector, a reference verifier and signer built from the curve primitives, and a
machine-readable set of known-answer tests in
[`vectors.json`](vectors.json) — including the intermediate values an
implementer needs to localise a mistake, and the `S + L` case where a Nano node
and a strict verifier disagree.

## Result

| # | Signature produced by | Verified with | Expected | Observed |
|---|---|---|---|---|
| 1 | ICP `sign_with_schnorr`, `algorithm = ed25519` | Standard Ed25519 (RFC 8032, SHA-512) | valid | **VALID** |
| 2 | ICP `sign_with_schnorr`, `algorithm = ed25519` | Ed25519-Blake2b (Nano) | invalid | **INVALID** |
| 3 | Nano mainnet genesis block | Ed25519-Blake2b (Nano) | valid | **VALID** |
| 4 | Nano mainnet genesis block | Standard Ed25519 (RFC 8032, SHA-512) | invalid | **INVALID** |

Checks 1 and 3 are the controls, and they carry the argument. Without them, the
failures in 2 and 4 would only prove that something somewhere is broken.

```bash
./run-checks.sh
```

needs rustup, which installs the pinned toolchain and the wasm target from
`rust-toolchain.toml`, and bash 4 or later for `readarray`. dfx 0.32.0 is
optional: without it the one check that rebuilds the canister reports `skip` and
the run ends with `1 skipped`. Everything here was built and run on x86_64
Linux; no other host has been tried. A cold run takes about two minutes.

It builds everything and re-runs the local outcomes — the four checks, the
structural properties, the three Blake2b rules, the address derivations,
the signer and the `S + L` divergence — against expectations **hardcoded in the
script itself**. It exits non-zero if any of them deviates.

**It is a regression harness, not a proof.** It does not read this page's prose;
it greps for the constants it pins, which catches a page left behind entirely,
and nothing finer. Values that appear here more than once survive one occurrence
being corrupted, and a false sentence beside a correct number passes. Claims in
sentences are the author's — check them against the sources cited throughout.

One check is not part of a CI run. Rebuilding the module and comparing its
hash needs dfx, which the workflow does not install, so there the suite reports
`skip module hash (dfx not installed)` and ends with `1 skipped`. A green CI run
therefore covers everything except the step that ties this source to the
deployed canister — run `./run-checks.sh` locally with dfx present for that one.

What no verifier can see is where a signature came from: one produced locally a
minute ago satisfies the same equation. That half rests on the public key being
the signing subnet's, and the suite now establishes it — `derive-key` re-derives
the key from the IC's master key offline, so the check runs in CI too, with no
dfx and no network. The next section sets out what that does and does not
settle.

## The vector

### ICP threshold Ed25519

```
public key   0CB17E3D5171C41E2CE62A90996167EBD6ED0176CC7C569A5FF638746C1EB534
message      991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948
signature    6E171132DF40BA82E3FE76FB6AFF28CD6EA9666560425DBCD214348E0375A6E1
             A2DD2888F4E7DE15CEB07BEA27C23C41D55D8F8321E37F09C5FE769A65DCCA04
```

Produced on 2026-11-20 by the canister in `signer/`, deployed to ICP mainnet as
`n7vqs-xqaaa-aaaao-bbtzq-cai` on subnet `o3ow2-2ipam-6fcjo-3j5vt-fzbge-2g7my-5fz2m-p4o2t-dwlc4-gt2q7-5ae`,
with `key_id.algorithm = ed25519`, `key_id.name = test_key_1` and an empty
derivation path. The canister was stopped after the run and still is. Its module hash on chain is
`ad8f4a4b2c7bd2bc116dc02217fb81f09b048cf35ae3d7513a92b200ec3b32f6`:

```bash
dfx canister info n7vqs-xqaaa-aaaao-bbtzq-cai --network ic
```

That hash is the SHA-256 of exactly the module `signer/` in this repository
builds. Reproducing it needs no replica and no cycles — only dfx and, on a cold
cargo cache, the network to fetch the pinned crates.

```bash
signer/build.sh
```

It prints `ad8f4a4b…` on the setup under [Environment](#environment); a
different dfx or rustc can emit a different module from the same source, and so
can a different crates.io registry protocol — the sparse index and the git
index put different directory names into the registry paths rustc records, which
the remapping below does not rewrite. You can see for yourself that no local
path survives: `strings` on the wasm finds `/cargo/registry/...` and no home
directory.

The script is a `dfx build --check` with one `--remap-path-prefix` flag, for
`CARGO_HOME`, and that flag is why the build goes through a script rather than a
bare dfx command: rustc writes absolute paths into panic metadata, so without it
your registry location ends up in the module, and your hash differs from the one
recorded here. The checkout location needs no remapping: a build that remaps only the
checkout and not `CARGO_HOME` produces the same hash as a build with no
remapping at all, because the local crate's recorded paths are relative. The flag is passed in `CARGO_ENCODED_RUSTFLAGS`, which cargo splits on
a separator instead of on whitespace, so a `CARGO_HOME` containing a space works
too. `[profile.release] trim-paths` would say the same thing declaratively in
`Cargo.toml`; it is not stabilised in Cargo 1.93.1, which `rust-toolchain.toml`
pins, so the flag is set in the script instead. `run-checks.sh` runs the same
script, so the flag cannot drift from this page. Use dfx rather than
`cargo build` — dfx embeds Candid metadata and shrinks the module afterwards, so
a plain release build hashes differently.

Because the module matches, so do the constants compiled into it — the key name
`test_key_1` and the empty derivation path in `signer/src/lib.rs` are part of
what the hash pins.

**So `signer/` is best left alone.** The compiled module records where each
potential panic sits in the source, which is why the hash moves when the line
positions of the code move. Measured on `signer/src/lib.rs`: inserting a comment
line *above* the code moves it, appending one after all the code does not, and
rewording a comment in place does not — but rewording a string literal does,
because the literal is compiled in. `signer/src/lib.rs` is not the only file
that counts: dfx embeds the Candid interface in the module, so editing
`signer/signer.did` moves the hash as well, comments included. Any edit that
moves the hash breaks both the rebuild check here and the match with the
deployed module.

Two things the hash does **not** do. It does not attest to the signature — it
identifies the code that ran, nothing more. And it will not last forever: a
stopped canister is eventually uninstalled once its cycles are exhausted, at
which point the module hash on chain becomes `null`. The signature and the
public key stay checkable either way, because the key derivation below does not
depend on this canister still existing.

**Checking that the key really is the subnet's.** One distinction first: the
canister runs on `o3ow2-…`, but the `test_key_1` key material lives on the IC's
**signing** subnet, a different one. This is the step that turns the vector from
"a signature that verifies" into "a signature only the signing subnet could have
produced", and it needs neither a canister nor cycles nor the network —
derivation is a pure function of a master public key and the path, which the
interface specification lists as a design requirement:

```bash
verify/target/release/derive-key \
  6c0824beb37621bcca6eecc237ed1bc4e64c9c59dcb85344aa7f9cc8278ee31f \
  n7vqs-xqaaa-aaaao-bbtzq-cai
```

The output is `0CB17E3D…1EB534`, the key check 1 verifies against. `run-checks.sh`
runs this, with the **production** `key_1` master as a negative control and a
principal checksum that refuses a mistyped id.

**That hex is the whole anchor, so check it at the source.** It is DFINITY's
mainnet `test_key_1` master public key, in
[`packages/ic-ed25519/src/lib.rs`](https://github.com/dfinity/ic/blob/master/packages/ic-ed25519/src/lib.rs)
as `PublicKey::mainnet_key`. Anyone free to choose that constant could forge
this vector outright — pick a master whose secret you hold, derive, sign
locally. Take it from DFINITY, not from this page.

If you would rather have the subnet answer directly, `schnorr_public_key` is
callable by canisters only, so that means deploying one of your own:

```bash
cd signer
dfx deploy signer --network ic          # your canister, your cycles
dfx canister call signer get_public_key \
  '(opt principal "n7vqs-xqaaa-aaaao-bbtzq-cai")' --network ic
```

Either route must give `0CB17E3D…1EB534`. No single party holds the private half
of a subnet-derived key — it exists only as shares across the signing subnet —
so a signature verifying under it could not have been produced elsewhere without
breaking that threshold assumption. That is the strength of the claim and its
limit: a threshold-security assumption, not a certificate. `test_key_1` is also
a **test** key, in assurance terms and in the sense that a rotation would stop
this vector reproducing.

Two properties of the API are worth knowing before reproducing any of it. The
subnet derives from the **calling canister's id**, so `get_public_key` with no
argument returns *your* key rather than ours, and a fresh deployment yields a
different one. And `sign_with_schnorr` is non-deterministic: signing the same
message twice returns two different valid signatures.

The message is the Nano mainnet genesis block hash. It carries no special
meaning here — it is used so that all four checks sign and verify a message of
the same shape, a 32-byte Nano block hash, removing one variable from the
comparison.

### Nano mainnet genesis block

```
account      nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3
public key   E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA
block hash   991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948
signature    9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E
             2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02
```

Source: `nanocurrency/nano-node`, tag `V27.0`, `nano/secure/common.cpp`,
`live_genesis_data` — where the account is written with the legacy `xrb_`
prefix rather than `nano_`; the two encode the same account. The genesis block was chosen because it is public,
permanent and independently checkable. It is a legacy `open` block, so its hash
is `Blake2b-256(source ‖ representative ‖ account)` with all three fields set to
the genesis account's public key — no state-block preamble, which makes the hash
recomputable from first principles rather than merely lookup-able.

## Machine-readable vectors

`vectors.json` carries the same material in a form another implementation's
test suite can read directly, rather than as prose to be retyped:

* the four **verification** cases — the ICP signature, the genesis block, the
  genesis signature with `S + L`, and an `R` carrying a point of order 8 — each
  with its expected outcome under four rules: RFC 8032, the strict
  Ed25519-Blake2b implemented here, `ed25519_blake2b_donna`, which is what
  nano-node actually accepts, and `ed25519_blake2b_cofactored`, which keeps the
  strict parse rules but uses the cofactored equation. The donna field exists
  because for `S + L` the
  strict rule and the node disagree, and an implementation aiming at consensus
  has to match the node. Dropping the file into a test suite without that field
  would encode the opposite. The last two cases are the two classic Ed25519
  interoperability splits: non-canonical `S`, where this repository is stricter
  than the node, and the cofactor, where it is not;
* six **signing** cases produced by `sign-blake2b`, with the public key, the
  signature, and every intermediate value: the clamped scalar, `a mod L`, the
  nonce digest, `r`, `R`, the challenge digest, `k` and `S`.

The intermediates are the point. A pass/fail outcome tells an implementer that
something is wrong; `r` and `k` tell them where. Messages of length 0, 1, 32 and
200 bytes are covered, together with an all-zero and a counting private key.

`cargo test` re-runs every case in the file through the tools, so it cannot
drift from them. The key expansion is additionally checked against the keypair
published on docs.nano.org for `key_expand`, which is an external reference
rather than this repository's own output.

> The private keys in that file are test material and the accounts they derive
> are real Nano accounts. **Do not fund them.**

**What transfers to a threshold implementation, and what does not.** Of the
eight intermediates per case, four belong to the single-signer path and have no
counterpart in threshold signing: `clamped` and `a` come from key expansion,
which the IC's derivation does not perform at all — the interface spec notes it
"does not make use of clamping" — while `nonce` and `r` come from hashing the
private key, where a threshold signer takes its nonce from an IDKG presignature.
What transfers is the challenge step itself — `(R, A, M)` to `challenge` to
`k` — and the verification outcome. `R` and `S` are listed with them, but these
values depend on the nonce and the expanded key, so a threshold signer will not
reproduce them. Treat the rest as
useful for checking a single-signer implementation and nothing more.

**On determinism, and why these are not nano-node's bytes.** Signing here is
deterministic: the nonce is `Blake2b-512(prefix ‖ M)`, the RFC 8032 rule, which
is what makes the cases usable as known answers. nano-node does **not** do
this. It patched ed25519-donna to randomise the nonce — its signing path
(`crypto/ed25519-donna/ed25519.c:69-83`) computes
`r = H(extsk[32..63] ‖ 32 random bytes ‖ 64 zero bytes ‖ M)`, with the
randomness from `ed25519_randombytes_unsafe`
(`nano/crypto_lib/interface.cpp:6-9`) and the padding placing the message in
its own hash block; the source comment names side channels as the reason.

So both nano-node and ICP's threshold signer are randomised, and this tool is
the odd one out by choice. The signatures it produces are valid Nano signatures
— any `(R, S)` satisfying the equation is accepted, and the tests verify each
one — but an implementation following nano-node will not reproduce these exact
bytes and should not be expected to. What transfers is the verification side
and the intermediate values of the challenge step; what does not is the nonce.

What is deliberately **out of scope**: Nano's wallet-level seed-to-key
derivation (`Blake2b-256(seed ‖ index)`). It sits above the signature scheme and
has no bearing on the question this repository is about.

**Where this stops being a consensus test suite.** `S >= L` is the one
node-versus-strict divergence covered here, in the `S + L` case. The other
difference between the two paths that this repository pins is whether a
non-decompressable `R` is reported as `ERROR` or as `INVALID`. Small-order and
mixed-order keys, and non-canonical encodings, are not fed to either path by any
check here, so this is not a substitute for differential testing against the
node.

That is a narrower result than it may look, for one reason worth stating
plainly: **neither path has ever been run against `ed25519-donna` itself.**
`--donna-compat` is this repository's model of the node's rule, built from the
source lines cited above, and the model is all that the agreement is between.
Four verification cases are enough to localise the incompatibility, which is
what this repository is for; they are not enough to qualify an implementation
for consensus. Anyone aiming at that should differential-test against donna
rather than extend these vectors.

## Why the signature fails

Both schemes verify a signature `(R, S)` against a public key `A` and a message
`M` with the same equation:

```
k = H(R ‖ A ‖ M)
[S]·B  ==  R + [k]·A          B = the Ed25519 base point
```

The verifier computes `k` itself. Nano uses **Blake2b-512** for `H`, RFC 8032 —
and therefore ICP's threshold Ed25519 — uses **SHA-512**. A different `k` places
`[k]·A` somewhere else on the curve, so the equation does not hold.

This is the cofactorless form. RFC 8032 §5.1.7 prescribes the cofactored check
`[8][S]·B == [8]R + [8][k]·A` and notes that it is *"sufficient, but not
required, to instead check [S]B = R + [k]A'"* — the cofactorless form is the
permitted alternative, not the other way round. Both `ed25519-dalek` and Nano's
ed25519-donna use the cofactorless check, and the distinction does not affect
the two signatures above: neither their keys nor their `R` values carry a
torsion component, which is what `point-checks` below asserts.

Both failures happen at that equation and nowhere earlier:

```bash
verify/target/release/point-checks <pubkey> <signature>
```

reports, for the public key and for `R` alike, that they decompress, are
torsion free and are not of small order, and that `S` is canonical. With `--assert` it
exits non-zero when a property is missing, which is how `run-checks.sh` enforces
this rather than printing it. Malformed input is reported as `ERROR` (exit 2) by
both verifiers, a failed equation as `INVALID` (exit 1), so the two cannot be
confused.

The cofactor distinction does affect a signature built to separate the two
forms. With `R` set to
`rB` plus a point of order 8, `[S]·B − [k]·A − R` is a point of order 8 rather
than the identity: the cofactorless rule rejects, and the cofactored rule
accepts, because multiplying by the cofactor sends an order-8 point to zero.
That case is the fourth vector in `vectors.json`, on the keypair
docs.nano.org publishes, and `run-checks.sh` asserts that the strict rule and
the node's rule both reject it.

### Is the hash the only free variable?

On the verification side, yes. Given `(A, R, S, M)`, the hash enters at exactly
one point — `k = H(R‖A‖M)` — and everything after it is curve arithmetic with no
hash in it. That single point is the whole of what the four checks above
exercise.

Signing from a seed is another matter, and worth stating because it is easy to
assume otherwise: Nano substitutes Blake2b in the key expansion and in the nonce
as well as in the challenge. The same seed therefore yields a different public
key under the two schemes — `3B6A27BC…` against `19D3D919…` for the all-zero
key, documented below. `sign-blake2b --intermediates` prints those values for
the Blake2b side, which is what an implementer debugging that side needs; it is
not a comparison of the two schemes, and no SHA-512 equivalent is shipped
here.

**Searching for an alternative challenge computation would add nothing**, which
is why there is no such search here. For a torsion-free `A` and a fixed `R` and
`S` there is exactly one `k` mod L solving the equation. Any second way of
computing the challenge that satisfied it would have to produce that same `k`,
with probability about 2⁻²⁵². Enumerating input orderings, digests and digest
readings therefore demonstrates a theorem, not a fact about Nano, and a check
that cannot meaningfully fail does not belong in a suite.

The same argument covers changes to the *shape* of the computation rather than
one of its parameters. An RFC 8032 §2 `dom2` prefix, Ed25519ph prehashing, or
keying the hash with the public key all come down to a different `k`, so none of
them can satisfy the equation either, and none is enumerated here.

One alternative is not a different `k` but a different **rule**, and that one is
shipped. As quoted above, RFC 8032 §5.1.7 prescribes the cofactored equation
`[8][S]·B == [8]R + [8][k]·A` and permits the cofactorless one as a sufficient
substitute; Nano takes the substitute. Which of the two a verifier applies is
observable, and `--cofactored` applies the prescribed form:

```bash
verify/target/release/verify-blake2b <pubkey> <message> <signature> --cofactored
```

It keeps the same parse rules and swaps only the equation. Nano, donna and dalek
all use the cofactorless form. The fourth vector in `vectors.json` is built so
that the difference `[S]·B − [k]·A − R` has order 8:
the cofactorless rule reports `INVALID`, the cofactored one `VALID`, and
`run-checks.sh` asserts both, so a verifier here cannot be switched between the
two forms unnoticed. Order 8 rather than 4 also fixes the multiplier: a mode
multiplying by 4 rejects this signature, so the 8 cannot be weakened either.

Personalised Blake2b needs no test either, because the source settles it: donna reaches
the hash through `ed25519_hash_init`, which nano defines as `blake2b_init(ctx,
64)` in `nano/crypto_lib/interface.cpp:10-13` — a plain Blake2b state with no
personalisation, salt or key.

## What the documentation states — and what it does not

**On the Nano side**, the page on
[signing, hashing and key derivation](https://docs.nano.org/protocol-design/signing-hashing-and-key-derivation/)
introduces the Blake2b-512 substitution as a matter of key derivation:
*"However, it should be noted that instead of using SHA-512 in the key derivation
function, Nano uses Blake2b-512"*. That same page then demonstrates the
substitution with the all-zero key, printing both results side by side —
*"Incorrect, SHA-512 has been used"* giving `3B6A27BC…`, and *"Correct,
Blake2b-512 digested the seed"* giving `19D3D919…`. `sign-std` and
`sign-blake2b` reproduce those two values respectively, which pins the
substitution to an official Nano source rather than to this repository's own
arithmetic; `run-checks.sh` asserts both.

The [integration basics](https://docs.nano.org/integration-guides/the-basics/)
go further than key derivation, describing the account public key as derived
*"by using the ED25519 curve using Blake2b-512 as the hash function"*, noting
that signing *"internally applies another Blake2b hashing"*, and labelling the
field *"ED25519+Blake2b 512-bit signature"*. What none of the pages consulted
here state is that Blake2b-512 is specifically the **challenge** hash, which is
the thing that breaks compatibility.

The source does, in `nanocurrency/nano-node` at tag `V27.0`:
`crypto/ed25519-donna/ed25519-hash-custom.h` sets `typedef blake2b_state
ed25519_hash_context`, so every hash in that Ed25519 implementation is Blake2b;
`crypto/ed25519-donna/ed25519.c` builds the challenge in `ed25519_hram` as
`RS ‖ pk ‖ m` (lines 34–42) and, on the verification path, reduces all 64 bytes
of it (`expand256_modm(hram, hash, 64)`, line 116); and `nano/lib/numbers.cpp`
reaches it through `validate_message`. The vector confirms that empirically,
against a signature nobody can forge after the fact.

Those citations are pinned to `V27.0`, which is what the vector was produced
against. Checked against the current `V28.2`: `ed25519.c` and `interface.cpp`
are byte-identical, so every line number above still holds. `common.cpp` has
changed — the genesis values are the same, but `live_genesis_data` has moved to
lines 53–60.

**Where the change would go.** The challenge-hash step is one function in
DFINITY's own tree:
[`rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/signing/eddsa.rs`](https://github.com/dfinity/ic/blob/master/rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/signing/eddsa.rs),
`fn ed25519_challenge_hash` (as of November 2026; the link follows `master`).
It writes `r.serialize()`, `p.serialize()` and the
message into SHA-512, reverses the digest and reduces it wide — `R ‖ A ‖ M`,
SHA-512, little-endian, which is byte for byte what `verify-std` and the
intermediates above show.

**On the ICP side**, the
[interface specification](https://docs.internetcomputer.org/references/ic-interface-spec/management-canister/)
cites RFC 8032 for both the key encoding (§5.1.2) and the signature format
(§5.1.6), and states that *"the returned signature is non-deterministic"*. It
does not write "SHA-512" for the signature anywhere; that ICP's Ed25519 is the
SHA-512 variant follows from the RFC reference and from check 1.

## What this shows, and what it does not

It shows that the threshold Ed25519 API available today produces signatures that
verify as standard RFC 8032 signatures and that Nano rejects them.
`schnorr_algorithm` offers exactly two values, `bip340secp256k1` and `ed25519`,
and the request carries no hash parameter. The optional `aux` field has a single
variant, `bip341`, which carries a Taproot Merkle root hash used to tweak the
key, and the spec allows it only for `bip340secp256k1` signatures. It is not a
place a different hash could be requested, and it has nothing to do with the
Ed25519 branch.

Whether one key could safely serve two different challenge hashes is a separate
question, sitting at the threshold layer inside IDKG; nothing measured here
speaks to it.

One boundary is worth drawing explicitly: a canister *can* produce valid Nano
signatures today by holding an Ed25519-Blake2b private key in its own memory and
signing in software. That is not threshold signing — the key exists in plaintext
in replicated canister memory, readable in principle by node providers and by
anyone who can upgrade the canister.

## What was deliberately not tested

No ICP-signed block was broadcast to the Nano network. Such a block would have to
come from the account whose public key is the ICP-derived one — for the key
above, `nano_157jhryo4wg65rpgecnim7iphtypxn1qfm5wctf7zxjrgjp3xfbnc3jqsk6o`. XNO
can be sent to that address but not retrieved, since the receive block would need
a signature **Nano** accepts, and no such signature can be produced for that key
today. RFC 8032 signatures for it can be — check 1 is one.
**Treat anything sent there as gone. Do not fund it.**

The local verification computes the same group equation a Nano node computes
when processing a block — but it is deliberately stricter than a node in two
respects, and both matter to anyone writing an implementation meant to stay in
consensus.

**Non-canonical `S`.** `ed25519-donna`, which nano-node uses, rejects `S` only
when any of the top three bits of its last byte is set —
`if ((RS[63] & 224) || !ge25519_unpack_negative_vartime(&A, pk)) return -1;` in
`crypto/ed25519-donna/ed25519.c` (lines 111–112) — and then reduces mod L. So a node
accepts values in `[L, 2^253)` that the strict path reports as
`ERROR   S is not canonical`. The genesis signature with `S + L` substituted is
exactly such a case: byte 63 becomes `0x12`, so donna's test passes.

Both halves can be run here — but be clear about what the second one is.
`--donna-compat` applies **this repository's model** of donna's rule, written
from the lines cited above; no donna code runs anywhere in this repository.
Anyone who wants the node's own answer should compile `ed25519.c` and feed the
vector to it:

```bash
verify/target/release/verify-blake2b <pubkey> <message> <S+L signature>
#   ERROR   S is not canonical (S >= L)                        exit 2
verify/target/release/verify-blake2b <pubkey> <message> <S+L signature> --donna-compat
#   VALID   (Ed25519-Blake2b, nano-node compatible)            exit 0
```

The case ships as a vector in `vectors.json` and `run-checks.sh` asserts both
outcomes, so the vector cannot be swapped for some other non-canonical `S`
without the suite noticing.

**`R` must decompress.** This verifier decodes `R` as a curve point before doing
anything else; donna never unpacks `R` in `ed25519_sign_open`, it only compares
the recomputed encoding against the given bytes. Where `R` decompresses the two
reach the same verdict, since both then compare the same bytes; where it does
not, the difference is whether that is reported as `ERROR` or as `INVALID`.

Both choices keep malformed input apart from a failed equation, which is what
the four checks are about. Neither is the behaviour of a node, and an
implementation aiming at consensus compatibility has to match donna rather than
this.

## The tools

The command lines below write `verify/target/release/…`. If you have
`CARGO_TARGET_DIR` set — which `run-checks.sh` deliberately honours — the
binaries are under that directory instead; `cargo metadata --format-version 1
--no-deps` prints where.

| | |
|---|---|
| `verify-std` | RFC 8032 verification, via `ed25519-dalek` |
| `verify-blake2b` | Nano's variant, implemented here from the curve primitives; `--donna-compat` applies nano-node's looser rule, `--cofactored` swaps the verification equation for RFC 8032 §5.1.7's cofactored form |
| `sign-blake2b` | a deterministic Ed25519-Blake2b signer, likewise from the primitives; `--intermediates` prints every value in the signing equation. Its signatures are valid for Nano but are **not** nano-node's bytes — see the note on determinism |
| `sign-std` | a local RFC 8032 signer, to rehearse checks 1 and 2 without spending cycles; same scheme as `sign_with_schnorr`, but deterministic |
| `point-checks` | decompression, torsion and canonicality of a key and signature |
| `derive-key` | re-derives an IC threshold Ed25519 public key offline from a master key and a canister id; HMAC and HKDF implemented here, no extra dependency |
| `block-hash` | recomputes the genesis block hash from the account's public key |
| `pubkey-to-address` | Nano address derivation, with the base32 alphabet and the Blake2b-40 checksum implemented here. It takes a public key and prints the address; `run-checks.sh` runs it on the genesis key and on the ICP key and compares both against the published addresses |
| `signer/` | the canister that produced the ICP signature |

Verifiers take the same three hex arguments and answer with exit code 0 for
VALID, 1 for INVALID and 2 for malformed input.

To produce your own ICP signature instead of using ours:

```bash
cd signer
dfx deploy signer --network ic
dfx canister call signer config --network ic
dfx canister call signer get_public_key --network ic
dfx canister call signer sign '("991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948")' --network ic
```

Both endpoints take the same key id and derivation path, so the key reported is
the key signed with. Had they
differed, the public key would not belong to the signature and a failed check
would prove nothing. The management call behind `get_public_key` carries no cycle cost, though the
calling canister still pays for its own execution; each `sign` costs 10 billion
cycles with `test_key_1`. A fresh deployment yields a **different** key, since
the subnet derives it from the calling canister's id — to re-derive the key in
this vector, pass our canister id as shown above.

## Environment

Everything here was built and run on x86_64 Linux; no other host has been
tried. The vector was produced on 2026-11-20 with dfx 0.32.0, `ic-cdk` 0.19.0 and
rustc 1.93.1 — the combination that yields the module hash above. The
verification side pins `ed25519-dalek` 2.2.0, `curve25519-dalek` 4.1.3,
`blake2` 0.10.6 and `sha2` 0.10.9 through the committed
`Cargo.lock`; `run-checks.sh` and CI build with `--locked`, so the pin is
enforced rather than advertised. The compiler is pinned too:
`rust-toolchain.toml` asks for `1.93.1`, because a different rustc can emit a
different module from the same source and the module hash above would then stop
matching.

## Licence

MIT, Copyright (c) 2026 Bernhard Klingseisen — see [LICENSE](LICENSE). The
vector itself — keys, message, signatures — is a set of facts; use it freely.
