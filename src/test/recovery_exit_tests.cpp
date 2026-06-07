// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// RECOVERY_EXIT consensus-logic tests. The headline property (the auditor's safe route): consensus
// DERIVES the exact normal-path SMILE2 nullifier from the revealed note (no key reveal), so a note spent
// on the normal V2_SEND path or already spent pre-sunset collides in the SHARED nullifier set => rejected.

#include <consensus/amount.h>
#include <hash.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <serialize.h>
#include <shielded/merkle_tree.h>
#include <shielded/note.h>
#include <shielded/nullifier.h>
#include <shielded/recovery_exit.h>
#include <shielded/smile2/wallet_bridge.h>
#include <span.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <limits>
#include <optional>
#include <vector>

using namespace shielded::recovery;

namespace {

uint256 HashKeyBytes(const std::vector<unsigned char>& bytes)
{
    HashWriter hw;
    hw.write(AsBytes(Span<const unsigned char>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

std::vector<unsigned char> RandBytes(size_t n)
{
    // GetRandBytes asserts num <= 32, so fill in 32-byte chunks.
    std::vector<unsigned char> v;
    v.reserve(n);
    while (v.size() < n) {
        const uint256 h = GetRandHash();
        const size_t take = std::min<size_t>(32, n - v.size());
        v.insert(v.end(), h.begin(), h.begin() + take);
    }
    return v;
}

struct Fixture {
    RecoveryExitClaim claim;
    RecoveryExitConstraints c;
    uint256 expected_cm;
    uint256 expected_nf;
};

// Build a valid claim. Returns nullopt if the note happens to lack a SMILE2 nullifier (retry).
std::optional<Fixture> TryMakeValid(CAmount value, CAmount fee)
{
    Fixture f;
    f.claim.value = value;
    f.claim.rho = GetRandHash();
    f.claim.rcm = GetRandHash();
    f.claim.spend_pubkey = RandBytes(64);
    f.claim.recipient_pk_hash = HashKeyBytes(f.claim.spend_pubkey); // binds pubkey to the note

    ShieldedNote note;
    note.value = value;
    note.recipient_pk_hash = f.claim.recipient_pk_hash;
    note.rho = f.claim.rho;
    note.rcm = f.claim.rcm;
    f.expected_cm = note.GetCommitment();
    const auto nf = smile2::wallet::ComputeSmileNullifierFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED, note);
    if (!nf.has_value() || nf->IsNull()) return std::nullopt;
    f.expected_nf = *nf;

    f.c.value_balance = value;
    f.c.fee = fee;
    f.c.transparent_out = value - fee;
    f.c.shielded_output_count = 0;
    f.c.pool_balance = value * 10;
    f.c.validation_height = 125'050;
    f.c.activation_height = 125'000;
    f.c.expiry_height = 0;
    f.c.ownership_verified = true;
    f.c.membership_verified = true;
    f.c.nullifier_already_spent = false;
    f.c.commitment_already_claimed = false;
    return f;
}

Fixture MakeValid(CAmount value, CAmount fee)
{
    for (int i = 0; i < 8; ++i) {
        if (auto f = TryMakeValid(value, fee)) return *f;
    }
    BOOST_FAIL("could not build a SMILE2-eligible note fixture");
    return {};
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(recovery_exit_tests, BasicTestingSetup)

// The crux: consensus derives EXACTLY the normal-path SMILE2 nullifier and the note commitment, from the
// revealed note alone (no key). This is what makes shared-set cross-path dedup possible.
BOOST_AUTO_TEST_CASE(derives_exact_normal_path_smile_nullifier_and_commitment)
{
    const Fixture f = MakeValid(50 * COIN, 1000);
    RecoveryExitIdentifiers ids;
    std::string err;
    BOOST_REQUIRE_MESSAGE(DeriveRecoveryExitIdentifiers(f.claim, ids, err), err);
    BOOST_CHECK(ids.nullifier == f.expected_nf);   // == ComputeSmileNullifierFromNote(...) the V2_SEND path uses
    BOOST_CHECK(ids.commitment == f.expected_cm);
}

BOOST_AUTO_TEST_CASE(rejects_pubkey_not_binding_to_note)
{
    Fixture f = MakeValid(50 * COIN, 1000);
    f.claim.recipient_pk_hash = GetRandHash(); // no longer == HashBytes(spend_pubkey)
    RecoveryExitIdentifiers ids;
    std::string err;
    BOOST_CHECK(!DeriveRecoveryExitIdentifiers(f.claim, ids, err));
    BOOST_CHECK_EQUAL(err, "bad-recovery-exit-pubkey-binding");
}

BOOST_AUTO_TEST_CASE(rejects_recovery_value_out_of_money_range)
{
    Fixture f = MakeValid(50 * COIN, 1000);
    f.claim.value = MAX_MONEY + 1;
    f.c.value_balance = f.claim.value;
    RecoveryExitIdentifiers ids;
    std::string err;
    BOOST_CHECK(!DeriveRecoveryExitIdentifiers(f.claim, ids, err));
    BOOST_CHECK_EQUAL(err, "bad-recovery-exit-value");

    err.clear();
    BOOST_CHECK(!CheckRecoveryExitClaim(f.claim, f.c, ids, err));
    BOOST_CHECK_EQUAL(err, "bad-recovery-exit-value");
}

BOOST_AUTO_TEST_CASE(accepts_valid_transparent_exit)
{
    const Fixture f = MakeValid(50 * COIN, 1000);
    RecoveryExitIdentifiers ids;
    std::string err;
    BOOST_CHECK_MESSAGE(CheckRecoveryExitClaim(f.claim, f.c, ids, err), err);
    BOOST_CHECK(ids.nullifier == f.expected_nf);
}

// Cross-path / pre-sunset-spent closure: the derived SMILE2 nullifier is already in the shared set.
BOOST_AUTO_TEST_CASE(rejects_when_nullifier_already_spent)
{
    Fixture f = MakeValid(50 * COIN, 1000);
    f.c.nullifier_already_spent = true; // note was spent via the normal V2_SEND path (or pre-sunset)
    RecoveryExitIdentifiers ids;
    std::string err;
    BOOST_CHECK(!CheckRecoveryExitClaim(f.claim, f.c, ids, err));
    BOOST_CHECK_EQUAL(err, "bad-recovery-exit-nullifier-spent");
}

BOOST_AUTO_TEST_CASE(rejects_double_recovery_same_commitment)
{
    Fixture f = MakeValid(50 * COIN, 1000);
    f.c.commitment_already_claimed = true;
    RecoveryExitIdentifiers ids;
    std::string err;
    BOOST_CHECK(!CheckRecoveryExitClaim(f.claim, f.c, ids, err));
    BOOST_CHECK_EQUAL(err, "bad-recovery-exit-commitment-claimed");
}

BOOST_AUTO_TEST_CASE(rejects_non_pure_transparent_exit)
{
    {   Fixture f = MakeValid(50 * COIN, 1000); f.c.shielded_output_count = 1;
        RecoveryExitIdentifiers ids; std::string err;
        BOOST_CHECK(!CheckRecoveryExitClaim(f.claim, f.c, ids, err));
        BOOST_CHECK_EQUAL(err, "bad-recovery-exit-has-shielded-output"); }
    {   Fixture f = MakeValid(50 * COIN, 1000); f.c.value_balance = 49 * COIN;
        RecoveryExitIdentifiers ids; std::string err;
        BOOST_CHECK(!CheckRecoveryExitClaim(f.claim, f.c, ids, err));
        BOOST_CHECK_EQUAL(err, "bad-recovery-exit-value-balance"); }
    {   Fixture f = MakeValid(50 * COIN, 1000); f.c.fee = -1; f.c.transparent_out = f.claim.value + 1;
        RecoveryExitIdentifiers ids; std::string err;
        BOOST_CHECK(!CheckRecoveryExitClaim(f.claim, f.c, ids, err));
        BOOST_CHECK_EQUAL(err, "bad-recovery-exit-fee"); }
    {   Fixture f = MakeValid(50 * COIN, 1000); f.c.transparent_out = 50 * COIN;
        RecoveryExitIdentifiers ids; std::string err;
        BOOST_CHECK(!CheckRecoveryExitClaim(f.claim, f.c, ids, err));
        BOOST_CHECK_EQUAL(err, "bad-recovery-exit-transparent-mismatch"); }
    {   Fixture f = MakeValid(1000, 1000); f.c.transparent_out = 0;
        RecoveryExitIdentifiers ids; std::string err;
        BOOST_CHECK(!CheckRecoveryExitClaim(f.claim, f.c, ids, err));
        BOOST_CHECK_EQUAL(err, "bad-recovery-exit-not-outflow"); }
}

BOOST_AUTO_TEST_CASE(rejects_when_not_active_or_pool_empty_or_expired)
{
    {   Fixture f = MakeValid(50 * COIN, 1000); f.c.activation_height = std::numeric_limits<int32_t>::max();
        RecoveryExitIdentifiers ids; std::string err;
        BOOST_CHECK(!CheckRecoveryExitClaim(f.claim, f.c, ids, err));
        BOOST_CHECK_EQUAL(err, "bad-recovery-exit-not-active"); }
    {   Fixture f = MakeValid(50 * COIN, 1000); f.c.validation_height = 124'999;
        RecoveryExitIdentifiers ids; std::string err;
        BOOST_CHECK(!CheckRecoveryExitClaim(f.claim, f.c, ids, err));
        BOOST_CHECK_EQUAL(err, "bad-recovery-exit-not-active"); }
    {   Fixture f = MakeValid(50 * COIN, 1000); f.c.pool_balance = 0;
        RecoveryExitIdentifiers ids; std::string err;
        BOOST_CHECK(!CheckRecoveryExitClaim(f.claim, f.c, ids, err));
        BOOST_CHECK_EQUAL(err, "bad-recovery-exit-pool-empty"); }
    {   Fixture f = MakeValid(50 * COIN, 1000); f.c.expiry_height = 130'000; f.c.validation_height = 130'000;
        RecoveryExitIdentifiers ids; std::string err;
        BOOST_CHECK(!CheckRecoveryExitClaim(f.claim, f.c, ids, err));
        BOOST_CHECK_EQUAL(err, "bad-recovery-exit-expired"); }
}

BOOST_AUTO_TEST_CASE(rejects_unverified_ownership_or_membership)
{
    {   Fixture f = MakeValid(50 * COIN, 1000); f.c.ownership_verified = false;
        RecoveryExitIdentifiers ids; std::string err;
        BOOST_CHECK(!CheckRecoveryExitClaim(f.claim, f.c, ids, err));
        BOOST_CHECK_EQUAL(err, "bad-recovery-exit-ownership"); }
    {   Fixture f = MakeValid(50 * COIN, 1000); f.c.membership_verified = false;
        RecoveryExitIdentifiers ids; std::string err;
        BOOST_CHECK(!CheckRecoveryExitClaim(f.claim, f.c, ids, err));
        BOOST_CHECK_EQUAL(err, "bad-recovery-exit-membership"); }
}

// --- ComputeRecoveryExitBindingHash: determinism + sensitivity to every input ----------------------
BOOST_AUTO_TEST_CASE(binding_hash_is_deterministic_and_input_sensitive)
{
    const uint256 cm = GetRandHash();
    const uint256 nf = GetRandHash();
    const CAmount value = 50 * COIN;
    const uint256 tb = GetRandHash();

    const uint256 base = ComputeRecoveryExitBindingHash(cm, nf, value, tb);
    // Determinism: identical inputs -> identical hash.
    BOOST_CHECK(base == ComputeRecoveryExitBindingHash(cm, nf, value, tb));
    BOOST_CHECK(!base.IsNull());

    // Sensitivity: changing any single input changes the hash.
    BOOST_CHECK(base != ComputeRecoveryExitBindingHash(GetRandHash(), nf, value, tb));
    BOOST_CHECK(base != ComputeRecoveryExitBindingHash(cm, GetRandHash(), value, tb));
    BOOST_CHECK(base != ComputeRecoveryExitBindingHash(cm, nf, value + 1, tb));
    BOOST_CHECK(base != ComputeRecoveryExitBindingHash(cm, nf, value, GetRandHash()));
}

// --- VerifyRecoveryExitMembership: real ShieldedMerkleTree + Witness round-trip ---------------------
BOOST_AUTO_TEST_CASE(membership_accepts_valid_witness_rejects_wrong_inputs)
{
    using shielded::ShieldedMerkleTree;
    using shielded::ShieldedMerkleWitness;

    ShieldedMerkleTree tree;
    // Append a few decoys, then the commitment we will prove, so position is non-trivial.
    tree.Append(GetRandHash());
    tree.Append(GetRandHash());
    const uint256 cm = GetRandHash();
    tree.Append(cm);
    const ShieldedMerkleWitness witness = tree.Witness();
    const uint256 root = tree.Root();

    RecoveryExitClaim claim;
    DataStream ss{};
    ss << witness;
    const auto proof_bytes = MakeUCharSpan(ss);
    claim.membership_proof.assign(proof_bytes.begin(), proof_bytes.end());

    std::string err;
    BOOST_CHECK_MESSAGE(VerifyRecoveryExitMembership(claim, cm, root, err), err);

    // Wrong root -> non-authenticating.
    err.clear();
    BOOST_CHECK(!VerifyRecoveryExitMembership(claim, cm, GetRandHash(), err));
    BOOST_CHECK_EQUAL(err, "bad-recovery-exit-membership");

    // Null root -> fail-closed.
    err.clear();
    BOOST_CHECK(!VerifyRecoveryExitMembership(claim, cm, uint256{}, err));
    BOOST_CHECK_EQUAL(err, "bad-recovery-exit-no-frozen-root");

    // Different leaf -> non-authenticating.
    err.clear();
    BOOST_CHECK(!VerifyRecoveryExitMembership(claim, GetRandHash(), root, err));
    BOOST_CHECK_EQUAL(err, "bad-recovery-exit-membership");

    // Garbage proof bytes -> deserialization failure.
    RecoveryExitClaim bad;
    bad.membership_proof = RandBytes(8);
    err.clear();
    BOOST_CHECK(!VerifyRecoveryExitMembership(bad, cm, root, err));
    BOOST_CHECK_EQUAL(err, "bad-recovery-exit-bad-membership-proof");
}

// --- VerifyRecoveryExitOwnership: real CPQKey sign / CPQPubKey verify --------------------------------
BOOST_AUTO_TEST_CASE(ownership_accepts_valid_pq_signature_rejects_tampered)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());

    RecoveryExitClaim claim;
    claim.spend_pubkey = key.GetPubKey();

    const uint256 binding_hash = GetRandHash();
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(binding_hash, sig));
    claim.ownership_sig = sig;

    BOOST_CHECK(VerifyRecoveryExitOwnership(claim, binding_hash));

    // Wrong message -> rejected.
    BOOST_CHECK(!VerifyRecoveryExitOwnership(claim, GetRandHash()));

    // Tampered signature -> rejected.
    {
        RecoveryExitClaim tampered = claim;
        tampered.ownership_sig[0] ^= 0x01;
        BOOST_CHECK(!VerifyRecoveryExitOwnership(tampered, binding_hash));
    }

    // Wrong pubkey (different key) -> rejected.
    {
        CPQKey other;
        other.MakeNewKey(PQAlgorithm::ML_DSA_44);
        RecoveryExitClaim wrong_pk = claim;
        wrong_pk.spend_pubkey = other.GetPubKey();
        BOOST_CHECK(!VerifyRecoveryExitOwnership(wrong_pk, binding_hash));
    }

    // Malformed (too-short) pubkey -> rejected, not a crash.
    {
        RecoveryExitClaim malformed = claim;
        malformed.spend_pubkey = RandBytes(8);
        BOOST_CHECK(!VerifyRecoveryExitOwnership(malformed, binding_hash));
    }
}

namespace {
uint256 Sha256OfBytes(const std::vector<unsigned char>& b)
{
    HashWriter hw; hw.write(AsBytes(Span<const unsigned char>{b.data(), b.size()})); return hw.GetSHA256();
}
} // namespace

// End-to-end consensus FLOW: runs the EXACT sequence ConnectBlock performs on a V2_RECOVERY_EXIT bundle,
// with real crypto (ML-DSA-44 ownership signature + a real ShieldedMerkleTree membership witness) and a
// real persistent NullifierSet spent-commitment set. Asserts a valid claim is ACCEPTED and retired, and
// each tampered input (ownership, membership, cross-path nullifier, value) is REJECTED.
BOOST_FIXTURE_TEST_CASE(recovery_exit_full_consensus_flow, BasicTestingSetup)
{
    // Real note + PQ key; recipient_pk_hash binds to the pubkey, SMILE2 nullifier must be derivable.
    CPQKey key; key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    const std::vector<unsigned char> pubkey = key.GetPubKey();
    ShieldedNote note;
    note.value = 50 * COIN;
    note.recipient_pk_hash = Sha256OfBytes(pubkey);
    bool eligible = false;
    for (int i = 0; i < 8 && !eligible; ++i) {
        note.rho = GetRandHash(); note.rcm = GetRandHash();
        eligible = smile2::wallet::ComputeSmileNullifierFromNote(
                       smile2::wallet::SMILE_GLOBAL_SEED, note).has_value();
    }
    BOOST_REQUIRE(eligible);
    const uint256 cm = note.GetCommitment();

    // Real commitment tree: decoys then the note appended last, so Witness() authenticates cm against the
    // test root. Production activation must use the consensus-pinned 125,000 root.
    shielded::ShieldedMerkleTree tree;
    tree.Append(GetRandHash());
    tree.Append(GetRandHash());
    tree.Append(cm);
    const shielded::ShieldedMerkleWitness witness = tree.Witness();
    const uint256 frozen_root = tree.Root();

    RecoveryExitClaim claim;
    claim.value = note.value;
    claim.recipient_pk_hash = note.recipient_pk_hash;
    claim.rho = note.rho;
    claim.rcm = note.rcm;
    claim.spend_pubkey = pubkey;
    { DataStream ws; ws << witness; const auto sp = MakeUCharSpan(ws); claim.membership_proof.assign(sp.begin(), sp.end()); }

    RecoveryExitIdentifiers ids; std::string err;
    BOOST_REQUIRE_MESSAGE(DeriveRecoveryExitIdentifiers(claim, ids, err), err);
    BOOST_CHECK(ids.commitment == cm);

    // Transparent payout + ownership signature over the binding hash.
    std::vector<CTxOut> vout{CTxOut(note.value - 1000, CScript() << OP_TRUE)};
    const uint256 tx_binding = ComputeRecoveryExitTransparentBinding(Span<const CTxOut>{vout});
    const uint256 binding_hash = ComputeRecoveryExitBindingHash(ids.commitment, ids.nullifier, claim.value, tx_binding);
    BOOST_REQUIRE(key.Sign(binding_hash, claim.ownership_sig));

    // === the ConnectBlock validation sequence, valid claim => ACCEPT ===
    BOOST_CHECK(VerifyRecoveryExitOwnership(claim, binding_hash));
    std::string mrr;
    BOOST_CHECK_MESSAGE(VerifyRecoveryExitMembership(claim, ids.commitment, frozen_root, mrr), mrr);
    RecoveryExitConstraints c;
    c.value_balance = claim.value; c.fee = 1000; c.transparent_out = note.value - 1000;
    c.shielded_output_count = 0; c.pool_balance = note.value * 10;
    c.validation_height = 125'050; c.activation_height = 125'000; c.expiry_height = 0;
    c.ownership_verified = true; c.membership_verified = true;
    c.nullifier_already_spent = false; c.commitment_already_claimed = false;
    RecoveryExitIdentifiers checked; std::string crr;
    BOOST_CHECK_MESSAGE(CheckRecoveryExitClaim(claim, c, checked, crr), crr);

    // === tampered inputs => REJECT at the corresponding stage ===
    { auto bad = claim; bad.ownership_sig[0] ^= 0x01;
      BOOST_CHECK(!VerifyRecoveryExitOwnership(bad, binding_hash)); }                 // ownership
    { std::string r; BOOST_CHECK(!VerifyRecoveryExitMembership(claim, ids.commitment, GetRandHash(), r)); } // wrong root
    { std::string r; BOOST_CHECK(!VerifyRecoveryExitMembership(claim, GetRandHash(), frozen_root, r)); }     // wrong leaf
    { auto cc = c; cc.nullifier_already_spent = true; RecoveryExitIdentifiers o; std::string r;
      BOOST_CHECK(!CheckRecoveryExitClaim(claim, cc, o, r));
      BOOST_CHECK_EQUAL(r, "bad-recovery-exit-nullifier-spent"); }                    // cross-path/pre-spent
    { auto cc = c; cc.value_balance = note.value - 1; RecoveryExitIdentifiers o; std::string r;
      BOOST_CHECK(!CheckRecoveryExitClaim(claim, cc, o, r)); }                        // value mismatch

    // === retirement + reorg undo through a real persistent NullifierSet ===
    NullifierSet ns(m_args.GetDataDirNet() / "re_flow", 1 << 20, false, true);
    BOOST_CHECK(!ns.ContainsRecoveryExitCommitment(ids.commitment));
    BOOST_CHECK(ns.InsertRecoveryExitCommitments({ids.commitment}));
    BOOST_CHECK(ns.ContainsRecoveryExitCommitment(ids.commitment));      // retired
    BOOST_CHECK(!ns.Contains(ids.nullifier));                            // separate keyspace
    BOOST_CHECK(ns.RemoveRecoveryExitCommitments({ids.commitment}));     // reorg
    BOOST_CHECK(!ns.ContainsRecoveryExitCommitment(ids.commitment));
}

BOOST_AUTO_TEST_SUITE_END()
