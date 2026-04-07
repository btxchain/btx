// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/smile2/wallet_bridge.h>
#include <shielded/smile2/params.h>
#include <shielded/smile2/verify_dispatch.h>
#include <shielded/note.h>
#include <test/util/smile2_placeholder_utils.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using namespace smile2;
using namespace smile2::wallet;

namespace {

ShieldedNote MakeNote(CAmount value, unsigned char seed)
{
    ShieldedNote note;
    note.value = value;
    note.recipient_pk_hash = uint256{seed};
    note.rho = uint256{static_cast<unsigned char>(seed + 1)};
    note.rcm = uint256{static_cast<unsigned char>(seed + 2)};
    note.memo = {seed, static_cast<unsigned char>(seed + 3)};
    return note;
}

std::vector<SmileRingMember> MakePlaceholderRing(size_t count, unsigned char seed_base)
{
    std::vector<SmileRingMember> ring;
    ring.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        ring.push_back(BuildPlaceholderRingMember(
            SMILE_GLOBAL_SEED,
            uint256{static_cast<unsigned char>(seed_base + i)}));
    }
    return ring;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(smile2_wallet_bridge_tests, BasicTestingSetup)

// W1: Global seed is deterministic and non-zero
BOOST_AUTO_TEST_CASE(w1_global_seed)
{
    bool all_zero = true;
    for (uint8_t b : SMILE_GLOBAL_SEED) {
        if (b != 0) { all_zero = false; break; }
    }
    BOOST_CHECK(!all_zero);

    // Must be deterministic (same every time)
    auto seed2 = SMILE_GLOBAL_SEED;
    BOOST_CHECK(SMILE_GLOBAL_SEED == seed2);
    BOOST_TEST_MESSAGE("W1: Global seed is deterministic and non-zero ✓");
}

// W2: Key derivation produces valid keys
BOOST_AUTO_TEST_CASE(w2_key_derivation)
{
    const ShieldedNote note = MakeNote(/*value=*/42, /*seed=*/0x42);
    auto kp = DeriveSmileKeyPairFromNote(SMILE_GLOBAL_SEED, note);

    // Public key should have KEY_ROWS polynomials
    BOOST_CHECK_EQUAL(kp.pub.pk.size(), KEY_ROWS);

    // Secret key should have KEY_COLS polynomials
    BOOST_CHECK_EQUAL(kp.sec.s.size(), KEY_COLS);

    // pk = A·s should hold
    for (size_t i = 0; i < KEY_ROWS; ++i) {
        SmilePoly acc;
        for (size_t j = 0; j < KEY_COLS; ++j) {
            acc += NttMul(kp.pub.A[i][j], kp.sec.s[j]);
        }
        acc.Reduce();
        SmilePoly pk_i = kp.pub.pk[i];
        pk_i.Reduce();
        BOOST_CHECK(acc == pk_i);
    }

    BOOST_TEST_MESSAGE("W2: Key derivation produces valid A·s = pk ✓");
}

// W3: Different commitments produce different keys
BOOST_AUTO_TEST_CASE(w3_key_isolation)
{
    const ShieldedNote note0 = MakeNote(/*value=*/10, /*seed=*/0x01);
    const ShieldedNote note1 = MakeNote(/*value=*/10, /*seed=*/0x02);
    auto kp0 = DeriveSmileKeyPairFromNote(SMILE_GLOBAL_SEED, note0);
    auto kp1 = DeriveSmileKeyPairFromNote(SMILE_GLOBAL_SEED, note1);

    // Different commitments should produce different secret keys
    bool same = true;
    for (size_t j = 0; j < KEY_COLS; ++j) {
        SmilePoly s0 = kp0.sec.s[j]; s0.Reduce();
        SmilePoly s1 = kp1.sec.s[j]; s1.Reduce();
        if (s0 != s1) { same = false; break; }
    }
    BOOST_CHECK(!same);

    BOOST_TEST_MESSAGE("W3: Commitment-based key isolation ✓");
}

// W4: Anonymity set construction from commitments
BOOST_AUTO_TEST_CASE(w4_anonymity_set)
{
    std::vector<SmileRingMember> ring_members = MakePlaceholderRing(/*count=*/32, /*seed_base=*/0x10);
    auto anon_set = BuildAnonymitySet(Span<const SmileRingMember>{ring_members.data(), ring_members.size()});

    BOOST_CHECK_EQUAL(anon_set.size(), 32u);

    // Each entry should have valid structure
    for (const auto& pk : anon_set) {
        BOOST_CHECK_EQUAL(pk.pk.size(), KEY_ROWS);
        BOOST_CHECK_EQUAL(pk.A.size(), KEY_ROWS);
        BOOST_CHECK_EQUAL(pk.A[0].size(), KEY_COLS);
    }

    // Different commitments should produce different public keys
    BOOST_CHECK(anon_set[0].pk[0] != anon_set[1].pk[0]);

    BOOST_TEST_MESSAGE("W4: Anonymity set construction (32 entries) ✓");
}

// W5: End-to-end SMILE proof creation via wallet bridge
BOOST_AUTO_TEST_CASE(w5_end_to_end_proof)
{
    std::vector<SmileRingMember> ring_members = MakePlaceholderRing(/*count=*/32, /*seed_base=*/0x20);
    const ShieldedNote input_note = MakeNote(/*value=*/100, /*seed=*/0x31);
    auto real_member = BuildRingMemberFromNote(SMILE_GLOBAL_SEED, input_note);
    BOOST_REQUIRE(real_member.has_value());
    ring_members[5] = *real_member;

    SmileInputMaterial input;
    input.note = input_note;
    input.account_leaf_commitment = real_member->account_leaf_commitment;
    input.ring_index = 5;

    const ShieldedNote out_a = MakeNote(/*value=*/60, /*seed=*/0x41);
    const ShieldedNote out_b = MakeNote(/*value=*/40, /*seed=*/0x51);

    std::vector<uint8_t> entropy(32, 0x77);
    std::vector<uint256> serial_hashes;

    auto proof_bytes = CreateSmileProof(
        SMILE_GLOBAL_SEED,
        {input},
        {out_a, out_b},
        Span<const SmileRingMember>{ring_members.data(), ring_members.size()},
        Span<const uint8_t>(entropy),
        serial_hashes);

    // With unified key derivation the prover's key always matches the
    // commitment-derived key, so the proof should succeed.
    BOOST_CHECK(proof_bytes.has_value());
    if (proof_bytes) {
        BOOST_CHECK_GT(proof_bytes->proof_bytes.size(), 0u);
        BOOST_CHECK_EQUAL(serial_hashes.size(), 1u);
        BOOST_TEST_MESSAGE("W5: End-to-end proof creation succeeded, size="
                           << proof_bytes->proof_bytes.size() << " bytes");
    }
}

// W6: Serial number hashes are deterministic
BOOST_AUTO_TEST_CASE(w6_serial_determinism)
{
    std::vector<SmileRingMember> ring = MakePlaceholderRing(/*count=*/32, /*seed_base=*/0x50);
    const ShieldedNote note = MakeNote(/*value=*/50, /*seed=*/0x61);
    auto real_member = BuildRingMemberFromNote(SMILE_GLOBAL_SEED, note);
    BOOST_REQUIRE(real_member.has_value());
    ring[3] = *real_member;

    SmileInputMaterial input;
    input.note = note;
    input.account_leaf_commitment = real_member->account_leaf_commitment;
    input.ring_index = 3;

    std::vector<uint8_t> entropy(32, 0x11);
    std::vector<uint256> hashes1, hashes2;

    auto p1 = CreateSmileProof(SMILE_GLOBAL_SEED,
                               {input},
                               {note},
                               Span<const SmileRingMember>{ring.data(), ring.size()},
                               Span<const uint8_t>(entropy),
                               hashes1);
    auto p2 = CreateSmileProof(SMILE_GLOBAL_SEED,
                               {input},
                               {note},
                               Span<const SmileRingMember>{ring.data(), ring.size()},
                               Span<const uint8_t>(entropy),
                               hashes2);

    // With unified key derivation, proofs should succeed.
    BOOST_CHECK(p1.has_value());
    BOOST_CHECK(p2.has_value());
    if (p1 && p2) {
        BOOST_CHECK(hashes1 == hashes2);
        BOOST_TEST_MESSAGE("W6: Serial hashes deterministic ✓");
    }
}

BOOST_AUTO_TEST_CASE(w6b_note_nullifier_matches_proof_serial_hash)
{
    std::vector<SmileRingMember> ring = MakePlaceholderRing(/*count=*/32, /*seed_base=*/0x5a);
    const ShieldedNote note = MakeNote(/*value=*/55, /*seed=*/0x6a);
    auto real_member = BuildRingMemberFromNote(SMILE_GLOBAL_SEED, note);
    BOOST_REQUIRE(real_member.has_value());
    ring[7] = *real_member;

    SmileInputMaterial input;
    input.note = note;
    input.account_leaf_commitment = real_member->account_leaf_commitment;
    input.ring_index = 7;

    std::vector<uint8_t> entropy(32, 0x17);
    std::vector<uint256> serial_hashes;

    auto proof = CreateSmileProof(SMILE_GLOBAL_SEED,
                                  {input},
                                  {note},
                                  Span<const SmileRingMember>{ring.data(), ring.size()},
                                  Span<const uint8_t>(entropy),
                                  serial_hashes);
    BOOST_REQUIRE(proof.has_value());
    BOOST_REQUIRE_EQUAL(serial_hashes.size(), 1U);

    const auto derived_nullifier = ComputeSmileNullifierFromNote(SMILE_GLOBAL_SEED, note);
    BOOST_REQUIRE(derived_nullifier.has_value());
    BOOST_CHECK_EQUAL(*derived_nullifier, serial_hashes[0]);
}

// W7: Serial hashes use canonical reduced coefficients.
BOOST_AUTO_TEST_CASE(w7_serial_hash_is_canonical_mod_q)
{
    SmilePoly serial_a;
    serial_a.coeffs[0] = 7;
    serial_a.coeffs[1] = 19;

    SmilePoly serial_b = serial_a;
    serial_b.coeffs[0] += Q;
    serial_b.coeffs[1] -= Q;

    BOOST_CHECK(ComputeSmileSerialHash(serial_a) == ComputeSmileSerialHash(serial_b));
}

// W8: Output coin hash changes when the transmitted public coin changes.
BOOST_AUTO_TEST_CASE(w8_output_coin_hash_tracks_coin_bytes)
{
    std::vector<SmileRingMember> ring_members = MakePlaceholderRing(/*count=*/32, /*seed_base=*/0x70);
    const ShieldedNote input_note = MakeNote(/*value=*/75, /*seed=*/0x81);
    auto real_member = BuildRingMemberFromNote(SMILE_GLOBAL_SEED, input_note);
    BOOST_REQUIRE(real_member.has_value());
    ring_members[4] = *real_member;

    SmileInputMaterial input;
    input.note = input_note;
    input.account_leaf_commitment = real_member->account_leaf_commitment;
    input.ring_index = 4;

    std::vector<uint8_t> entropy(32, 0x22);
    std::vector<uint256> serial_hashes;
    auto result = CreateSmileProof(SMILE_GLOBAL_SEED,
                                   {input},
                                   {input_note},
                                   Span<const SmileRingMember>{ring_members.data(), ring_members.size()},
                                   Span<const uint8_t>(entropy),
                                   serial_hashes);
    BOOST_REQUIRE(result.has_value());
    BOOST_REQUIRE_EQUAL(result->output_coins.size(), 1U);

    const uint256 original_hash = ComputeSmileOutputCoinHash(result->output_coins[0]);
    auto mutated_coin = result->output_coins[0];
    BOOST_REQUIRE(!mutated_coin.t_msg.empty());
    mutated_coin.t_msg[0].coeffs[0] += 1;

    BOOST_CHECK(original_hash != ComputeSmileOutputCoinHash(mutated_coin));
}

BOOST_AUTO_TEST_CASE(w9_rejects_out_of_bounds_ring_index)
{
    std::vector<SmileRingMember> ring_members = MakePlaceholderRing(/*count=*/32, /*seed_base=*/0x90);

    SmileInputMaterial input;
    input.note = MakeNote(/*value=*/10, /*seed=*/0x91);
    input.ring_index = ring_members.size();

    std::vector<uint8_t> entropy(32, 0x32);
    std::vector<uint256> serial_hashes;

    auto result = CreateSmileProof(SMILE_GLOBAL_SEED,
                                   {input},
                                   {input.note},
                                   Span<const SmileRingMember>{ring_members.data(), ring_members.size()},
                                   Span<const uint8_t>(entropy),
                                   serial_hashes);
    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(w10_rejects_mismatched_commitment_and_amount_domain)
{
    std::vector<SmileRingMember> ring_members = MakePlaceholderRing(/*count=*/32, /*seed_base=*/0xa0);

    SmileInputMaterial input;
    input.note = MakeNote(/*value=*/10, /*seed=*/0xa1);
    input.ring_index = 1;

    std::vector<uint8_t> entropy(32, 0x42);
    std::vector<uint256> serial_hashes;

    auto mismatched = CreateSmileProof(SMILE_GLOBAL_SEED,
                                       {input},
                                       {input.note},
                                       Span<const SmileRingMember>{ring_members.data(), ring_members.size()},
                                       Span<const uint8_t>(entropy),
                                       serial_hashes);
    BOOST_CHECK(!mismatched.has_value());

    input.note.value = -1;
    auto negative = CreateSmileProof(SMILE_GLOBAL_SEED,
                                     {input},
                                     {input.note},
                                     Span<const SmileRingMember>{ring_members.data(), ring_members.size()},
                                     Span<const uint8_t>(entropy),
                                     serial_hashes);
    BOOST_CHECK(!negative.has_value());

    input.note = MakeNote(/*value=*/Q, /*seed=*/0xa2);
    auto wraps = CreateSmileProof(SMILE_GLOBAL_SEED,
                                  {input},
                                  {input.note},
                                  Span<const SmileRingMember>{ring_members.data(), ring_members.size()},
                                  Span<const uint8_t>(entropy),
                                  serial_hashes);
    BOOST_CHECK(!wraps.has_value());
}

BOOST_AUTO_TEST_CASE(w10b_rejects_real_input_member_with_mismatched_public_coin)
{
    std::vector<SmileRingMember> ring_members = MakePlaceholderRing(/*count=*/32, /*seed_base=*/0xa8);
    const ShieldedNote note = MakeNote(/*value=*/25, /*seed=*/0xa9);
    auto real_member = BuildRingMemberFromNote(SMILE_GLOBAL_SEED, note);
    BOOST_REQUIRE(real_member.has_value());
    BOOST_REQUIRE(!real_member->public_coin.t_msg.empty());
    real_member->public_coin.t_msg[0].coeffs[0] =
        mod_q(real_member->public_coin.t_msg[0].coeffs[0] + 1);
    ring_members[2] = *real_member;

    SmileInputMaterial input;
    input.note = note;
    input.account_leaf_commitment = real_member->account_leaf_commitment;
    input.ring_index = 2;

    std::vector<uint8_t> entropy(32, 0x44);
    std::vector<uint256> serial_hashes;

    auto result = CreateSmileProof(SMILE_GLOBAL_SEED,
                                   {input},
                                   {note},
                                   Span<const SmileRingMember>{ring_members.data(), ring_members.size()},
                                   Span<const uint8_t>(entropy),
                                   serial_hashes);
    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(w10c_rejects_real_input_member_with_mismatched_public_key)
{
    std::vector<SmileRingMember> ring_members = MakePlaceholderRing(/*count=*/32, /*seed_base=*/0xb0);
    const ShieldedNote note = MakeNote(/*value=*/30, /*seed=*/0xb1);
    auto real_member = BuildRingMemberFromNote(SMILE_GLOBAL_SEED, note);
    BOOST_REQUIRE(real_member.has_value());
    BOOST_REQUIRE(!real_member->public_key.pk.empty());
    real_member->public_key.pk[0].coeffs[0] =
        mod_q(real_member->public_key.pk[0].coeffs[0] + 1);
    ring_members[6] = *real_member;

    SmileInputMaterial input;
    input.note = note;
    input.account_leaf_commitment = real_member->account_leaf_commitment;
    input.ring_index = 6;

    std::vector<uint8_t> entropy(32, 0x45);
    std::vector<uint256> serial_hashes;

    auto result = CreateSmileProof(SMILE_GLOBAL_SEED,
                                   {input},
                                   {note},
                                   Span<const SmileRingMember>{ring_members.data(), ring_members.size()},
                                   Span<const uint8_t>(entropy),
                                   serial_hashes);
    BOOST_CHECK(!result.has_value());
}

// W11: Regression guard: note-derived secret material must not collapse to the
// same keypair as commitment-only derivation.
BOOST_AUTO_TEST_CASE(w11_commitment_derived_secret_is_publicly_reproducible)
{
    const ShieldedNote note = MakeNote(/*value=*/77, /*seed=*/0xb1);
    const uint256 commitment = note.GetCommitment();

    const auto note_derived = DeriveSmileKeyPairFromNote(SMILE_GLOBAL_SEED, note);
    const auto public_placeholder = DeriveSmileKeyPair(SMILE_GLOBAL_SEED, commitment);

    BOOST_REQUIRE_EQUAL(note_derived.sec.s.size(), public_placeholder.sec.s.size());
    bool any_diff{false};
    for (size_t i = 0; i < note_derived.sec.s.size(); ++i) {
        SmilePoly lhs = note_derived.sec.s[i];
        SmilePoly rhs = public_placeholder.sec.s[i];
        lhs.Reduce();
        rhs.Reduce();
        if (lhs != rhs) {
            any_diff = true;
            break;
        }
    }
    BOOST_CHECK(any_diff);
}

BOOST_AUTO_TEST_CASE(w12_compact_public_account_hash_must_match_ring_member_commitment)
{
    const ShieldedNote note = MakeNote(/*value=*/81, /*seed=*/0xc1);
    auto account = BuildCompactPublicAccountFromNote(SMILE_GLOBAL_SEED, note);
    BOOST_REQUIRE(account.has_value());

    const uint256 commitment = ComputeCompactPublicAccountHash(*account);
    auto member = BuildRingMemberFromCompactPublicAccount(SMILE_GLOBAL_SEED, commitment, *account);
    BOOST_CHECK(member.has_value());

    auto mismatched = BuildRingMemberFromCompactPublicAccount(SMILE_GLOBAL_SEED, uint256{0xcc}, *account);
    BOOST_CHECK(!mismatched.has_value());
}

BOOST_AUTO_TEST_SUITE_END()
