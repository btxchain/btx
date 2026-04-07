// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <random.h>
#include <hash.h>
#include <shielded/lattice/sampling.h>
#include <shielded/ringct/proof_encoding.h>
#include <shielded/ringct/ring_signature.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <set>
#include <string>

using namespace shielded::ringct;
namespace lattice = shielded::lattice;

namespace {

uint256 SerializeRingSignatureHash(const RingSignature& sig)
{
    DataStream ss;
    ss << sig;
    HashWriter hw;
    if (!ss.empty()) {
        hw.write(Span<const std::byte>{ss.data(), ss.size()});
    }
    return hw.GetSHA256();
}

uint256 DeterministicVectorHash(const std::string& tag, uint32_t index)
{
    HashWriter hw;
    hw << std::string{"BTX_RINGSIG_TEST_VECTOR_V1"};
    hw << tag;
    hw << index;
    return hw.GetSHA256();
}

lattice::PolyVec DeriveTestPublicKey(const uint256& ring_member, size_t member_index)
{
    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_RingSig_Public_V5"};
    hw << ring_member;
    hw << static_cast<uint32_t>(member_index);
    const uint256 seed = hw.GetSHA256();
    return lattice::ExpandUniformVec(
        Span<const unsigned char>{seed.begin(), uint256::size()},
        lattice::MODULE_RANK,
        24576);
}

lattice::PolyVec DeriveTestInputSecret(Span<const unsigned char> spending_key,
                                       const uint256& ring_member,
                                       size_t input_index)
{
    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_RingSig_TestSecret_V1"};
    hw.write(AsBytes(spending_key));
    hw << ring_member;
    hw << static_cast<uint32_t>(input_index);
    const uint256 seed = hw.GetSHA256();
    FastRandomContext rng(seed);
    return lattice::SampleSmallVec(rng, lattice::MODULE_RANK, /*eta=*/2);
}

std::vector<lattice::PolyVec> BuildInputSecretsForTest(const std::vector<std::vector<uint256>>& ring_members,
                                                       const std::vector<size_t>& real_indices,
                                                       Span<const unsigned char> spending_key)
{
    if (ring_members.size() != real_indices.size()) return {};
    std::vector<lattice::PolyVec> input_secrets;
    input_secrets.reserve(ring_members.size());
    for (size_t input_idx = 0; input_idx < ring_members.size(); ++input_idx) {
        if (real_indices[input_idx] >= ring_members[input_idx].size()) return {};
        input_secrets.push_back(DeriveTestInputSecret(spending_key,
                                                      ring_members[input_idx][real_indices[input_idx]],
                                                      input_idx));
    }
    return input_secrets;
}

bool CreateRingSignatureForTest(RingSignature& sig,
                                const std::vector<std::vector<uint256>>& ring_members,
                                const std::vector<size_t>& real_indices,
                                Span<const unsigned char> spending_key,
                                const uint256& message_hash,
                                Span<const unsigned char> entropy = {})
{
    const std::vector<lattice::PolyVec> input_secrets = BuildInputSecretsForTest(ring_members, real_indices, spending_key);
    if (input_secrets.size() != ring_members.size()) return false;
    return CreateRingSignature(sig, ring_members, real_indices, input_secrets, message_hash, entropy);
}

bool DeriveInputNullifierForTest(Nullifier& out_nullifier,
                                 Span<const unsigned char> spending_key,
                                 const uint256& ring_member)
{
    const lattice::PolyVec input_secret = DeriveTestInputSecret(spending_key, ring_member, /*input_index=*/0);
    return DeriveInputNullifierFromSecret(out_nullifier, input_secret, ring_member);
}

uint256 PolyVecHash(const lattice::PolyVec& vec)
{
    DataStream ss;
    ss << vec;
    HashWriter hw;
    if (!ss.empty()) {
        hw.write(Span<const std::byte>{ss.data(), ss.size()});
    }
    return hw.GetSHA256();
}

[[nodiscard]] std::vector<std::vector<uint256>> MakeRandomRingMembers(size_t input_count,
                                                                      size_t ring_size)
{
    std::vector<std::vector<uint256>> ring_members(input_count, std::vector<uint256>(ring_size));
    for (auto& ring : ring_members) {
        for (auto& member : ring) {
            member = GetRandHash();
        }
    }
    return ring_members;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(ringct_ring_signature_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(create_verify_ring_signature)
{
    std::vector<std::vector<uint256>> ring_members = MakeRandomRingMembers(2, lattice::RING_SIZE);
    std::vector<size_t> real_indices{2, 7};
    const uint256 message_hash = GetRandHash();
    std::vector<unsigned char> spending_key(32, 0x42);

    RingSignature sig;
    BOOST_REQUIRE(CreateRingSignatureForTest(sig, ring_members, real_indices, spending_key, message_hash));
    BOOST_CHECK(VerifyRingSignature(sig, ring_members, message_hash));
}

BOOST_AUTO_TEST_CASE(wrong_message_fails)
{
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) {
        member = GetRandHash();
    }

    std::vector<size_t> real_indices{5};
    std::vector<unsigned char> spending_key(32, 0xA1);

    RingSignature sig;
    const uint256 good_message = GetRandHash();
    BOOST_REQUIRE(CreateRingSignatureForTest(sig, ring_members, real_indices, spending_key, good_message));

    const uint256 bad_message = GetRandHash();
    BOOST_CHECK(!VerifyRingSignature(sig, ring_members, bad_message));
}

BOOST_AUTO_TEST_CASE(tamper_detected)
{
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) {
        member = GetRandHash();
    }

    std::vector<size_t> real_indices{3};
    std::vector<unsigned char> spending_key(32, 0x55);
    const uint256 message = GetRandHash();

    RingSignature sig;
    BOOST_REQUIRE(CreateRingSignatureForTest(sig, ring_members, real_indices, spending_key, message));

    BOOST_REQUIRE(!sig.input_proofs.empty());
    BOOST_REQUIRE(!sig.input_proofs[0].responses.empty());
    sig.input_proofs[0].responses[0][0].coeffs[0] ^= 1;
    BOOST_CHECK(!VerifyRingSignature(sig, ring_members, message));
}

BOOST_AUTO_TEST_CASE(challenge_decomposition_tamper_detected)
{
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) {
        member = GetRandHash();
    }

    std::vector<size_t> real_indices{6};
    std::vector<unsigned char> spending_key(32, 0x44);
    const uint256 message_hash = GetRandHash();

    RingSignature sig;
    BOOST_REQUIRE(CreateRingSignatureForTest(sig, ring_members, real_indices, spending_key, message_hash));
    BOOST_REQUIRE(!sig.input_proofs.empty());
    BOOST_REQUIRE(!sig.input_proofs[0].challenges.empty());

    sig.input_proofs[0].challenges[0] = GetRandHash();
    BOOST_CHECK(!VerifyRingSignature(sig, ring_members, message_hash));
}

BOOST_AUTO_TEST_CASE(random_forgery_rejected)
{
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) {
        member = GetRandHash();
    }

    RingSignature forged;
    forged.challenge_seed = GetRandHash();
    FastRandomContext rng1(GetRandHash());
    forged.key_images.assign(1, lattice::SampleSmallVec(rng1, lattice::MODULE_RANK));
    RingInputProof input;
    input.challenges.assign(lattice::RING_SIZE, GetRandHash());
    FastRandomContext rng2(GetRandHash());
    input.responses.assign(lattice::RING_SIZE, lattice::SampleSmallVec(rng2, lattice::MODULE_RANK));
    forged.input_proofs.push_back(std::move(input));

    BOOST_CHECK(!VerifyRingSignature(forged, ring_members, GetRandHash()));
}

BOOST_AUTO_TEST_CASE(monte_carlo_forgery_rejection)
{
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) {
        member = GetRandHash();
    }

    for (int trial = 0; trial < 32; ++trial) {
        RingSignature forged;
        forged.challenge_seed = GetRandHash();
        FastRandomContext rng1(GetRandHash());
        forged.key_images.assign(1, lattice::SampleSmallVec(rng1, lattice::MODULE_RANK));
        RingInputProof input;
        input.challenges.resize(lattice::RING_SIZE);
        for (auto& c : input.challenges) c = GetRandHash();
        FastRandomContext rng2(GetRandHash());
        input.responses.assign(lattice::RING_SIZE, lattice::SampleSmallVec(rng2, lattice::MODULE_RANK));
        forged.input_proofs = {std::move(input)};

        BOOST_CHECK(!VerifyRingSignature(forged, ring_members, GetRandHash()));
    }
}

BOOST_AUTO_TEST_CASE(challenge_chain_tamper_detected)
{
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) member = GetRandHash();

    std::vector<size_t> real_indices{4};
    std::vector<unsigned char> spending_key(32, 0x2A);
    const uint256 message_hash = GetRandHash();

    RingSignature sig;
    BOOST_REQUIRE(CreateRingSignatureForTest(sig, ring_members, real_indices, spending_key, message_hash));
    BOOST_REQUIRE(!sig.input_proofs.empty());
    BOOST_REQUIRE(sig.input_proofs[0].challenges.size() == lattice::RING_SIZE);

    sig.input_proofs[0].challenges[(lattice::RING_SIZE - 1)] = GetRandHash();
    BOOST_CHECK(!VerifyRingSignature(sig, ring_members, message_hash));
}

BOOST_AUTO_TEST_CASE(public_key_offset_tamper_detected)
{
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) member = GetRandHash();

    std::vector<size_t> real_indices{2};
    std::vector<unsigned char> spending_key(32, 0x91);
    const uint256 message_hash = GetRandHash();

    RingSignature sig;
    BOOST_REQUIRE(CreateRingSignatureForTest(sig, ring_members, real_indices, spending_key, message_hash));
    BOOST_REQUIRE_EQUAL(sig.member_public_key_offsets.size(), 1U);
    BOOST_REQUIRE_EQUAL(sig.member_public_key_offsets[0].size(), lattice::RING_SIZE);
    BOOST_REQUIRE_EQUAL(sig.member_public_key_offsets[0][0].size(), lattice::MODULE_RANK);

    sig.member_public_key_offsets[0][0][0].coeffs[0] ^= 1;
    BOOST_CHECK(!VerifyRingSignature(sig, ring_members, message_hash));
}

BOOST_AUTO_TEST_CASE(duplicate_effective_public_keys_rejected)
{
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) member = GetRandHash();

    const std::vector<size_t> real_indices{4};
    std::vector<unsigned char> spending_key(32, 0x5C);
    const uint256 message_hash = GetRandHash();

    RingSignature sig;
    BOOST_REQUIRE(CreateRingSignatureForTest(sig, ring_members, real_indices, spending_key, message_hash));
    BOOST_REQUIRE(VerifyRingSignature(sig, ring_members, message_hash));
    BOOST_REQUIRE_EQUAL(sig.member_public_key_offsets.size(), 1U);
    BOOST_REQUIRE_EQUAL(sig.member_public_key_offsets[0].size(), lattice::RING_SIZE);

    const lattice::PolyVec pk_0 = DeriveTestPublicKey(ring_members[0][0], 0);
    const lattice::PolyVec pk_1 = DeriveTestPublicKey(ring_members[0][1], 1);
    sig.member_public_key_offsets[0][1] = lattice::PolyVecAdd(
        sig.member_public_key_offsets[0][0],
        lattice::PolyVecSub(pk_0, pk_1));

    BOOST_CHECK(!VerifyRingSignature(sig, ring_members, message_hash));
}

BOOST_AUTO_TEST_CASE(serialized_size_is_compact)
{
    std::vector<std::vector<uint256>> ring_members(2, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& ring : ring_members) {
        for (auto& member : ring) member = GetRandHash();
    }

    std::vector<size_t> real_indices{1, 7};
    const uint256 message_hash = GetRandHash();
    std::vector<unsigned char> spending_key(32, 0x33);

    RingSignature sig;
    BOOST_REQUIRE(CreateRingSignatureForTest(sig, ring_members, real_indices, spending_key, message_hash));
    BOOST_CHECK(VerifyRingSignature(sig, ring_members, message_hash));

    // Lattice-based ring signatures are larger than elliptic-curve ones;
    // 256 KB is a generous upper bound for a single-input proof.
    BOOST_CHECK_LT(sig.GetSerializedSize(), static_cast<size_t>(256 * 1024));
}

BOOST_AUTO_TEST_CASE(derive_input_nullifier_is_deterministic)
{
    std::vector<unsigned char> spending_key(32, 0x5A);
    const uint256 ring_member = GetRandHash();

    Nullifier nf1;
    Nullifier nf2;
    BOOST_REQUIRE(DeriveInputNullifierForTest(nf1,
                                       Span<const unsigned char>{spending_key.data(), spending_key.size()},
                                       ring_member));
    BOOST_REQUIRE(DeriveInputNullifierForTest(nf2,
                                       Span<const unsigned char>{spending_key.data(), spending_key.size()},
                                       ring_member));
    BOOST_CHECK(nf1 == nf2);
}

BOOST_AUTO_TEST_CASE(derive_input_secret_from_note_requires_32_byte_key_and_nonzero_secret)
{
    ShieldedNote note;
    note.value = 42;
    note.recipient_pk_hash = DeterministicVectorHash("note-pk", 0);
    note.rho = DeterministicVectorHash("note-rho", 0);
    note.rcm = DeterministicVectorHash("note-rcm", 0);

    lattice::PolyVec secret;
    std::array<unsigned char, 31> short_spending_key{};
    for (size_t i = 0; i < short_spending_key.size(); ++i) {
        short_spending_key[i] = static_cast<unsigned char>(0x20 + i);
    }
    BOOST_CHECK(!DeriveInputSecretFromNote(secret,
                                           Span<const unsigned char>{short_spending_key.data(), short_spending_key.size()},
                                           note));
    BOOST_CHECK(secret.empty());

    std::array<unsigned char, 32> spending_key{};
    for (size_t i = 0; i < spending_key.size(); ++i) {
        spending_key[i] = static_cast<unsigned char>(0x40 + i);
    }
    BOOST_REQUIRE(DeriveInputSecretFromNote(secret,
                                            Span<const unsigned char>{spending_key.data(), spending_key.size()},
                                            note));
    BOOST_REQUIRE_EQUAL(secret.size(), lattice::MODULE_RANK);
    BOOST_CHECK_GT(lattice::PolyVecInfNorm(secret), 0);

    lattice::PolyVec secret_repeat;
    BOOST_REQUIRE(DeriveInputSecretFromNote(secret_repeat,
                                            Span<const unsigned char>{spending_key.data(), spending_key.size()},
                                            note));
    BOOST_CHECK_EQUAL(PolyVecHash(secret), PolyVecHash(secret_repeat));
}

BOOST_AUTO_TEST_CASE(ring_signature_nullifier_binding_detects_tamper)
{
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) member = GetRandHash();

    std::vector<size_t> real_indices{3};
    const uint256 message_hash = GetRandHash();
    std::vector<unsigned char> spending_key(32, 0x29);

    RingSignature sig;
    BOOST_REQUIRE(CreateRingSignatureForTest(sig, ring_members, real_indices, spending_key, message_hash));
    BOOST_CHECK(VerifyRingSignature(sig, ring_members, message_hash));

    std::vector<Nullifier> bound_nullifiers;
    bound_nullifiers.reserve(sig.key_images.size());
    for (const auto& key_image : sig.key_images) {
        bound_nullifiers.push_back(ComputeNullifierFromKeyImage(key_image));
    }
    BOOST_CHECK(VerifyRingSignatureNullifierBinding(sig, bound_nullifiers));

    bound_nullifiers[0] = GetRandHash();
    BOOST_CHECK(!VerifyRingSignatureNullifierBinding(sig, bound_nullifiers));
}

BOOST_AUTO_TEST_CASE(create_rejects_zero_input_secret)
{
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) member = GetRandHash();

    const std::vector<size_t> real_indices{3};
    const uint256 message_hash = GetRandHash();

    std::vector<lattice::PolyVec> input_secrets;
    input_secrets.emplace_back(lattice::MODULE_RANK);

    RingSignature sig;
    BOOST_CHECK(!CreateRingSignature(sig, ring_members, real_indices, input_secrets, message_hash));
}

BOOST_AUTO_TEST_CASE(response_distribution_limits_real_index_bias)
{
    constexpr int kSamples{24};
    // Use deterministic ring members and messages for reproducibility.
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (size_t i = 0; i < lattice::RING_SIZE; ++i) {
        ring_members[0][i] = DeterministicVectorHash("bias-member", static_cast<uint32_t>(i));
    }

    std::vector<unsigned char> spending_key(32);
    for (size_t i = 0; i < spending_key.size(); ++i) {
        spending_key[i] = static_cast<unsigned char>(i);
    }

    int max_norm_hits_on_real{0};
    int64_t total_real_norm{0};
    int64_t total_decoy_norm{0};
    int decoy_norm_count{0};

    for (int trial = 0; trial < kSamples; ++trial) {
        const size_t real_index = static_cast<size_t>(trial % static_cast<int>(lattice::RING_SIZE));
        const uint256 message = DeterministicVectorHash("bias-message", static_cast<uint32_t>(trial));
        RingSignature sig;
        BOOST_REQUIRE(CreateRingSignatureForTest(sig,
                                          ring_members,
                                          {real_index},
                                          spending_key,
                                          message));
        BOOST_REQUIRE_EQUAL(sig.input_proofs.size(), 1U);
        BOOST_REQUIRE_EQUAL(sig.input_proofs[0].responses.size(), lattice::RING_SIZE);

        int32_t max_norm{-1};
        size_t max_norm_index{0};
        for (size_t i = 0; i < lattice::RING_SIZE; ++i) {
            const int32_t norm = lattice::PolyVecInfNorm(sig.input_proofs[0].responses[i]);
            if (norm > max_norm) {
                max_norm = norm;
                max_norm_index = i;
            }
            if (i == real_index) {
                total_real_norm += norm;
            } else {
                total_decoy_norm += norm;
                ++decoy_norm_count;
            }
        }

        if (max_norm_index == real_index) ++max_norm_hits_on_real;
        BOOST_CHECK(VerifyRingSignature(sig, ring_members, message));
    }

    const double avg_real = static_cast<double>(total_real_norm) / kSamples;
    const double avg_decoy = static_cast<double>(total_decoy_norm) / decoy_norm_count;
    BOOST_TEST_MESSAGE("ring-response stats: max-hit-real="
                       << max_norm_hits_on_real
                       << "/"
                       << kSamples
                       << " avg_real="
                       << avg_real
                       << " avg_decoy="
                       << avg_decoy);

    // Keep response distributions statistically close across real/decoy indices.
    // With only 24 samples, a tolerance of 16.0 accommodates normal variance
    // while still catching gross bias (a biased scheme would diverge by 100+).
    BOOST_CHECK_LE(max_norm_hits_on_real, kSamples / 2);
    BOOST_CHECK(std::abs(avg_real - avg_decoy) < 16.0);
}

BOOST_AUTO_TEST_CASE(known_answer_vectors_for_deterministic_derivations)
{
    std::vector<unsigned char> spending_key(32);
    for (size_t i = 0; i < spending_key.size(); ++i) {
        spending_key[i] = static_cast<unsigned char>(0xA0 + i);
    }
    const uint256 ring_member{"11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"};

    Nullifier nf;
    BOOST_REQUIRE(DeriveInputNullifierForTest(nf,
                                       Span<const unsigned char>{spending_key.data(), spending_key.size()},
                                       ring_member));
    BOOST_CHECK_EQUAL(nf, uint256{"2e282e9e614f5f9f77c45582a9d528039c4d61f6b126eb16a6cbef07cd17c57f"});

    FastRandomContext rng_a{uint256{"00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa"}};
    FastRandomContext rng_b{uint256{"55bb55bb55bb55bb55bb55bb55bb55bb55bb55bb55bb55bb55bb55bb55bb55bb"}};
    const lattice::PolyVec blind_a = lattice::SampleSmallVec(rng_a, lattice::MODULE_RANK, /*eta=*/2);
    const lattice::PolyVec blind_b = lattice::SampleSmallVec(rng_b, lattice::MODULE_RANK, /*eta=*/2);
    const Commitment in0 = Commit(/*value=*/13, blind_a);
    const Commitment in1 = Commit(/*value=*/21, blind_b);
    const Commitment out0 = Commit(/*value=*/31, blind_a);
    const std::vector<Nullifier> input_nullifiers{
        uint256{"0f0e0d0c0b0a09080706050403020100ffeeddccbbaa99887766554433221100"},
        uint256{"00112233445566778899aabbccddeeff0f0e0d0c0b0a09080706050403020100"},
    };
    const uint256 tx_binding_hash{"1234567890abcdef00112233445566778899aabbccddeeff1122334455667788"};
    const uint256 msg_hash = RingSignatureMessageHash({in0, in1}, {out0}, /*fee=*/3, input_nullifiers, tx_binding_hash);
    BOOST_CHECK_EQUAL(msg_hash, uint256{"11d9cac523f007a94904f74314f9e3ed89da86b0d8300bcb78bf1511ad3dc448"});
}

BOOST_AUTO_TEST_CASE(duplicate_key_images_are_rejected)
{
    std::vector<std::vector<uint256>> ring_members(2, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& ring : ring_members) {
        for (auto& member : ring) {
            member = GetRandHash();
        }
    }
    // Force duplicate key images by reusing the exact same ring member in both inputs.
    ring_members[1] = ring_members[0];

    const std::vector<size_t> real_indices{5, 5};
    std::vector<unsigned char> spending_key(32, 0x7A);
    const uint256 message_hash = GetRandHash();

    RingSignature sig;
    std::vector<lattice::PolyVec> duplicate_input_secrets;
    duplicate_input_secrets.reserve(2);
    duplicate_input_secrets.push_back(DeriveTestInputSecret(spending_key, ring_members[0][real_indices[0]], 0));
    duplicate_input_secrets.push_back(duplicate_input_secrets[0]);
    BOOST_CHECK(!CreateRingSignature(sig, ring_members, real_indices, duplicate_input_secrets, message_hash));

    // Also verify explicit key-image tampering is detected.
    const std::vector<size_t> distinct_real_indices{5, 7};
    BOOST_REQUIRE(CreateRingSignatureForTest(sig, ring_members, distinct_real_indices, spending_key, message_hash));
    BOOST_REQUIRE_EQUAL(sig.key_images.size(), 2U);
    sig.key_images[1] = sig.key_images[0];
    BOOST_CHECK(!VerifyRingSignature(sig, ring_members, message_hash));
}

BOOST_AUTO_TEST_CASE(duplicate_ring_members_are_rejected_by_creation)
{
    // Duplicate ring members must be rejected by CreateRingSignature to
    // prevent ring-degeneracy attacks.
    constexpr size_t ring_size{16};
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(ring_size));
    for (size_t i = 0; i < ring_size; ++i) {
        ring_members[0][i] = DeterministicVectorHash("dup-member", static_cast<uint32_t>(i));
    }
    ring_members[0][10] = ring_members[0][3]; // introduce duplicate

    const std::vector<size_t> real_indices{3};
    std::vector<unsigned char> spending_key(32, 0x47);
    const uint256 message_hash = DeterministicVectorHash("dup-message", 0);

    RingSignature sig;
    BOOST_CHECK(!CreateRingSignatureForTest(sig, ring_members, real_indices, spending_key, message_hash));
}

BOOST_AUTO_TEST_CASE(slot_domain_separation_produces_distinct_public_keys)
{
    // Same ring member hash at different slot indices must derive different
    // public keys, ensuring domain separation in the MatRiCT+ construction.
    const uint256 member = DeterministicVectorHash("dup-member", 3);
    const lattice::PolyVec pk_a = DeriveTestPublicKey(member, 3);
    const lattice::PolyVec pk_b = DeriveTestPublicKey(member, 10);
    BOOST_CHECK(PolyVecHash(pk_a) != PolyVecHash(pk_b));
}

BOOST_AUTO_TEST_CASE(null_ring_members_are_rejected)
{
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (size_t i = 0; i < lattice::RING_SIZE; ++i) {
        ring_members[0][i] = DeterministicVectorHash("null-member", static_cast<uint32_t>(i));
    }
    ring_members[0][6] = uint256{};

    const std::vector<size_t> real_indices{3};
    std::vector<unsigned char> spending_key(32, 0x61);
    const uint256 message_hash = DeterministicVectorHash("null-message", 0);

    RingSignature sig;
    BOOST_CHECK(!CreateRingSignatureForTest(sig, ring_members, real_indices, spending_key, message_hash));
}

BOOST_AUTO_TEST_CASE(verify_rejects_null_member_ring)
{
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& member : ring_members[0]) member = GetRandHash();

    const std::vector<size_t> real_indices{4};
    std::vector<unsigned char> spending_key(32, 0x62);
    const uint256 message_hash = GetRandHash();

    RingSignature sig;
    BOOST_REQUIRE(CreateRingSignatureForTest(sig, ring_members, real_indices, spending_key, message_hash));
    BOOST_REQUIRE(VerifyRingSignature(sig, ring_members, message_hash));

    ring_members[0][0] = uint256{};
    BOOST_CHECK(!VerifyRingSignature(sig, ring_members, message_hash));
}

BOOST_AUTO_TEST_CASE(rejects_oversized_input_count)
{
    const size_t oversized_inputs = MAX_RING_SIGNATURE_INPUTS + 1;
    std::vector<std::vector<uint256>> ring_members(oversized_inputs, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& ring : ring_members) {
        for (auto& member : ring) member = GetRandHash();
    }
    std::vector<size_t> real_indices(oversized_inputs, 0);
    std::vector<unsigned char> spending_key(32, 0x4C);
    const uint256 message_hash = GetRandHash();

    RingSignature sig;
    BOOST_CHECK(!CreateRingSignatureForTest(sig, ring_members, real_indices, spending_key, message_hash));
    BOOST_CHECK(!VerifyRingSignature(sig, ring_members, message_hash));
}

BOOST_AUTO_TEST_CASE(serialize_rejects_oversized_input_proof_vector_count)
{
    RingSignature sig;
    sig.input_proofs.resize(MAX_RING_SIGNATURE_INPUTS + 1);

    DataStream ss;
    BOOST_CHECK_EXCEPTION(ss << sig,
                          std::ios_base::failure,
                          HasReason("RingSignature::Serialize oversized input_proofs count"));
}

BOOST_AUTO_TEST_CASE(unserialize_rejects_oversized_input_proof_vector_count)
{
    DataStream ss;
    uint64_t input_proof_count = MAX_RING_SIGNATURE_INPUTS + 1;
    ::Serialize(ss, COMPACTSIZE(input_proof_count));

    RingSignature decoded;
    BOOST_CHECK_EXCEPTION(ss >> decoded,
                          std::ios_base::failure,
                          HasReason("RingSignature::Unserialize oversized input_proofs count"));
}

BOOST_AUTO_TEST_CASE(unserialize_polyvec_signed8_rejects_invalid_packed_length)
{
    DataStream ss;
    uint64_t packed_count = (lattice::MODULE_RANK * lattice::POLY_N) + 1;
    ::Serialize(ss, COMPACTSIZE(packed_count));

    lattice::PolyVec decoded;
    BOOST_CHECK_EXCEPTION(UnserializePolyVecSigned8(ss, decoded, "proof-encoding-s8"),
                          std::ios_base::failure,
                          HasReason("proof-encoding-s8: invalid packed signed8 length"));
}

BOOST_AUTO_TEST_CASE(unserialize_polyvec_signed16_rejects_invalid_packed_length)
{
    DataStream ss;
    uint64_t packed_count = (lattice::MODULE_RANK * lattice::POLY_N) + 1;
    ::Serialize(ss, COMPACTSIZE(packed_count));

    lattice::PolyVec decoded;
    BOOST_CHECK_EXCEPTION(UnserializePolyVecSigned16(ss, decoded, "proof-encoding-s16"),
                          std::ios_base::failure,
                          HasReason("proof-encoding-s16: invalid packed signed16 length"));
}

BOOST_AUTO_TEST_CASE(unserialize_polyvec_modq24_rejects_invalid_packed_length)
{
    DataStream ss;
    uint64_t packed_count = POLYVEC_MODQ24_PACKED_SIZE + 1;
    ::Serialize(ss, COMPACTSIZE(packed_count));

    lattice::PolyVec decoded;
    BOOST_CHECK_EXCEPTION(UnserializePolyVecModQ24(ss, decoded, "proof-encoding-modq24"),
                          std::ios_base::failure,
                          HasReason("proof-encoding-modq24: invalid packed mod-q length"));
}

BOOST_AUTO_TEST_CASE(derive_input_nullifier_changes_with_key_and_member)
{
    std::vector<unsigned char> spending_key_a(32, 0x11);
    std::vector<unsigned char> spending_key_b(32, 0x22);
    const uint256 ring_member_a = GetRandHash();
    const uint256 ring_member_b = GetRandHash();

    Nullifier nf_aa;
    Nullifier nf_ab;
    Nullifier nf_ba;
    BOOST_REQUIRE(DeriveInputNullifierForTest(nf_aa,
                                       Span<const unsigned char>{spending_key_a.data(), spending_key_a.size()},
                                       ring_member_a));
    BOOST_REQUIRE(DeriveInputNullifierForTest(nf_ab,
                                       Span<const unsigned char>{spending_key_a.data(), spending_key_a.size()},
                                       ring_member_b));
    BOOST_REQUIRE(DeriveInputNullifierForTest(nf_ba,
                                       Span<const unsigned char>{spending_key_b.data(), spending_key_b.size()},
                                       ring_member_a));

    BOOST_CHECK(nf_aa != nf_ab);
    BOOST_CHECK(nf_aa != nf_ba);
    BOOST_CHECK(nf_ab != nf_ba);
}

BOOST_AUTO_TEST_CASE(deterministic_ring_signature_known_answer_vector)
{
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (size_t i = 0; i < lattice::RING_SIZE; ++i) {
        ring_members[0][i] = DeterministicVectorHash("member", static_cast<uint32_t>(i));
    }
    const std::vector<size_t> real_indices{7};
    std::vector<unsigned char> spending_key(32);
    for (size_t i = 0; i < spending_key.size(); ++i) {
        spending_key[i] = static_cast<unsigned char>(0x30 + i);
    }
    const uint256 message_hash = DeterministicVectorHash("message", 0);

    RingSignature sig_a;
    RingSignature sig_b;
    BOOST_REQUIRE(CreateRingSignatureForTest(sig_a, ring_members, real_indices, spending_key, message_hash));
    BOOST_REQUIRE(CreateRingSignatureForTest(sig_b, ring_members, real_indices, spending_key, message_hash));
    BOOST_REQUIRE(VerifyRingSignature(sig_a, ring_members, message_hash));
    BOOST_REQUIRE(VerifyRingSignature(sig_b, ring_members, message_hash));

    const uint256 hash_a = SerializeRingSignatureHash(sig_a);
    const uint256 hash_b = SerializeRingSignatureHash(sig_b);
    BOOST_CHECK_EQUAL(hash_a, hash_b);
    // R6-306: Frozen ring signature KAT — pinned hash detects silent changes.
    BOOST_CHECK_EQUAL(hash_a, uint256{"7b4fd90250f9d9ac64450475d4c74e7982cef9b0ad18dceedc11c6a4a226a197"});
}

BOOST_AUTO_TEST_CASE(hedged_entropy_changes_signature_but_verifies)
{
    std::vector<std::vector<uint256>> ring_members(1, std::vector<uint256>(lattice::RING_SIZE));
    for (size_t i = 0; i < lattice::RING_SIZE; ++i) {
        ring_members[0][i] = DeterministicVectorHash("entropy-member", static_cast<uint32_t>(i));
    }
    const std::vector<size_t> real_indices{4};
    std::vector<unsigned char> spending_key(32);
    for (size_t i = 0; i < spending_key.size(); ++i) {
        spending_key[i] = static_cast<unsigned char>(0x61 + i);
    }
    const uint256 message_hash = DeterministicVectorHash("entropy-message", 0);

    std::array<unsigned char, 32> entropy_a{};
    std::array<unsigned char, 32> entropy_b{};
    for (size_t i = 0; i < entropy_a.size(); ++i) {
        entropy_a[i] = static_cast<unsigned char>(i + 1);
        entropy_b[i] = static_cast<unsigned char>(0xC0 + i);
    }

    RingSignature sig_a;
    RingSignature sig_b;
    RingSignature sig_a_repeat;
    BOOST_REQUIRE(CreateRingSignatureForTest(sig_a,
                                      ring_members,
                                      real_indices,
                                      spending_key,
                                      message_hash,
                                      Span<const unsigned char>{entropy_a.data(), entropy_a.size()}));
    BOOST_REQUIRE(CreateRingSignatureForTest(sig_b,
                                      ring_members,
                                      real_indices,
                                      spending_key,
                                      message_hash,
                                      Span<const unsigned char>{entropy_b.data(), entropy_b.size()}));
    BOOST_REQUIRE(CreateRingSignatureForTest(sig_a_repeat,
                                      ring_members,
                                      real_indices,
                                      spending_key,
                                      message_hash,
                                      Span<const unsigned char>{entropy_a.data(), entropy_a.size()}));

    BOOST_CHECK(VerifyRingSignature(sig_a, ring_members, message_hash));
    BOOST_CHECK(VerifyRingSignature(sig_b, ring_members, message_hash));
    BOOST_CHECK(VerifyRingSignature(sig_a_repeat, ring_members, message_hash));

    const uint256 hash_a = SerializeRingSignatureHash(sig_a);
    const uint256 hash_b = SerializeRingSignatureHash(sig_b);
    const uint256 hash_a_repeat = SerializeRingSignatureHash(sig_a_repeat);

    BOOST_CHECK(hash_a != hash_b);
    BOOST_CHECK_EQUAL(hash_a, hash_a_repeat);
}

BOOST_AUTO_TEST_CASE(public_key_offset_intersection_is_input_localized)
{
    constexpr size_t ring_size{16};
    std::vector<std::vector<uint256>> ring_members(2, std::vector<uint256>(ring_size));
    for (size_t input_idx = 0; input_idx < ring_members.size(); ++input_idx) {
        for (size_t member_idx = 0; member_idx < ring_size; ++member_idx) {
            ring_members[input_idx][member_idx] = DeterministicVectorHash(
                "offset-intersection",
                static_cast<uint32_t>(input_idx * 100 + member_idx));
        }
    }

    const std::vector<size_t> real_indices{3, 11};
    std::vector<unsigned char> spending_key(32);
    for (size_t i = 0; i < spending_key.size(); ++i) {
        spending_key[i] = static_cast<unsigned char>(0x51 + i);
    }
    const uint256 message_hash = DeterministicVectorHash("offset-message", 0);

    RingSignature sig;
    BOOST_REQUIRE(CreateRingSignatureForTest(sig, ring_members, real_indices, spending_key, message_hash));
    BOOST_REQUIRE(VerifyRingSignature(sig, ring_members, message_hash));
    BOOST_REQUIRE_EQUAL(sig.member_public_key_offsets.size(), ring_members.size());

    std::vector<std::set<uint256>> candidate_sets(ring_members.size());
    for (size_t input_idx = 0; input_idx < ring_members.size(); ++input_idx) {
        BOOST_REQUIRE_EQUAL(sig.member_public_key_offsets[input_idx].size(), ring_size);
        for (size_t member_idx = 0; member_idx < ring_size; ++member_idx) {
            const lattice::PolyVec candidate = lattice::PolyVecAdd(
                DeriveTestPublicKey(ring_members[input_idx][member_idx], member_idx),
                sig.member_public_key_offsets[input_idx][member_idx]);
            BOOST_REQUIRE(lattice::IsValidPolyVec(candidate));
            candidate_sets[input_idx].insert(PolyVecHash(candidate));
        }
    }

    size_t overlap{0};
    for (const uint256& candidate : candidate_sets[0]) {
        if (candidate_sets[1].count(candidate) != 0) ++overlap;
    }
    BOOST_CHECK_EQUAL(overlap, 0U);
}

BOOST_AUTO_TEST_CASE(create_verify_ring_signature_supports_larger_supported_ring_sizes)
{
    for (const size_t ring_size : {size_t{16}, lattice::MAX_RING_SIZE}) {
        auto ring_members = MakeRandomRingMembers(2, ring_size);
        const std::vector<size_t> real_indices{2, ring_size - 1};
        const uint256 message_hash = GetRandHash();
        std::vector<unsigned char> spending_key(32, static_cast<unsigned char>(0x20 + ring_size));

        RingSignature sig;
        BOOST_REQUIRE_MESSAGE(CreateRingSignatureForTest(sig, ring_members, real_indices, spending_key, message_hash),
                              "CreateRingSignature failed for ring_size=" + std::to_string(ring_size));
        BOOST_CHECK_MESSAGE(VerifyRingSignature(sig, ring_members, message_hash),
                            "VerifyRingSignature failed for ring_size=" + std::to_string(ring_size));
    }
}

BOOST_AUTO_TEST_SUITE_END()
