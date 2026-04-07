// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/ringct/commitment.h>
#include <hash.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <ios>

using namespace shielded::ringct;
namespace lattice = shielded::lattice;

BOOST_FIXTURE_TEST_SUITE(ringct_commitment_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(commit_open_verify_roundtrip)
{
    CommitmentOpening opening;
    opening.value = 12345;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    opening.blind[0].coeffs[0] = 7;

    const Commitment c = Commit(opening.value, opening.blind);
    BOOST_CHECK(c.IsValid());
    BOOST_CHECK(VerifyCommitment(c, opening));
}

BOOST_AUTO_TEST_CASE(commit_with_seed_is_deterministic)
{
    const std::array<unsigned char, 16> seed{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const Commitment c1 = CommitWithSeed(/*value=*/888, seed);
    const Commitment c2 = CommitWithSeed(/*value=*/888, seed);

    BOOST_CHECK(c1.vec == c2.vec);
    BOOST_CHECK(CommitmentHash(c1) == CommitmentHash(c2));
}

BOOST_AUTO_TEST_CASE(additivity_property_mod_q)
{
    CommitmentOpening a;
    a.value = 100;
    a.blind = lattice::PolyVec(lattice::MODULE_RANK);
    a.blind[0].coeffs[0] = 11;

    CommitmentOpening b;
    b.value = 150;
    b.blind = lattice::PolyVec(lattice::MODULE_RANK);
    b.blind[0].coeffs[0] = 22;

    const Commitment ca = Commit(a.value, a.blind);
    const Commitment cb = Commit(b.value, b.blind);
    const Commitment sum = CommitmentAdd(ca, cb);

    CommitmentOpening expected;
    expected.value = a.value + b.value;
    expected.blind = lattice::PolyVecAdd(a.blind, b.blind);

    BOOST_CHECK(VerifyCommitment(sum, expected));
}

BOOST_AUTO_TEST_CASE(commitment_serialization_roundtrip)
{
    CommitmentOpening opening;
    opening.value = 42;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    opening.blind[0].coeffs[0] = 17;

    const Commitment original = Commit(opening.value, opening.blind);
    DataStream ds;
    ds << original;

    Commitment decoded;
    ds >> decoded;
    BOOST_CHECK(decoded.vec == original.vec);
    BOOST_CHECK_LT(decoded.GetSerializedSize(), static_cast<size_t>(4 * 1024));
}

BOOST_AUTO_TEST_CASE(commitment_deserialize_rejects_out_of_range_coeff)
{
    CommitmentOpening opening;
    opening.value = 7;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    const Commitment original = Commit(opening.value, opening.blind);

    DataStream ds;
    ds << original;
    BOOST_REQUIRE_GE(ds.size(), 3U); // first packed coeff spans 23 bits across bytes 0..2

    // First packed coeff (little-endian 23-bit field) -> set to 0x7FFFFF (> q), which must be rejected.
    ds[0] = std::byte{0xFF};
    ds[1] = std::byte{0xFF};
    ds[2] = std::byte{0x7F};

    Commitment decoded;
    BOOST_CHECK_THROW(ds >> decoded, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(commitment_modq23_serialization_boundary_roundtrip)
{
    Commitment original;
    original.vec = lattice::PolyVec(lattice::MODULE_RANK);
    for (size_t rank = 0; rank < lattice::MODULE_RANK; ++rank) {
        for (size_t i = 0; i < lattice::POLY_N; ++i) {
            const bool use_max = ((rank + i) & 1U) == 0;
            original.vec[rank].coeffs[i] = use_max ? (lattice::POLY_Q - 1) : 0;
        }
    }
    BOOST_REQUIRE(original.IsValid());

    DataStream ds;
    ds << original;

    Commitment decoded;
    ds >> decoded;
    BOOST_CHECK(decoded.vec == original.vec);
}

BOOST_AUTO_TEST_CASE(deterministic_commitment_known_answer_vector)
{
    // Fixed inputs for deterministic KAT vector
    CommitmentOpening opening;
    opening.value = 42;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    for (size_t rank = 0; rank < lattice::MODULE_RANK; ++rank) {
        for (size_t i = 0; i < lattice::POLY_N; ++i) {
            opening.blind[rank].coeffs[i] = static_cast<int32_t>((rank * 256 + i) % 17);
        }
    }

    const Commitment commitment = Commit(opening.value, opening.blind);
    BOOST_CHECK(commitment.IsValid());
    BOOST_CHECK(VerifyCommitment(commitment, opening));

    // R5-302 + R6-305: Frozen commitment KAT — pinned hash detects silent changes.
    const uint256 kat_hash = CommitmentHash(commitment);
    BOOST_CHECK_EQUAL(kat_hash.GetHex(),
                      "fe88c4b9969a61e1ca65e0009eb8ad129ede5bda573b9f1949b27390b703eb3f");

    // Verify reproducibility — same inputs must always produce same commitment.
    const Commitment commitment_b = Commit(opening.value, opening.blind);
    BOOST_CHECK_EQUAL(CommitmentHash(commitment_b), kat_hash);

    // Self-consistency: verify the opening still validates against the re-computed commitment.
    BOOST_CHECK(VerifyCommitment(commitment_b, opening));
}

BOOST_AUTO_TEST_CASE(zero_value_commitment_roundtrip)
{
    CommitmentOpening opening;
    opening.value = 0;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    opening.blind[0].coeffs[0] = 7;

    const Commitment c = Commit(opening.value, opening.blind);
    BOOST_CHECK(c.IsValid());
    BOOST_CHECK(VerifyCommitment(c, opening));
}

BOOST_AUTO_TEST_CASE(max_money_commitment_roundtrip)
{
    CommitmentOpening opening;
    opening.value = MAX_MONEY;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    opening.blind[0].coeffs[0] = 11;

    const Commitment c = Commit(opening.value, opening.blind);
    BOOST_CHECK(c.IsValid());
    BOOST_CHECK(VerifyCommitment(c, opening));
}

BOOST_AUTO_TEST_CASE(commitment_hiding_property)
{
    // Same value with different blinds must produce different commitments
    CommitmentOpening a, b;
    a.value = 100;
    b.value = 100;
    a.blind = lattice::PolyVec(lattice::MODULE_RANK);
    b.blind = lattice::PolyVec(lattice::MODULE_RANK);
    a.blind[0].coeffs[0] = 1;
    b.blind[0].coeffs[0] = 2;

    const Commitment ca = Commit(a.value, a.blind);
    const Commitment cb = Commit(b.value, b.blind);

    BOOST_CHECK(ca.vec != cb.vec);
}

BOOST_AUTO_TEST_SUITE_END()
