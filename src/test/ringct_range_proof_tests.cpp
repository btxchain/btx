// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/ringct/range_proof.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using namespace shielded::ringct;
namespace lattice = shielded::lattice;

BOOST_FIXTURE_TEST_SUITE(ringct_range_proof_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(create_verify_range_proof)
{
    CommitmentOpening opening;
    opening.value = 777;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    opening.blind[0].coeffs[0] = 5;

    const Commitment commitment = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_CHECK(CreateRangeProof(proof, opening, commitment));
    BOOST_CHECK(VerifyRangeProof(proof, commitment));
}

BOOST_AUTO_TEST_CASE(negative_value_rejected)
{
    CommitmentOpening opening;
    opening.value = -1;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);

    const Commitment commitment = Commit(/*value=*/0, opening.blind);

    RangeProof proof;
    BOOST_CHECK(!CreateRangeProof(proof, opening, commitment));
}

BOOST_AUTO_TEST_CASE(value_above_range_bits_rejected)
{
    CommitmentOpening opening;
    opening.value = static_cast<CAmount>(uint64_t{1} << lattice::VALUE_BITS);
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);

    const Commitment commitment = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_CHECK(!CreateRangeProof(proof, opening, commitment));
}

BOOST_AUTO_TEST_CASE(tamper_fails_verification)
{
    CommitmentOpening opening;
    opening.value = 333;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    opening.blind[0].coeffs[0] = 9;

    const Commitment commitment = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_REQUIRE(CreateRangeProof(proof, opening, commitment));

    BOOST_REQUIRE(!proof.bit_proofs.empty());
    proof.bit_proofs[0].c0 = GetRandHash();
    BOOST_CHECK(!VerifyRangeProof(proof, commitment));
}

BOOST_AUTO_TEST_CASE(binding_tamper_fails_verification)
{
    CommitmentOpening opening;
    opening.value = 444;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    opening.blind[0].coeffs[0] = 6;

    const Commitment commitment = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_REQUIRE(CreateRangeProof(proof, opening, commitment));
    proof.bit_proof_binding = GetRandHash();
    BOOST_CHECK(!VerifyRangeProof(proof, commitment));
}

BOOST_AUTO_TEST_CASE(serialized_size_is_compact)
{
    CommitmentOpening opening;
    opening.value = 123456;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    opening.blind[0].coeffs[0] = 7;

    const Commitment commitment = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_REQUIRE(CreateRangeProof(proof, opening, commitment));
    BOOST_CHECK(VerifyRangeProof(proof, commitment));

    const size_t proof_size = proof.GetSerializedSize();
    BOOST_TEST_MESSAGE("Range proof serialized size: " << proof_size << " bytes");
    // Tight guardrail for VALUE_BITS=51 with polynomial-challenge proofs.
    BOOST_CHECK_LT(proof_size, static_cast<size_t>(512 * 1024));
}

BOOST_AUTO_TEST_CASE(max_money_value_roundtrip)
{
    CommitmentOpening opening;
    opening.value = MAX_MONEY;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    opening.blind[0].coeffs[0] = 11;

    const Commitment commitment = Commit(opening.value, opening.blind);
    RangeProof proof;
    BOOST_REQUIRE(CreateRangeProof(proof, opening, commitment));
    BOOST_CHECK(VerifyRangeProof(proof, commitment));
}

BOOST_AUTO_TEST_CASE(zero_value_range_proof_roundtrip)
{
    CommitmentOpening opening;
    opening.value = 0;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    opening.blind[0].coeffs[0] = 13;

    const Commitment commitment = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_CHECK(CreateRangeProof(proof, opening, commitment));
    BOOST_CHECK(VerifyRangeProof(proof, commitment));
}

BOOST_AUTO_TEST_CASE(value_one_range_proof_roundtrip)
{
    CommitmentOpening opening;
    opening.value = 1;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    opening.blind[0].coeffs[0] = 4;

    const Commitment commitment = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_CHECK(CreateRangeProof(proof, opening, commitment));
    BOOST_CHECK(VerifyRangeProof(proof, commitment));
}

BOOST_AUTO_TEST_CASE(power_of_two_boundary_range_proof_roundtrip)
{
    // Test value = 2^50 (one below VALUE_BITS boundary)
    CommitmentOpening opening;
    opening.value = static_cast<CAmount>(uint64_t{1} << 50);
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    opening.blind[0].coeffs[0] = 8;

    const Commitment commitment = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_CHECK(CreateRangeProof(proof, opening, commitment));
    BOOST_CHECK(VerifyRangeProof(proof, commitment));
}

BOOST_AUTO_TEST_CASE(max_range_value_roundtrip)
{
    // Test value = 2^51 - 1 (maximum representable in VALUE_BITS)
    CommitmentOpening opening;
    opening.value = static_cast<CAmount>((uint64_t{1} << lattice::VALUE_BITS) - 1);
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    opening.blind[0].coeffs[0] = 15;

    const Commitment commitment = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_CHECK(CreateRangeProof(proof, opening, commitment));
    BOOST_CHECK(VerifyRangeProof(proof, commitment));
}

BOOST_AUTO_TEST_CASE(wrong_commitment_fails_verification)
{
    CommitmentOpening opening;
    opening.value = 555;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    opening.blind[0].coeffs[0] = 3;

    const Commitment commitment = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_REQUIRE(CreateRangeProof(proof, opening, commitment));

    // Try verifying against a different commitment
    CommitmentOpening other_opening;
    other_opening.value = 556;
    other_opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    other_opening.blind[0].coeffs[0] = 3;
    const Commitment wrong_commitment = Commit(other_opening.value, other_opening.blind);

    BOOST_CHECK(!VerifyRangeProof(proof, wrong_commitment));
}

BOOST_AUTO_TEST_CASE(all_zero_responses_rejected)
{
    CommitmentOpening opening;
    opening.value = 100;
    opening.blind = lattice::PolyVec(lattice::MODULE_RANK);
    opening.blind[0].coeffs[0] = 2;

    const Commitment commitment = Commit(opening.value, opening.blind);

    RangeProof proof;
    BOOST_REQUIRE(CreateRangeProof(proof, opening, commitment));

    // Zero out all responses in first bit proof
    BOOST_REQUIRE(!proof.bit_proofs.empty());
    proof.bit_proofs[0].z0 = lattice::PolyVec(lattice::MODULE_RANK);
    proof.bit_proofs[0].z1 = lattice::PolyVec(lattice::MODULE_RANK);
    BOOST_CHECK(!VerifyRangeProof(proof, commitment));
}

BOOST_AUTO_TEST_SUITE_END()
