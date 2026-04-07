// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/ringct/balance_proof.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using namespace shielded::ringct;
namespace lattice = shielded::lattice;

BOOST_FIXTURE_TEST_SUITE(ringct_balance_proof_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(create_verify_balance_proof)
{
    std::vector<CommitmentOpening> inputs;
    std::vector<CommitmentOpening> outputs;

    CommitmentOpening in1;
    in1.value = 600;
    in1.blind = lattice::PolyVec(lattice::MODULE_RANK);
    in1.blind[0].coeffs[0] = 10;

    CommitmentOpening in2;
    in2.value = 500;
    in2.blind = lattice::PolyVec(lattice::MODULE_RANK);
    in2.blind[0].coeffs[0] = 20;

    CommitmentOpening out1;
    out1.value = 700;
    out1.blind = lattice::PolyVec(lattice::MODULE_RANK);
    out1.blind[0].coeffs[0] = 12;

    CommitmentOpening out2;
    out2.value = 300;
    out2.blind = lattice::PolyVec(lattice::MODULE_RANK);
    out2.blind[0].coeffs[0] = 8;

    inputs = {in1, in2};
    outputs = {out1, out2};

    BalanceProof proof;
    BOOST_REQUIRE(CreateBalanceProof(proof, inputs, outputs, /*fee=*/100));

    const std::vector<Commitment> input_commitments{
        Commit(in1.value, in1.blind),
        Commit(in2.value, in2.blind),
    };

    const std::vector<Commitment> output_commitments{
        Commit(out1.value, out1.blind),
        Commit(out2.value, out2.blind),
    };

    BOOST_CHECK(VerifyBalanceProof(proof, input_commitments, output_commitments, /*fee=*/100));
}

BOOST_AUTO_TEST_CASE(imbalance_rejected)
{
    CommitmentOpening in;
    in.value = 1000;
    in.blind = lattice::PolyVec(lattice::MODULE_RANK);

    CommitmentOpening out;
    out.value = 900;
    out.blind = lattice::PolyVec(lattice::MODULE_RANK);

    BalanceProof proof;
    BOOST_CHECK(!CreateBalanceProof(proof, {in}, {out}, /*fee=*/50));
}

BOOST_AUTO_TEST_CASE(tamper_detected)
{
    CommitmentOpening in;
    in.value = 1000;
    in.blind = lattice::PolyVec(lattice::MODULE_RANK);

    CommitmentOpening out;
    out.value = 950;
    out.blind = lattice::PolyVec(lattice::MODULE_RANK);

    BalanceProof proof;
    BOOST_REQUIRE(CreateBalanceProof(proof, {in}, {out}, /*fee=*/50));

    std::vector<Commitment> in_commitments{Commit(in.value, in.blind)};
    std::vector<Commitment> out_commitments{Commit(out.value, out.blind)};

    out_commitments[0].vec[0].coeffs[0] += 1;
    BOOST_CHECK(!VerifyBalanceProof(proof, in_commitments, out_commitments, /*fee=*/50));
}

BOOST_AUTO_TEST_CASE(tx_binding_hash_mismatch_rejected)
{
    CommitmentOpening in;
    in.value = 1200;
    in.blind = lattice::PolyVec(lattice::MODULE_RANK);
    in.blind[0].coeffs[0] = 5;

    CommitmentOpening out;
    out.value = 1100;
    out.blind = lattice::PolyVec(lattice::MODULE_RANK);
    out.blind[0].coeffs[0] = 7;

    const uint256 tx_binding_hash = GetRandHash();

    BalanceProof proof;
    BOOST_REQUIRE(CreateBalanceProof(proof, {in}, {out}, /*fee=*/100, tx_binding_hash));

    std::vector<Commitment> in_commitments{Commit(in.value, in.blind)};
    std::vector<Commitment> out_commitments{Commit(out.value, out.blind)};

    BOOST_CHECK(VerifyBalanceProof(proof, in_commitments, out_commitments, /*fee=*/100, tx_binding_hash));
    BOOST_CHECK(!VerifyBalanceProof(proof, in_commitments, out_commitments, /*fee=*/100, GetRandHash()));
}

BOOST_AUTO_TEST_CASE(serialized_size_is_compact)
{
    CommitmentOpening in;
    in.value = 1000;
    in.blind = lattice::PolyVec(lattice::MODULE_RANK);
    in.blind[0].coeffs[0] = 3;

    CommitmentOpening out;
    out.value = 900;
    out.blind = lattice::PolyVec(lattice::MODULE_RANK);
    out.blind[0].coeffs[0] = 11;

    BalanceProof proof;
    BOOST_REQUIRE(CreateBalanceProof(proof, {in}, {out}, /*fee=*/100, GetRandHash()));
    BOOST_CHECK_LT(proof.GetSerializedSize(), static_cast<size_t>(7 * 1024));
}

BOOST_AUTO_TEST_CASE(zero_fee_balance_proof_roundtrip)
{
    CommitmentOpening in;
    in.value = 500;
    in.blind = lattice::PolyVec(lattice::MODULE_RANK);
    in.blind[0].coeffs[0] = 15;

    CommitmentOpening out;
    out.value = 500;
    out.blind = lattice::PolyVec(lattice::MODULE_RANK);
    out.blind[0].coeffs[0] = 22;

    BalanceProof proof;
    BOOST_REQUIRE(CreateBalanceProof(proof, {in}, {out}, /*fee=*/0));

    std::vector<Commitment> in_commitments{Commit(in.value, in.blind)};
    std::vector<Commitment> out_commitments{Commit(out.value, out.blind)};

    BOOST_CHECK(VerifyBalanceProof(proof, in_commitments, out_commitments, /*fee=*/0));
    // Wrong fee should fail
    BOOST_CHECK(!VerifyBalanceProof(proof, in_commitments, out_commitments, /*fee=*/1));
}

BOOST_AUTO_TEST_CASE(wrong_fee_fails_verification)
{
    CommitmentOpening in;
    in.value = 1000;
    in.blind = lattice::PolyVec(lattice::MODULE_RANK);
    in.blind[0].coeffs[0] = 5;

    CommitmentOpening out;
    out.value = 900;
    out.blind = lattice::PolyVec(lattice::MODULE_RANK);
    out.blind[0].coeffs[0] = 8;

    BalanceProof proof;
    BOOST_REQUIRE(CreateBalanceProof(proof, {in}, {out}, /*fee=*/100));

    std::vector<Commitment> in_commitments{Commit(in.value, in.blind)};
    std::vector<Commitment> out_commitments{Commit(out.value, out.blind)};

    BOOST_CHECK(VerifyBalanceProof(proof, in_commitments, out_commitments, /*fee=*/100));
    BOOST_CHECK(!VerifyBalanceProof(proof, in_commitments, out_commitments, /*fee=*/99));
    BOOST_CHECK(!VerifyBalanceProof(proof, in_commitments, out_commitments, /*fee=*/101));
}

BOOST_AUTO_TEST_CASE(three_input_three_output_balance_proof)
{
    CommitmentOpening in1, in2, in3;
    in1.value = 300; in1.blind = lattice::PolyVec(lattice::MODULE_RANK); in1.blind[0].coeffs[0] = 1;
    in2.value = 400; in2.blind = lattice::PolyVec(lattice::MODULE_RANK); in2.blind[0].coeffs[0] = 2;
    in3.value = 500; in3.blind = lattice::PolyVec(lattice::MODULE_RANK); in3.blind[0].coeffs[0] = 3;

    CommitmentOpening out1, out2, out3;
    out1.value = 350; out1.blind = lattice::PolyVec(lattice::MODULE_RANK); out1.blind[0].coeffs[0] = 4;
    out2.value = 450; out2.blind = lattice::PolyVec(lattice::MODULE_RANK); out2.blind[0].coeffs[0] = 5;
    out3.value = 350; out3.blind = lattice::PolyVec(lattice::MODULE_RANK); out3.blind[0].coeffs[0] = 6;

    BalanceProof proof;
    BOOST_REQUIRE(CreateBalanceProof(proof, {in1, in2, in3}, {out1, out2, out3}, /*fee=*/50));

    std::vector<Commitment> in_commitments{
        Commit(in1.value, in1.blind),
        Commit(in2.value, in2.blind),
        Commit(in3.value, in3.blind),
    };
    std::vector<Commitment> out_commitments{
        Commit(out1.value, out1.blind),
        Commit(out2.value, out2.blind),
        Commit(out3.value, out3.blind),
    };

    BOOST_CHECK(VerifyBalanceProof(proof, in_commitments, out_commitments, /*fee=*/50));
}

BOOST_AUTO_TEST_CASE(swapped_input_output_order_fails)
{
    CommitmentOpening in1, in2;
    in1.value = 600; in1.blind = lattice::PolyVec(lattice::MODULE_RANK); in1.blind[0].coeffs[0] = 10;
    in2.value = 500; in2.blind = lattice::PolyVec(lattice::MODULE_RANK); in2.blind[0].coeffs[0] = 20;

    CommitmentOpening out1;
    out1.value = 1050; out1.blind = lattice::PolyVec(lattice::MODULE_RANK); out1.blind[0].coeffs[0] = 14;

    BalanceProof proof;
    BOOST_REQUIRE(CreateBalanceProof(proof, {in1, in2}, {out1}, /*fee=*/50));

    std::vector<Commitment> in_commitments{
        Commit(in1.value, in1.blind),
        Commit(in2.value, in2.blind),
    };
    std::vector<Commitment> out_commitments{
        Commit(out1.value, out1.blind),
    };

    BOOST_CHECK(VerifyBalanceProof(proof, in_commitments, out_commitments, /*fee=*/50));

    // Swap input order — should fail since transcript binds to order
    std::vector<Commitment> swapped_in_commitments{
        Commit(in2.value, in2.blind),
        Commit(in1.value, in1.blind),
    };
    BOOST_CHECK(!VerifyBalanceProof(proof, swapped_in_commitments, out_commitments, /*fee=*/50));
}

BOOST_AUTO_TEST_SUITE_END()
