// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/pqm.h>

#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>
#include <vector>

namespace {

std::vector<unsigned char> MakePattern(size_t size, unsigned char seed)
{
    std::vector<unsigned char> out(size);
    for (size_t i = 0; i < out.size(); ++i) out[i] = static_cast<unsigned char>(seed + i);
    return out;
}

std::vector<unsigned char> ToBytes(const uint256& hash)
{
    return std::vector<unsigned char>(hash.begin(), hash.end());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_merkle_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(compute_single_leaf_hash)
{
    const auto mldsa_pubkey = MakePattern(MLDSA44_PUBKEY_SIZE, 0x11);
    const auto script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, mldsa_pubkey);

    const uint256 h1 = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, script);
    const uint256 h2 = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, script);

    BOOST_CHECK(h1 == h2);
    BOOST_CHECK(h1 != uint256::ZERO);
}

BOOST_AUTO_TEST_CASE(compute_two_leaf_merkle_root)
{
    const auto ml_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, MakePattern(MLDSA44_PUBKEY_SIZE, 0x21));
    const auto slh_script = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x42));

    const uint256 leaf_a = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, ml_script);
    const uint256 leaf_b = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, slh_script);
    const uint256 root = ComputeP2MRMerkleRoot({leaf_a, leaf_b});
    const uint256 branch = ComputeP2MRBranchHash(leaf_a, leaf_b);

    BOOST_CHECK(root == branch);
}

BOOST_AUTO_TEST_CASE(single_leaf_merkle_root_equals_leaf_hash)
{
    const auto script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, MakePattern(MLDSA44_PUBKEY_SIZE, 0x31));
    const uint256 leaf = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, script);
    const uint256 root = ComputeP2MRMerkleRoot({leaf});
    BOOST_CHECK(root == leaf);
}

BOOST_AUTO_TEST_CASE(default_wallet_tree_produces_deterministic_root)
{
    const auto ml_script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, MakePattern(MLDSA44_PUBKEY_SIZE, 0x00));
    const auto slh_script = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x80));

    const uint256 root1 = ComputeP2MRMerkleRoot({
        ComputeP2MRLeafHash(P2MR_LEAF_VERSION, ml_script),
        ComputeP2MRLeafHash(P2MR_LEAF_VERSION, slh_script),
    });
    const uint256 root2 = ComputeP2MRMerkleRoot({
        ComputeP2MRLeafHash(P2MR_LEAF_VERSION, ml_script),
        ComputeP2MRLeafHash(P2MR_LEAF_VERSION, slh_script),
    });

    BOOST_CHECK(root1 == root2);
    BOOST_CHECK(root1 != uint256::ZERO);
}

BOOST_AUTO_TEST_CASE(control_block_single_leaf_is_one_byte)
{
    const auto script = BuildP2MRScript(PQAlgorithm::ML_DSA_44, MakePattern(MLDSA44_PUBKEY_SIZE, 0x33));
    const uint256 leaf = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, script);
    const uint256 root = ComputeP2MRMerkleRoot({leaf});

    const std::vector<unsigned char> control{P2MR_LEAF_VERSION};
    BOOST_CHECK_EQUAL(control.size(), 1U);
    BOOST_CHECK(VerifyP2MRCommitment(control, ToBytes(root), leaf));
}

BOOST_AUTO_TEST_CASE(control_block_two_leaves_is_33_bytes)
{
    const auto script_a = BuildP2MRScript(PQAlgorithm::ML_DSA_44, MakePattern(MLDSA44_PUBKEY_SIZE, 0x44));
    const auto script_b = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x55));

    const uint256 leaf_a = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, script_a);
    const uint256 leaf_b = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, script_b);
    const uint256 root = ComputeP2MRMerkleRoot({leaf_a, leaf_b});

    std::vector<unsigned char> control{P2MR_LEAF_VERSION};
    control.insert(control.end(), leaf_b.begin(), leaf_b.end());
    BOOST_CHECK_EQUAL(control.size(), 33U);
    BOOST_CHECK(VerifyP2MRCommitment(control, ToBytes(root), leaf_a));
}

BOOST_AUTO_TEST_CASE(verify_merkle_proof_valid)
{
    const auto script_a = BuildP2MRScript(PQAlgorithm::ML_DSA_44, MakePattern(MLDSA44_PUBKEY_SIZE, 0x66));
    const auto script_b = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x77));

    const uint256 leaf_a = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, script_a);
    const uint256 leaf_b = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, script_b);
    const uint256 root = ComputeP2MRMerkleRoot({leaf_a, leaf_b});

    std::vector<unsigned char> control{P2MR_LEAF_VERSION};
    control.insert(control.end(), leaf_b.begin(), leaf_b.end());
    BOOST_CHECK(VerifyP2MRCommitment(control, ToBytes(root), leaf_a));
}

BOOST_AUTO_TEST_CASE(verify_merkle_proof_invalid_sibling)
{
    const auto script_a = BuildP2MRScript(PQAlgorithm::ML_DSA_44, MakePattern(MLDSA44_PUBKEY_SIZE, 0x88));
    const auto script_b = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x99));

    const uint256 leaf_a = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, script_a);
    const uint256 leaf_b = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, script_b);
    const uint256 root = ComputeP2MRMerkleRoot({leaf_a, leaf_b});

    std::vector<unsigned char> control{P2MR_LEAF_VERSION};
    control.insert(control.end(), leaf_b.begin(), leaf_b.end());
    control.back() ^= 0x01;

    BOOST_CHECK(!VerifyP2MRCommitment(control, ToBytes(root), leaf_a));
}

BOOST_AUTO_TEST_SUITE_END()
