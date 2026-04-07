// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/merkle_tree.h>

#include <hash.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using namespace shielded;

BOOST_FIXTURE_TEST_SUITE(shielded_merkle_serialization_tests, BasicTestingSetup)

namespace {

uint256 TestCommitment(uint64_t position)
{
    HashWriter hw;
    hw << std::string{"BTX_Shielded_Serialization_Test_V1"};
    hw << position;
    return hw.GetSHA256();
}

} // namespace

BOOST_AUTO_TEST_CASE(tree_unserialize_rejects_size_overflow)
{
    DataStream ss{};
    ::Serialize(ss, MERKLE_MAX_LEAVES + 1);
    ::Serialize(ss, uint8_t{0}); // left_ absent
    ::Serialize(ss, uint8_t{0}); // right_ absent
    uint64_t parent_count{0};
    ::Serialize(ss, COMPACTSIZE(parent_count));

    ShieldedMerkleTree decoded;
    BOOST_CHECK_EXCEPTION(ss >> decoded,
                          std::ios_base::failure,
                          HasReason("ShieldedMerkleTree: size overflow"));
}

BOOST_AUTO_TEST_CASE(witness_unserialize_rejects_invalid_cursor_flag)
{
    ShieldedMerkleTree tree;
    DataStream ss{};
    ss << tree;
    uint64_t filled_count{0};
    ::Serialize(ss, COMPACTSIZE(filled_count));
    ::Serialize(ss, uint8_t{2}); // invalid has_cursor marker

    ShieldedMerkleWitness decoded;
    BOOST_CHECK_EXCEPTION(ss >> decoded,
                          std::ios_base::failure,
                          HasReason("ShieldedMerkleWitness: invalid cursor flag"));
}

BOOST_AUTO_TEST_CASE(witness_unserialize_rejects_cursor_depth_overflow)
{
    ShieldedMerkleTree tree;
    DataStream ss{};
    ss << tree;
    uint64_t filled_count{0};
    ::Serialize(ss, COMPACTSIZE(filled_count));
    ::Serialize(ss, uint8_t{1}); // has cursor
    ss << tree;                  // cursor tree
    uint64_t cursor_depth = MERKLE_DEPTH + 1;
    ::Serialize(ss, COMPACTSIZE(cursor_depth));

    ShieldedMerkleWitness decoded;
    BOOST_CHECK_EXCEPTION(ss >> decoded,
                          std::ios_base::failure,
                          HasReason("ShieldedMerkleWitness: cursor depth overflow"));
}

BOOST_AUTO_TEST_CASE(tree_unserialize_rebinds_commitment_index_after_store_reopen)
{
    struct CommitmentStoreResetGuard {
        ~CommitmentStoreResetGuard()
        {
            ShieldedMerkleTree::ResetCommitmentIndexStore();
        }
    } guard;

    const fs::path db_path = m_path_root / "shielded_merkle_serialization_reopen";
    ShieldedMerkleTree::ResetCommitmentIndexStore();
    BOOST_REQUIRE(ShieldedMerkleTree::ConfigureCommitmentIndexStore(db_path,
                                                                     /*db_cache_bytes=*/1 << 20,
                                                                     /*lru_capacity=*/1024,
                                                                     /*memory_only=*/false,
                                                                     /*wipe_data=*/true));

    DataStream ss{};
    std::vector<uint256> commitments;
    {
        ShieldedMerkleTree tree;
        for (uint64_t i = 0; i < 16; ++i) {
            commitments.push_back(TestCommitment(i));
            tree.Append(commitments.back());
        }
        ss << tree;
    }

    ShieldedMerkleTree::ResetCommitmentIndexStore();
    BOOST_REQUIRE(ShieldedMerkleTree::ConfigureCommitmentIndexStore(db_path,
                                                                     /*db_cache_bytes=*/1 << 20,
                                                                     /*lru_capacity=*/1024,
                                                                     /*memory_only=*/false,
                                                                     /*wipe_data=*/false));

    ShieldedMerkleTree reopened_tree;
    ss >> reopened_tree;
    BOOST_CHECK(reopened_tree.HasCommitmentIndex());
    for (size_t i = 0; i < commitments.size(); ++i) {
        const auto restored = reopened_tree.CommitmentAt(i);
        BOOST_REQUIRE(restored.has_value());
        BOOST_CHECK_EQUAL(*restored, commitments[i]);
    }

    ShieldedMerkleTree snapshot = reopened_tree;
    BOOST_CHECK(snapshot.HasCommitmentIndex());
    for (size_t i = 0; i < commitments.size(); ++i) {
        const auto restored = snapshot.CommitmentAt(i);
        BOOST_REQUIRE(restored.has_value());
        BOOST_CHECK_EQUAL(*restored, commitments[i]);
    }
}

BOOST_AUTO_TEST_SUITE_END()
