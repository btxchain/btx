// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piece4m.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_piece4m_tests, BasicTestingSetup)

static modelnet::SwarmPieceSplit NotedSplit()
{
    modelnet::SwarmPieceSplit split;
    split.manifest_id = "manifest-split";
    split.piece_bytes = 64;
    split.want_store = false;
    return split;
}

static void ExpectFlagsStayFalse(const modelnet::SwarmPieceSplitResult& result)
{
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(empty_manifest_id_is_piece)
{
    modelnet::SwarmPieceSplit split = NotedSplit();
    split.manifest_id.clear();
    std::string err = "prior";
    const modelnet::SwarmPieceSplitResult result = modelnet::SwarmNotePieceSplit(split, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK_EQUAL(err, "PIECE");
}

BOOST_AUTO_TEST_CASE(negative_piece_bytes_is_piece)
{
    modelnet::SwarmPieceSplit split = NotedSplit();
    split.piece_bytes = -1;
    std::string err = "prior";
    const modelnet::SwarmPieceSplitResult result = modelnet::SwarmNotePieceSplit(split, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK_EQUAL(err, "PIECE");
}

BOOST_AUTO_TEST_CASE(empty_manifest_id_wins_over_split_cap_and_want_store)
{
    modelnet::SwarmPieceSplit split = NotedSplit();
    split.manifest_id.clear();
    split.piece_bytes = 4194305;
    split.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmPieceSplitResult result = modelnet::SwarmNotePieceSplit(split, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK_EQUAL(err, "PIECE");
}

BOOST_AUTO_TEST_CASE(negative_piece_bytes_wins_over_want_store)
{
    modelnet::SwarmPieceSplit split = NotedSplit();
    split.piece_bytes = -1;
    split.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmPieceSplitResult result = modelnet::SwarmNotePieceSplit(split, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK_EQUAL(err, "PIECE");
}

BOOST_AUTO_TEST_CASE(one_byte_over_the_cap_is_split_cap)
{
    modelnet::SwarmPieceSplit split = NotedSplit();
    split.piece_bytes = 4194305;
    split.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmPieceSplitResult result = modelnet::SwarmNotePieceSplit(split, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "SPLIT_CAP");
    BOOST_CHECK_EQUAL(err, "SPLIT_CAP");
}

BOOST_AUTO_TEST_CASE(split_cap_wins_when_want_store_is_true)
{
    modelnet::SwarmPieceSplit split = NotedSplit();
    split.piece_bytes = 4194305;
    split.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmPieceSplitResult result = modelnet::SwarmNotePieceSplit(split, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "SPLIT_CAP");
    BOOST_CHECK_EQUAL(err, "SPLIT_CAP");
}

BOOST_AUTO_TEST_CASE(want_store_is_held)
{
    modelnet::SwarmPieceSplit split = NotedSplit();
    split.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmPieceSplitResult result = modelnet::SwarmNotePieceSplit(split, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(exact_cap_with_want_store_is_held)
{
    modelnet::SwarmPieceSplit split = NotedSplit();
    split.piece_bytes = 4194304;
    split.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmPieceSplitResult result = modelnet::SwarmNotePieceSplit(split, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(small_split_is_noted)
{
    modelnet::SwarmPieceSplit split = NotedSplit();
    std::string err = "prior";
    const modelnet::SwarmPieceSplitResult result = modelnet::SwarmNotePieceSplit(split, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(exact_cap_without_want_store_is_noted)
{
    modelnet::SwarmPieceSplit split = NotedSplit();
    split.piece_bytes = 4194304;
    split.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmPieceSplitResult result = modelnet::SwarmNotePieceSplit(split, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
