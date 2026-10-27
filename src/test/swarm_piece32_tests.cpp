// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piece32.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_piece32_tests, BasicTestingSetup)

static modelnet::SwarmPieceBody NotedBody()
{
    modelnet::SwarmPieceBody body;
    body.piece_id = "piece-body";
    body.bytes = 64;
    body.want_store = false;
    return body;
}

static void ExpectFlagsStayFalse(const modelnet::SwarmPieceBodyResult& result)
{
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(empty_piece_id_is_piece)
{
    modelnet::SwarmPieceBody body = NotedBody();
    body.piece_id.clear();
    std::string err = "prior";
    const modelnet::SwarmPieceBodyResult result = modelnet::SwarmNotePieceBody(body, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK_EQUAL(err, "PIECE");
}

BOOST_AUTO_TEST_CASE(negative_bytes_is_piece)
{
    modelnet::SwarmPieceBody body = NotedBody();
    body.bytes = -1;
    std::string err = "prior";
    const modelnet::SwarmPieceBodyResult result = modelnet::SwarmNotePieceBody(body, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK_EQUAL(err, "PIECE");
}

BOOST_AUTO_TEST_CASE(empty_piece_id_wins_over_oversize_and_want_store)
{
    modelnet::SwarmPieceBody body = NotedBody();
    body.piece_id.clear();
    body.bytes = 33554433;
    body.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmPieceBodyResult result = modelnet::SwarmNotePieceBody(body, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK_EQUAL(err, "PIECE");
}

BOOST_AUTO_TEST_CASE(negative_bytes_wins_over_want_store)
{
    modelnet::SwarmPieceBody body = NotedBody();
    body.bytes = -1;
    body.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmPieceBodyResult result = modelnet::SwarmNotePieceBody(body, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK_EQUAL(err, "PIECE");
}

BOOST_AUTO_TEST_CASE(one_byte_over_the_cap_is_oversize)
{
    modelnet::SwarmPieceBody body = NotedBody();
    body.bytes = 33554433;
    body.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmPieceBodyResult result = modelnet::SwarmNotePieceBody(body, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "OVERSIZE");
    BOOST_CHECK_EQUAL(err, "OVERSIZE");
}

BOOST_AUTO_TEST_CASE(oversize_wins_when_want_store_is_true)
{
    modelnet::SwarmPieceBody body = NotedBody();
    body.bytes = 33554433;
    body.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmPieceBodyResult result = modelnet::SwarmNotePieceBody(body, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "OVERSIZE");
    BOOST_CHECK_EQUAL(err, "OVERSIZE");
}

BOOST_AUTO_TEST_CASE(want_store_is_held)
{
    modelnet::SwarmPieceBody body = NotedBody();
    body.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmPieceBodyResult result = modelnet::SwarmNotePieceBody(body, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(exact_cap_with_want_store_is_held)
{
    modelnet::SwarmPieceBody body = NotedBody();
    body.bytes = 33554432;
    body.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmPieceBodyResult result = modelnet::SwarmNotePieceBody(body, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(small_body_is_noted)
{
    modelnet::SwarmPieceBody body = NotedBody();
    std::string err = "prior";
    const modelnet::SwarmPieceBodyResult result = modelnet::SwarmNotePieceBody(body, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(exact_cap_without_want_store_is_noted)
{
    modelnet::SwarmPieceBody body = NotedBody();
    body.bytes = 33554432;
    body.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmPieceBodyResult result = modelnet::SwarmNotePieceBody(body, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
