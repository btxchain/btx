// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecepipe/digest.h>
#include <modelnet/swarm_piecepipe/swarm_piecepipe.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace {

void ExpectQuiet(const modelnet::SwarmPiecePipe& pipe)
{
    BOOST_CHECK_EQUAL(pipe.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!pipe.decrypted());
    BOOST_CHECK(!pipe.broadcast());
    BOOST_CHECK(!pipe.launched());
    BOOST_CHECK(!pipe.gpu());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_piecepipe_accept_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sha384_hex_matches_the_empty_and_abc_vectors)
{
    const std::string empty = modelnet::SwarmPiecePipeDigest(nullptr, 0);
    const std::vector<unsigned char> none;
    BOOST_CHECK_EQUAL(empty, modelnet::SwarmPiecePipeDigest(none));
    BOOST_CHECK_EQUAL(empty, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    BOOST_CHECK_EQUAL(empty.size(), static_cast<std::size_t>(96));

    const std::vector<unsigned char> abc = {'a', 'b', 'c'};
    const std::string id = modelnet::SwarmPiecePipeDigest(abc);
    BOOST_CHECK_EQUAL(id, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    BOOST_CHECK(id.find_first_of("ABCDEF") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(empty_body_is_piece_and_stores_nothing)
{
    modelnet::SwarmPiecePipe pipe;
    std::string err = "stale";
    BOOST_CHECK(!pipe.Accept("any", {}, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(0));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(0));
    BOOST_CHECK(!pipe.HasPiece("any"));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(digest_mismatch_is_piece_digest_and_stores_nothing)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    std::string err = "stale";
    BOOST_CHECK(!pipe.Accept(id + "aa", body, err));
    BOOST_CHECK_EQUAL(err, "PIECE_DIGEST");
    BOOST_CHECK(!pipe.Accept("", body, err));
    BOOST_CHECK_EQUAL(err, "PIECE_DIGEST");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(0));
    BOOST_CHECK(!pipe.HasPiece(id));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(uppercase_hex_does_not_match_the_lowercase_id)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'a', 'b', 'c'};
    std::string upper = modelnet::SwarmPiecePipeDigest(body);
    for (char& ch : upper) {
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }
    std::string err;
    BOOST_CHECK(!pipe.Accept(upper, body, err));
    BOOST_CHECK_EQUAL(err, "PIECE_DIGEST");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(0));
}

BOOST_AUTO_TEST_CASE(matching_digest_stores_the_body)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    BOOST_CHECK_EQUAL(id, "ebc73c02e0b2bfec33a8131e2363f896aade3230f85a2ffc6063078ed1e9d19277d93fe4619f5cfb83bb1e7ff034010c");
    std::string err = "stale";
    BOOST_CHECK(pipe.Accept(id, body, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(pipe.HasPiece(id));
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(0));
    BOOST_CHECK(!pipe.usable(id));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(second_accept_of_the_same_body_is_replay_and_keeps_the_first)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    std::string err;
    BOOST_REQUIRE(pipe.Accept(id, body, err));
    BOOST_CHECK(!pipe.Accept(id, body, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK(pipe.HasPiece(id));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(second_accept_of_a_different_body_is_conflict_and_keeps_the_first)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> first = {'p', 'i', 'e', 'c', 'e'};
    const std::vector<unsigned char> other = {'o', 't', 'h', 'e', 'r'};
    const std::string id = modelnet::SwarmPiecePipeDigest(first);
    std::string err;
    BOOST_REQUIRE(pipe.Accept(id, first, err));
    BOOST_CHECK(!pipe.Accept(id, other, err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK(!pipe.Accept(id, first, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(empty_followup_stays_piece_and_the_first_body_remains)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    std::string err;
    BOOST_REQUIRE(pipe.Accept(id, body, err));
    BOOST_CHECK(!pipe.Accept(id, {}, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK(!pipe.Accept(id, body, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
}

BOOST_AUTO_TEST_SUITE_END()
