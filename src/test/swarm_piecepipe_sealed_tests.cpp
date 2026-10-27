// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecepipe/digest.h>
#include <modelnet/swarm_piecepipe/limits.h>
#include <modelnet/swarm_piecepipe/swarm_piecepipe.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

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

BOOST_FIXTURE_TEST_SUITE(swarm_piecepipe_sealed_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(private_data_stores_nothing)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    std::string err = "stale";
    BOOST_CHECK(!pipe.AcceptSealed(id, body, false, true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!pipe.AcceptSealed(id, {}, false, true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!pipe.AcceptSealed("other", body, false, true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(0));
    BOOST_CHECK(!pipe.HasPiece(id));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(private_wins_when_ciphertext_is_also_set)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    std::string err;
    BOOST_CHECK(!pipe.AcceptSealed(id, body, true, true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(0));
    BOOST_CHECK(!pipe.decrypted());
    BOOST_CHECK_EQUAL(pipe.bytes_moved(), static_cast<std::int64_t>(0));
}

BOOST_AUTO_TEST_CASE(ciphertext_is_realm_sealed_and_does_not_decrypt)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    std::string err = "stale";
    BOOST_CHECK(!pipe.AcceptSealed(id, body, true, false, err));
    BOOST_CHECK_EQUAL(err, "REALM_SEALED");
    BOOST_CHECK(!pipe.AcceptSealed(id, {}, true, false, err));
    BOOST_CHECK_EQUAL(err, "REALM_SEALED");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(0));
    BOOST_CHECK(!pipe.HasPiece(id));
    BOOST_CHECK(!pipe.decrypted());
    BOOST_CHECK_EQUAL(pipe.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!pipe.broadcast());
    BOOST_CHECK(!pipe.launched());
    BOOST_CHECK(!pipe.gpu());
}

BOOST_AUTO_TEST_CASE(public_plaintext_follows_accept)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::vector<unsigned char> other = {'o', 't', 'h', 'e', 'r'};
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    std::string err = "stale";
    BOOST_CHECK(!pipe.AcceptSealed(id, {}, false, false, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK(!pipe.AcceptSealed(id, other, false, false, err));
    BOOST_CHECK_EQUAL(err, "PIECE_DIGEST");
    BOOST_CHECK(pipe.AcceptSealed(id, body, false, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK(!pipe.AcceptSealed(id, body, false, false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!pipe.AcceptSealed(id, other, false, false, err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK(!pipe.AcceptSealed(id, body, false, false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(0));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(realm_sealed_does_not_block_a_later_public_accept)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    std::string err;
    BOOST_CHECK(!pipe.AcceptSealed(id, body, true, false, err));
    BOOST_CHECK_EQUAL(err, "REALM_SEALED");
    BOOST_CHECK(pipe.AcceptSealed(id, body, false, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(pipe.HasPiece(id));
    BOOST_CHECK(!pipe.decrypted());
    BOOST_CHECK_EQUAL(pipe.bytes_moved(), static_cast<std::int64_t>(0));
}

BOOST_AUTO_TEST_CASE(public_over_the_body_limit_is_piece_limit)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> over(modelnet::kSwarmPiecePipeBodyLimit + 1, 0x55);
    std::string err;
    BOOST_CHECK(!pipe.AcceptSealed("id", over, false, false, err));
    BOOST_CHECK_EQUAL(err, "PIECE_LIMIT");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(0));
    BOOST_CHECK(!pipe.AcceptSealed("id", over, true, false, err));
    BOOST_CHECK_EQUAL(err, "REALM_SEALED");
    BOOST_CHECK(!pipe.AcceptSealed("id", over, false, true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(0));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_SUITE_END()
