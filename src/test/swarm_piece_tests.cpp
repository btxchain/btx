// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piece.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_piece_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a_piece_is_accepted_only_when_its_digest_matches)
{
    const std::vector<unsigned char> bytes = {'p', 'i', 'e', 'c', 'e'};
    const std::string id = modelnet::SwarmPieceDigest(bytes);
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmAcceptPiece(id, bytes, err));
    std::vector<unsigned char> changed = bytes;
    changed[0] = 'q';
    BOOST_CHECK(!modelnet::SwarmAcceptPiece(id, changed, err));
    BOOST_CHECK_EQUAL(err, "PIECE_DIGEST");
    BOOST_CHECK(!modelnet::SwarmAcceptPiece(id, {}, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK(!modelnet::SwarmAcceptPiece("abc", bytes, err));
    BOOST_CHECK_EQUAL(err, "PIECE_ID");
}

BOOST_AUTO_TEST_SUITE_END()
