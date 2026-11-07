// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sealopen.h>
#include <test/util/setup_common.h>

#include <string>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_sealopen_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_piece_id)
{
    modelnet::SwarmSealOpen piece;
    piece.piece_id.clear();
    piece.sealed = false;
    piece.want_open = false;
    std::string err = "stale";
    const modelnet::SwarmSealOpenResult result = modelnet::SwarmNoteSealOpen(piece, err);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK_EQUAL(result.opened, false);
}

BOOST_AUTO_TEST_CASE(sealed_want_open_false)
{
    modelnet::SwarmSealOpen piece;
    piece.piece_id = "piece-1";
    piece.sealed = true;
    piece.want_open = false;
    std::string err = "stale";
    const modelnet::SwarmSealOpenResult result = modelnet::SwarmNoteSealOpen(piece, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_OPENED");
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
    BOOST_CHECK_EQUAL(result.opened, false);
}

BOOST_AUTO_TEST_CASE(want_open_unsealed)
{
    modelnet::SwarmSealOpen piece;
    piece.piece_id = "piece-1";
    piece.sealed = false;
    piece.want_open = true;
    std::string err = "stale";
    const modelnet::SwarmSealOpenResult result = modelnet::SwarmNoteSealOpen(piece, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(result.opened, false);
}

BOOST_AUTO_TEST_CASE(neither_noted)
{
    modelnet::SwarmSealOpen piece;
    piece.piece_id = "piece-1";
    piece.sealed = false;
    piece.want_open = false;
    std::string err = "stale";
    const modelnet::SwarmSealOpenResult result = modelnet::SwarmNoteSealOpen(piece, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(result.opened, false);
}

BOOST_AUTO_TEST_SUITE_END()
