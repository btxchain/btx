// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopiece4mib2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopiece4mib2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_piece_id)
{
    modelnet::SwarmNotNoPiece4Mib2 note;
    std::string err = "stale";
    const modelnet::SwarmNotNoPiece4Mib2Result result = modelnet::SwarmNoteNotNoPiece4Mib2(note, err);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK(!result.split);
    BOOST_CHECK_EQUAL(err, "PIECE");
}

BOOST_AUTO_TEST_CASE(size_bytes_1)
{
    modelnet::SwarmNotNoPiece4Mib2 note;
    note.piece_id = "piece-1";
    note.size_bytes = 1;
    note.want_split = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoPiece4Mib2Result result = modelnet::SwarmNoteNotNoPiece4Mib2(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.split);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_split_size_4194304)
{
    modelnet::SwarmNotNoPiece4Mib2 note;
    note.piece_id = "piece-1";
    note.size_bytes = 4194304;
    note.want_split = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoPiece4Mib2Result result = modelnet::SwarmNoteNotNoPiece4Mib2(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.split);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(plain_note_size_4194304)
{
    modelnet::SwarmNotNoPiece4Mib2 note;
    note.piece_id = "piece-1";
    note.size_bytes = 4194304;
    note.want_split = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoPiece4Mib2Result result = modelnet::SwarmNoteNotNoPiece4Mib2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.split);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
