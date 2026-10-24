// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprefetch2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoprefetch2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_transfer_id_is_transfer)
{
    modelnet::SwarmNotNoPrefetch2 note;
    note.transfer_id.clear();
    note.want_prefetch = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoPrefetch2Result result = modelnet::SwarmNoteNotNoPrefetch2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "TRANSFER");
    BOOST_CHECK_EQUAL(err, "TRANSFER");
}

BOOST_AUTO_TEST_CASE(want_prefetch_is_held)
{
    modelnet::SwarmNotNoPrefetch2 note;
    note.transfer_id = "transfer-1";
    note.want_prefetch = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPrefetch2Result result = modelnet::SwarmNoteNotNoPrefetch2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoPrefetch2 note;
    note.transfer_id = "transfer-1";
    note.want_prefetch = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoPrefetch2Result result = modelnet::SwarmNoteNotNoPrefetch2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
