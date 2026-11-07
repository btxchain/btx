// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnockptsave2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnockptsave2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id)
{
    modelnet::SwarmNotNoCkptSave2 note;
    note.want_save = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoCkptSave2Result result = modelnet::SwarmNoteNotNoCkptSave2(note, err);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
    BOOST_CHECK(!result.saved);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(want_save)
{
    modelnet::SwarmNotNoCkptSave2 note;
    note.run_id = "run-a";
    note.want_save = true;
    std::string err;
    const modelnet::SwarmNotNoCkptSave2Result result = modelnet::SwarmNoteNotNoCkptSave2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.saved);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoCkptSave2 note;
    note.run_id = "run-a";
    std::string err = "stale";
    const modelnet::SwarmNotNoCkptSave2Result result = modelnet::SwarmNoteNotNoCkptSave2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.saved);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_SUITE_END()
