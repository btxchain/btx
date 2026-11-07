// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofsdp2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofsdp2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoFsdp2 NotedNote()
{
    modelnet::SwarmNotNoFsdp2 note;
    note.run_id = "run-1";
    note.want_fsdp = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_run_id_is_run)
{
    modelnet::SwarmNotNoFsdp2 note = NotedNote();
    note.run_id.clear();
    note.want_fsdp = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFsdp2Result result = modelnet::SwarmNoteNotNoFsdp2(note, err);
    BOOST_CHECK(!result.ran);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(want_fsdp_is_not_run)
{
    modelnet::SwarmNotNoFsdp2 note = NotedNote();
    note.want_fsdp = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFsdp2Result result = modelnet::SwarmNoteNotNoFsdp2(note, err);
    BOOST_CHECK(!result.ran);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoFsdp2 note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoFsdp2Result result = modelnet::SwarmNoteNotNoFsdp2(note, err);
    BOOST_CHECK(!result.ran);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
