// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notuseful.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notuseful_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_task_id)
{
    modelnet::SwarmNotUseful note;
    note.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmNotUsefulResult out = modelnet::SwarmNoteNotUseful(note, err);
    BOOST_CHECK_EQUAL(out.code, "TASK");
    BOOST_CHECK(!out.published);
    BOOST_CHECK_EQUAL(out.gpu_hours, 0);
    BOOST_CHECK(!out.useful);
    BOOST_CHECK_EQUAL(err, "TASK");
}

BOOST_AUTO_TEST_CASE(want_publish_unmeasured)
{
    modelnet::SwarmNotUseful note;
    note.task_id = "task-useful";
    note.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmNotUsefulResult out = modelnet::SwarmNoteNotUseful(note, err);
    BOOST_CHECK_EQUAL(out.code, "UNMEASURED");
    BOOST_CHECK(!out.published);
    BOOST_CHECK_EQUAL(out.gpu_hours, 0);
    BOOST_CHECK(!out.useful);
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotUseful note;
    note.task_id = "task-useful";
    std::string err = "stale";
    const modelnet::SwarmNotUsefulResult out = modelnet::SwarmNoteNotUseful(note, err);
    BOOST_CHECK_EQUAL(out.code, "NOTED");
    BOOST_CHECK(!out.published);
    BOOST_CHECK_EQUAL(out.gpu_hours, 0);
    BOOST_CHECK(!out.useful);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
