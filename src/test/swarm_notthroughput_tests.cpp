// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notthroughput.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notthroughput_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_batch_id_is_batch)
{
    modelnet::SwarmNotThroughput note;
    note.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmNotThroughputResult out = modelnet::SwarmNoteNotThroughput(note, err);
    BOOST_CHECK_EQUAL(out.code, "BATCH");
    BOOST_CHECK(!out.published);
    BOOST_CHECK_EQUAL(out.payments_per_sec, 0);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK_EQUAL(err, "BATCH");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    modelnet::SwarmNotThroughput note;
    note.batch_id = "batch-1";
    note.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmNotThroughputResult out = modelnet::SwarmNoteNotThroughput(note, err);
    BOOST_CHECK_EQUAL(out.code, "UNMEASURED");
    BOOST_CHECK(!out.published);
    BOOST_CHECK_EQUAL(out.payments_per_sec, 0);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmNotThroughput note;
    note.batch_id = "batch-1";
    note.want_publish = false;
    std::string err = "stale";
    const modelnet::SwarmNotThroughputResult out = modelnet::SwarmNoteNotThroughput(note, err);
    BOOST_CHECK_EQUAL(out.code, "NOTED");
    BOOST_CHECK(!out.published);
    BOOST_CHECK_EQUAL(out.payments_per_sec, 0);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
