// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault15.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_fault15_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_batch_id)
{
    std::string err = "prior";
    modelnet::SwarmFault15 in;
    in.batch_id = "";
    in.channel_count = 2;
    in.want_measure = true;
    in.want_broadcast = true;
    const modelnet::SwarmFault15Result out = modelnet::SwarmRecoverFault15(in, err);
    BOOST_CHECK_EQUAL(out.code, "BATCH");
    BOOST_CHECK(!out.measured);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK(!out.committed);
    BOOST_CHECK_EQUAL(out.assumed_bytes, 0);
    BOOST_CHECK_EQUAL(err, "BATCH");
}

BOOST_AUTO_TEST_CASE(channel_count_one)
{
    std::string err = "prior";
    modelnet::SwarmFault15 in;
    in.batch_id = "batch-15";
    in.channel_count = 1;
    in.want_measure = true;
    in.want_broadcast = true;
    const modelnet::SwarmFault15Result out = modelnet::SwarmRecoverFault15(in, err);
    BOOST_CHECK_EQUAL(out.code, "BATCH");
    BOOST_CHECK(!out.measured);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK(!out.committed);
    BOOST_CHECK_EQUAL(out.assumed_bytes, 0);
    BOOST_CHECK_EQUAL(err, "BATCH");
}

BOOST_AUTO_TEST_CASE(measure_refused_even_if_broadcast)
{
    std::string err = "prior";
    modelnet::SwarmFault15 in;
    in.batch_id = "batch-15";
    in.channel_count = 2;
    in.want_measure = true;
    in.want_broadcast = true;
    const modelnet::SwarmFault15Result out = modelnet::SwarmRecoverFault15(in, err);
    BOOST_CHECK_EQUAL(out.code, "MEASURE_REFUSED");
    BOOST_CHECK(!out.measured);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK(!out.committed);
    BOOST_CHECK_EQUAL(out.assumed_bytes, 0);
    BOOST_CHECK_EQUAL(err, "MEASURE_REFUSED");
}

BOOST_AUTO_TEST_CASE(broadcast_held)
{
    std::string err = "prior";
    modelnet::SwarmFault15 in;
    in.batch_id = "batch-15";
    in.channel_count = 3;
    in.want_measure = false;
    in.want_broadcast = true;
    const modelnet::SwarmFault15Result out = modelnet::SwarmRecoverFault15(in, err);
    BOOST_CHECK_EQUAL(out.code, "HELD");
    BOOST_CHECK(!out.measured);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK(!out.committed);
    BOOST_CHECK_EQUAL(out.assumed_bytes, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(noted)
{
    std::string err = "prior";
    modelnet::SwarmFault15 in;
    in.batch_id = "batch-15";
    in.channel_count = 2;
    in.want_measure = false;
    in.want_broadcast = false;
    const modelnet::SwarmFault15Result out = modelnet::SwarmRecoverFault15(in, err);
    BOOST_CHECK_EQUAL(out.code, "NOTED");
    BOOST_CHECK(!out.measured);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK(!out.committed);
    BOOST_CHECK_EQUAL(out.assumed_bytes, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
