// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault04.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault04_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_job_id)
{
    modelnet::SwarmFault04 in;
    in.checkpoint_saved = true;
    in.durable = true;
    in.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmFault04Result out = modelnet::SwarmRecoverFault04(in, err);
    BOOST_CHECK_EQUAL(out.code, "JOB");
    BOOST_CHECK(!out.published);
    BOOST_CHECK(!out.recovered);
    BOOST_CHECK(!out.distributed);
    BOOST_CHECK(!out.bytes_moved);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK_EQUAL(err, "JOB");
}

BOOST_AUTO_TEST_CASE(no_checkpoint)
{
    modelnet::SwarmFault04 in;
    in.job_id = "job-4";
    in.durable = true;
    in.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmFault04Result out = modelnet::SwarmRecoverFault04(in, err);
    BOOST_CHECK_EQUAL(out.code, "NO_CHECKPOINT");
    BOOST_CHECK(!out.published);
    BOOST_CHECK(!out.recovered);
    BOOST_CHECK(!out.distributed);
    BOOST_CHECK(!out.bytes_moved);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK_EQUAL(err, "NO_CHECKPOINT");
}

BOOST_AUTO_TEST_CASE(want_publish_held)
{
    modelnet::SwarmFault04 in;
    in.job_id = "job-4";
    in.checkpoint_saved = true;
    in.durable = true;
    in.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmFault04Result out = modelnet::SwarmRecoverFault04(in, err);
    BOOST_CHECK_EQUAL(out.code, "HELD");
    BOOST_CHECK(!out.published);
    BOOST_CHECK(!out.recovered);
    BOOST_CHECK(!out.distributed);
    BOOST_CHECK(!out.bytes_moved);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(durable_local)
{
    modelnet::SwarmFault04 in;
    in.job_id = "job-4";
    in.checkpoint_saved = true;
    in.durable = true;
    std::string err = "stale";
    const modelnet::SwarmFault04Result out = modelnet::SwarmRecoverFault04(in, err);
    BOOST_CHECK_EQUAL(out.code, "DURABLE");
    BOOST_CHECK(out.recovered);
    BOOST_CHECK(!out.published);
    BOOST_CHECK(!out.distributed);
    BOOST_CHECK(!out.bytes_moved);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmFault04 in;
    in.job_id = "job-4";
    in.checkpoint_saved = true;
    std::string err = "stale";
    const modelnet::SwarmFault04Result out = modelnet::SwarmRecoverFault04(in, err);
    BOOST_CHECK_EQUAL(out.code, "NOTED");
    BOOST_CHECK(!out.published);
    BOOST_CHECK(!out.recovered);
    BOOST_CHECK(!out.distributed);
    BOOST_CHECK(!out.bytes_moved);
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
