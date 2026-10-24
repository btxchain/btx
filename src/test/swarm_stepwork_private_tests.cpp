// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <modelnet/swarm_stepwork/swarm_stepwork.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_stepwork_private_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(private_record_stores_nothing)
{
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);

    modelnet::SwarmStepWork work;
    std::string err = "prior";
    BOOST_CHECK(!work.Record("secret", 1, true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!work.Record("prompt", 500, true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!work.Record("cred", 0, true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!work.Record("wide", 1001, true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");

    BOOST_CHECK(work.state_hash().empty());
    BOOST_CHECK_EQUAL(work.size(), 0U);
    BOOST_CHECK_EQUAL(work.queued_count(), 0U);
    BOOST_CHECK_EQUAL(work.reward_of("secret"), -1);
    BOOST_CHECK_EQUAL(work.reward_of("prompt"), -1);
    BOOST_CHECK(!work.offered("secret"));
    BOOST_CHECK(!work.private_stored());
    BOOST_CHECK(!work.gpu());

    modelnet::SwarmIntCycle cycle;
    std::string cycle_err;
    BOOST_REQUIRE(cycle.Run(1, cycle_err));
    BOOST_CHECK(work.state_hash() != cycle.state_hash());
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);
}

BOOST_AUTO_TEST_SUITE_END()
