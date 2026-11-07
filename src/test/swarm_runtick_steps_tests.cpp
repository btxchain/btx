// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <modelnet/swarm_runtick/swarm_runtick.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <hash.h>
#include <util/strencodings.h>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_runtick_steps_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(steps_below_one_do_not_call_the_trainer)
{
    modelnet::SwarmIntCycle cycle;
    std::string cycle_err;
    BOOST_REQUIRE(cycle.Run(1, cycle_err));
    const std::string independent = HexStr(Hash(cycle.state_hash()));

    modelnet::SwarmRunTick runner;
    std::string err = "prior";
    BOOST_CHECK(!runner.Tick(0, err));
    BOOST_CHECK_EQUAL(err, "STEPS");
    BOOST_CHECK(runner.trained_steps() == 0);
    BOOST_CHECK(runner.digest().empty());
    BOOST_CHECK(runner.digest() != independent);
    BOOST_CHECK(runner.page_bytes() == 0);
    BOOST_CHECK(!runner.launched());
    BOOST_CHECK(!runner.gpu());
}

BOOST_AUTO_TEST_CASE(a_zero_step_after_a_tick_leaves_the_stored_count)
{
    modelnet::SwarmRunTick runner;
    std::string err;
    BOOST_REQUIRE(runner.Tick(1, err));
    const std::string digest = runner.digest();
    const std::int64_t pages = runner.page_bytes();
    BOOST_REQUIRE(runner.trained_steps() == 1);
    BOOST_REQUIRE(!digest.empty());

    BOOST_CHECK(!runner.Tick(0, err));
    BOOST_CHECK_EQUAL(err, "STEPS");
    BOOST_CHECK(runner.trained_steps() == 1);
    BOOST_CHECK_EQUAL(runner.digest(), digest);
    BOOST_CHECK(runner.page_bytes() == pages);
    BOOST_CHECK(!runner.launched());
    BOOST_CHECK(!runner.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
