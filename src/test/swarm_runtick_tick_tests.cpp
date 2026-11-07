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

BOOST_FIXTURE_TEST_SUITE(swarm_runtick_tick_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(tick_trains_hashes_and_copies_the_state_page)
{
    modelnet::SwarmIntCycle cycle;
    std::string cycle_err;
    BOOST_REQUIRE(cycle.Run(1, cycle_err));
    const std::string state_hash = cycle.state_hash();
    const std::string expected = HexStr(Hash(state_hash));

    modelnet::SwarmRunTick runner;
    std::string err = "prior";
    BOOST_REQUIRE(runner.Tick(1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(runner.trained_steps() == 1);
    BOOST_CHECK_EQUAL(runner.digest(), expected);
    BOOST_CHECK_EQUAL(runner.page_bytes(), static_cast<std::int64_t>(state_hash.size()));
    BOOST_CHECK(!runner.launched());
    BOOST_CHECK(!runner.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
