// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/agent_guard/agent_guard.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(agent_guard_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stored_permit)
{
    modelnet::AgentGuard eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Permit("guard-a", "inprocess", err));
    BOOST_CHECK_EQUAL(err, "PROCESS");
    BOOST_CHECK(!eng.process_present());
    BOOST_CHECK(!eng.stored("guard-a"));
    BOOST_CHECK(eng.text("guard-a").empty());

    BOOST_CHECK(eng.Permit("guard-a", "permit-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("guard-a"));
    BOOST_CHECK_EQUAL(eng.text("guard-a"), "permit-a");
    BOOST_CHECK(!eng.process_present());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.process_present());
}

BOOST_AUTO_TEST_SUITE_END()
