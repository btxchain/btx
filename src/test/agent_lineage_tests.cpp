// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/agent_lineage/agent_lineage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::AgentLineage& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(agent_lineage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_stored_line)
{
    modelnet::AgentLineage eng;
    std::string err;

    BOOST_CHECK(!eng.Line("agent-a", "inherit", err));
    BOOST_CHECK_EQUAL(err, "GRANT");
    BOOST_CHECK(!eng.stored("agent-a"));
    BOOST_CHECK_EQUAL(eng.child("agent-a"), "");

    BOOST_CHECK(eng.Line("agent-a", "agent-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("agent-a"));
    BOOST_CHECK_EQUAL(eng.child("agent-a"), "agent-b");

    BOOST_CHECK(!eng.Line("agent-a", "inherit", err));
    BOOST_CHECK_EQUAL(err, "GRANT");
    BOOST_CHECK(eng.stored("agent-a"));
    BOOST_CHECK_EQUAL(eng.child("agent-a"), "agent-b");

    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
