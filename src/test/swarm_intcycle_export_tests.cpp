// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_intcycle_export_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(export_grad_is_not_exported)
{
    modelnet::SwarmIntCycle cycle;
    std::string err = "prior";
    BOOST_CHECK(!cycle.ExportGrad(err));
    BOOST_CHECK_EQUAL(err, "NOT_EXPORTED");
    BOOST_CHECK(cycle.bytes_moved() == 0);
    BOOST_CHECK(cycle.atoms_moved() == 0);
    BOOST_CHECK_EQUAL(cycle.automatic_spend(), "0");
    BOOST_CHECK(cycle.steps() == 0);
    BOOST_CHECK(cycle.state_hash().empty());
    BOOST_CHECK(!cycle.gpu());
    BOOST_CHECK(!cycle.distributed());
    BOOST_CHECK(!cycle.launched());
    BOOST_CHECK(!cycle.broadcast());
}

BOOST_AUTO_TEST_CASE(export_after_a_step_moves_no_bytes)
{
    modelnet::SwarmIntCycle cycle;
    std::string err;
    BOOST_REQUIRE(cycle.Run(1, err));
    const std::string hash = cycle.state_hash();

    BOOST_CHECK(!cycle.ExportGrad(err));
    BOOST_CHECK_EQUAL(err, "NOT_EXPORTED");
    BOOST_CHECK(cycle.bytes_moved() == 0);
    BOOST_CHECK(cycle.steps() == 1);
    BOOST_CHECK_EQUAL(cycle.state_hash(), hash);
}

BOOST_AUTO_TEST_SUITE_END()
