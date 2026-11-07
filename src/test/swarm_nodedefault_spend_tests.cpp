// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/nodedefault.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nodedefault_spend_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(spend_starts_unarmed)
{
    modelnet::SwarmNodeDefault node;
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "0");
    BOOST_REQUIRE(!node.armed());
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(research_key_is_not_signed)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(!node.ArmSpend(5, true, true, false, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "0");
    BOOST_REQUIRE(!node.armed());
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(scheduler_is_not_signed)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(!node.ArmSpend(5, true, false, true, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "0");
    BOOST_REQUIRE(!node.armed());
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(research_key_and_scheduler_are_not_signed)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(!node.ArmSpend(5, true, true, true, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "0");
    BOOST_REQUIRE(!node.armed());
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(unsigned_operator_is_not_signed)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(!node.ArmSpend(5, false, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "0");
    BOOST_REQUIRE(!node.armed());
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(unsigned_operator_with_low_bound_is_not_signed)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(!node.ArmSpend(0, false, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "0");
    BOOST_REQUIRE(!node.armed());
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(research_key_with_low_bound_is_not_signed)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(!node.ArmSpend(0, true, true, false, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "0");
    BOOST_REQUIRE(!node.armed());
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(bound_below_one)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(!node.ArmSpend(0, true, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "BOUND");
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "0");
    BOOST_REQUIRE(!node.armed());
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(negative_bound)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(!node.ArmSpend(-1, true, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "BOUND");
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "0");
    BOOST_REQUIRE(!node.armed());
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(operator_signed_arm_records_decimal)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(node.ArmSpend(10, true, false, false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(node.armed());
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "10");
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);
    BOOST_REQUIRE(node.modelnet_on());
    BOOST_REQUIRE_EQUAL(node.launch_profile(), "BTX035-LAUNCH-DECODER-2x64");
    BOOST_REQUIRE(node.dns_seeds().empty());
    BOOST_REQUIRE(!node.training());
    BOOST_REQUIRE(!node.private_prompts());
    BOOST_REQUIRE_EQUAL(node.cpu_threads(), 64);
    BOOST_REQUIRE_EQUAL(node.vram_mib(), 0);
    BOOST_REQUIRE(node.seeder());
    BOOST_REQUIRE(node.evaluator());
    BOOST_REQUIRE_EQUAL(node.slots(), 1);

    err = "prior";
    BOOST_REQUIRE(!node.ArmSpend(11, true, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(node.armed());
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "10");
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(minimum_bound_arms)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(node.ArmSpend(1, true, false, false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(node.armed());
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "1");
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(second_arm_is_replay_ahead_of_other_refusals)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(node.ArmSpend(4, true, false, false, err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!node.ArmSpend(4, true, true, false, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");

    err = "prior";
    BOOST_REQUIRE(!node.ArmSpend(4, true, false, true, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");

    err = "prior";
    BOOST_REQUIRE(!node.ArmSpend(4, false, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");

    err = "prior";
    BOOST_REQUIRE(!node.ArmSpend(0, true, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");

    BOOST_REQUIRE(node.armed());
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "4");
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(refused_arm_does_not_block_a_later_arm)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(!node.ArmSpend(5, false, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE(!node.armed());
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "0");

    err = "prior";
    BOOST_REQUIRE(!node.ArmSpend(0, true, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "BOUND");
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "0");
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(node.ArmSpend(5, true, false, false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(node.armed());
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "5");
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
