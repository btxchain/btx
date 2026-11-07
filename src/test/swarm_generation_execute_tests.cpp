// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/generation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_generation_execute_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(task_requires_a_name_and_a_data_grant)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";

    BOOST_CHECK(!gen.SelectTask("", true, err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_CHECK_EQUAL(gen.task_count(), 0U);

    BOOST_CHECK(!gen.SelectTask("", false, err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_CHECK_EQUAL(gen.task_count(), 0U);

    BOOST_CHECK(!gen.SelectTask("try-recipe", false, err));
    BOOST_CHECK_EQUAL(err, "DATA");
    BOOST_CHECK_EQUAL(gen.task_count(), 0U);

    BOOST_CHECK(gen.SelectTask("try-recipe", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(gen.task_count(), 1U);
}

BOOST_AUTO_TEST_CASE(execute_records_an_attempt_and_does_not_run)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";

    BOOST_CHECK(!gen.running());
    BOOST_CHECK(!gen.launched());
    BOOST_CHECK(!gen.gpu());
    BOOST_CHECK_EQUAL(gen.training_count(), 0U);

    BOOST_CHECK(!gen.Execute(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!gen.running());
    BOOST_CHECK(!gen.launched());
    BOOST_CHECK(!gen.gpu());
    BOOST_CHECK_EQUAL(gen.training_count(), 1U);
    BOOST_CHECK(gen.bytes_moved() == 0);
    BOOST_CHECK(gen.atoms_moved() == 0);

    BOOST_CHECK(!gen.Execute(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!gen.running());
    BOOST_CHECK_EQUAL(gen.training_count(), 2U);
}

BOOST_AUTO_TEST_SUITE_END()
