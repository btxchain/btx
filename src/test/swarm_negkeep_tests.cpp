// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_negkeep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_negkeep_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_result_id_is_result)
{
    modelnet::SwarmNegKeep result;
    result.result_id = "";
    result.negative = false;
    result.want_hide = false;
    result.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNegKeepResult out = modelnet::SwarmKeepNegative(result, err);
    BOOST_CHECK_EQUAL(out.hidden, false);
    BOOST_CHECK_EQUAL(out.training, false);
    BOOST_CHECK_EQUAL(out.kept, false);
    BOOST_CHECK_EQUAL(out.code, "RESULT");
    BOOST_CHECK_EQUAL(err, "RESULT");
}

BOOST_AUTO_TEST_CASE(negative_true_want_hide_false_is_kept)
{
    modelnet::SwarmNegKeep result;
    result.result_id = "neg-1";
    result.negative = true;
    result.want_hide = false;
    result.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNegKeepResult out = modelnet::SwarmKeepNegative(result, err);
    BOOST_CHECK_EQUAL(out.hidden, false);
    BOOST_CHECK_EQUAL(out.training, false);
    BOOST_CHECK_EQUAL(out.kept, true);
    BOOST_CHECK_EQUAL(out.code, "KEPT");
    BOOST_CHECK_EQUAL(err, "KEPT");
}

BOOST_AUTO_TEST_CASE(want_hide_true_negative_false_is_held)
{
    modelnet::SwarmNegKeep result;
    result.result_id = "neg-1";
    result.negative = false;
    result.want_hide = true;
    result.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNegKeepResult out = modelnet::SwarmKeepNegative(result, err);
    BOOST_CHECK_EQUAL(out.hidden, false);
    BOOST_CHECK_EQUAL(out.training, false);
    BOOST_CHECK_EQUAL(out.kept, true);
    BOOST_CHECK_EQUAL(out.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_is_noted)
{
    modelnet::SwarmNegKeep result;
    result.result_id = "neg-1";
    result.negative = false;
    result.want_hide = false;
    result.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNegKeepResult out = modelnet::SwarmKeepNegative(result, err);
    BOOST_CHECK_EQUAL(out.hidden, false);
    BOOST_CHECK_EQUAL(out.training, false);
    BOOST_CHECK_EQUAL(out.kept, true);
    BOOST_CHECK_EQUAL(out.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
