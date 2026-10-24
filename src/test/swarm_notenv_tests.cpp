// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notenv.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notenv_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_feature_id_is_feature)
{
    std::string err = "prior";
    modelnet::SwarmNotEnv note;
    note.env_required = true;
    note.want_enable = true;
    const modelnet::SwarmNotEnvResult result = modelnet::SwarmNoteNotEnv(note, err);
    BOOST_CHECK(!result.enabled);
    BOOST_CHECK(!result.required_env);
    BOOST_CHECK_EQUAL(result.code, "FEATURE");
    BOOST_CHECK_EQUAL(err, "FEATURE");
}

BOOST_AUTO_TEST_CASE(env_required_is_no_switch)
{
    std::string err = "prior";
    modelnet::SwarmNotEnv note;
    note.feature_id = "feature-env";
    note.env_required = true;
    note.want_enable = false;
    const modelnet::SwarmNotEnvResult result = modelnet::SwarmNoteNotEnv(note, err);
    BOOST_CHECK(!result.enabled);
    BOOST_CHECK(!result.required_env);
    BOOST_CHECK_EQUAL(result.code, "NO_SWITCH");
    BOOST_CHECK_EQUAL(err, "NO_SWITCH");
}

BOOST_AUTO_TEST_CASE(want_enable_is_no_switch)
{
    std::string err = "prior";
    modelnet::SwarmNotEnv note;
    note.feature_id = "feature-env";
    note.env_required = false;
    note.want_enable = true;
    const modelnet::SwarmNotEnvResult result = modelnet::SwarmNoteNotEnv(note, err);
    BOOST_CHECK(!result.enabled);
    BOOST_CHECK(!result.required_env);
    BOOST_CHECK_EQUAL(result.code, "NO_SWITCH");
    BOOST_CHECK_EQUAL(err, "NO_SWITCH");
}

BOOST_AUTO_TEST_CASE(env_required_and_want_enable_is_no_switch)
{
    std::string err = "prior";
    modelnet::SwarmNotEnv note;
    note.feature_id = "feature-env";
    note.env_required = true;
    note.want_enable = true;
    const modelnet::SwarmNotEnvResult result = modelnet::SwarmNoteNotEnv(note, err);
    BOOST_CHECK(!result.enabled);
    BOOST_CHECK(!result.required_env);
    BOOST_CHECK_EQUAL(result.code, "NO_SWITCH");
    BOOST_CHECK_EQUAL(err, "NO_SWITCH");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotEnv note;
    note.feature_id = "feature-env";
    note.env_required = false;
    note.want_enable = false;
    const modelnet::SwarmNotEnvResult result = modelnet::SwarmNoteNotEnv(note, err);
    BOOST_CHECK(!result.enabled);
    BOOST_CHECK(!result.required_env);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
