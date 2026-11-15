// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_safetyblock.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_safetyblock_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_safety)
{
    std::string err = "prior";
    modelnet::SwarmSafetyBlock note;
    note.safety_fail = true;
    note.broad_regression = true;
    note.want_graduate = true;
    const modelnet::SwarmSafetyBlockResult result = modelnet::SwarmNoteSafetyBlock(note, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "SAFETY");
    BOOST_CHECK_EQUAL(err, "SAFETY");
}

BOOST_AUTO_TEST_CASE(safety_fail_blocks_even_when_want_graduate)
{
    std::string err = "prior";
    modelnet::SwarmSafetyBlock note;
    note.candidate_id = "cand-a";
    note.safety_fail = true;
    note.broad_regression = false;
    note.want_graduate = true;
    const modelnet::SwarmSafetyBlockResult result = modelnet::SwarmNoteSafetyBlock(note, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "BLOCK");
    BOOST_CHECK_EQUAL(err, "BLOCK");
}

BOOST_AUTO_TEST_CASE(broad_regression_blocks_even_when_want_graduate)
{
    std::string err = "prior";
    modelnet::SwarmSafetyBlock note;
    note.candidate_id = "cand-a";
    note.safety_fail = false;
    note.broad_regression = true;
    note.want_graduate = true;
    const modelnet::SwarmSafetyBlockResult result = modelnet::SwarmNoteSafetyBlock(note, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "BLOCK");
    BOOST_CHECK_EQUAL(err, "BLOCK");
}

BOOST_AUTO_TEST_CASE(want_graduate_is_held_and_does_not_graduate)
{
    std::string err = "prior";
    modelnet::SwarmSafetyBlock note;
    note.candidate_id = "cand-a";
    note.safety_fail = false;
    note.broad_regression = false;
    note.want_graduate = true;
    const modelnet::SwarmSafetyBlockResult result = modelnet::SwarmNoteSafetyBlock(note, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmSafetyBlock note;
    note.candidate_id = "cand-a";
    note.safety_fail = false;
    note.broad_regression = false;
    note.want_graduate = false;
    const modelnet::SwarmSafetyBlockResult result = modelnet::SwarmNoteSafetyBlock(note, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
