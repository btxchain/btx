// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_twelve/swarm_twelve.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <hash.h>
#include <util/strencodings.h>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_twelve_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(twelve_stages_follow_the_engines)
{
    modelnet::SwarmTwelveRun run;
    std::string err = "prior";
    const std::string payload = "abc";
    const std::string prefix = payload.substr(0, 8);

    BOOST_CHECK(!run.Run("", payload, err));
    BOOST_CHECK_EQUAL(err, "WORK");
    BOOST_CHECK(!run.stage_done(modelnet::kSwarmTwelveStageForm));
    BOOST_CHECK(run.digest().empty());

    BOOST_CHECK(!run.Run("job", "", err));
    BOOST_CHECK_EQUAL(err, "PAYLOAD");
    BOOST_CHECK(!run.stage_done(modelnet::kSwarmTwelveStageForm));

    BOOST_REQUIRE(run.Run("job", payload, err));
    BOOST_CHECK(err.empty());

    const std::string expected = HexStr(Hash(payload));
    BOOST_CHECK_EQUAL(run.digest(), expected);
    BOOST_CHECK(prefix.size() <= 8);
    BOOST_CHECK_EQUAL(run.text(), prefix);
    BOOST_CHECK_EQUAL(run.tokens(), static_cast<int64_t>(prefix.size()));
    BOOST_CHECK(run.recovered());
    BOOST_CHECK(run.continued());
    BOOST_CHECK(!run.candidate_id().empty());
    BOOST_CHECK(!run.next_candidate_id().empty());
    BOOST_CHECK(run.candidate_id() != run.next_candidate_id());
    BOOST_CHECK(run.qualified(run.candidate_id()));
    BOOST_CHECK(run.promoted());
    BOOST_CHECK(run.adopted());
    BOOST_CHECK(!run.passed());
    BOOST_CHECK(!run.gpu_passed());
    BOOST_CHECK(!run.windows_passed());
    BOOST_CHECK(!run.launched());
    BOOST_CHECK(!run.gpu());
    BOOST_CHECK(!run.broadcast());
    BOOST_CHECK(!run.fault_hardware());
    BOOST_CHECK(!run.realm_promoted());
    BOOST_CHECK(!run.qualified());
    BOOST_CHECK_EQUAL(run.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(run.automatic_spend(), "0");
    BOOST_CHECK(!run.state_hash().empty());
    BOOST_CHECK(run.steps() == 1);
    BOOST_CHECK_EQUAL(run.stage_code(modelnet::kSwarmTwelveStageDescendants), "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(run.stage_code(modelnet::kSwarmTwelveStagePay), "HELD");
    BOOST_CHECK(run.stage_done(modelnet::kSwarmTwelveStageForm));
    BOOST_CHECK(run.stage_done(modelnet::kSwarmTwelveStageAgent));
    BOOST_CHECK(run.stage_done(modelnet::kSwarmTwelveStageAccelerate));
    BOOST_CHECK(run.stage_done(modelnet::kSwarmTwelveStageExperience));
    BOOST_CHECK(run.stage_done(modelnet::kSwarmTwelveStageTrain));
    BOOST_CHECK(run.stage_done(modelnet::kSwarmTwelveStageDescendants));
    BOOST_CHECK(run.stage_done(modelnet::kSwarmTwelveStageEvaluate));
    BOOST_CHECK(run.stage_done(modelnet::kSwarmTwelveStageGraduate));
    BOOST_CHECK(run.stage_done(modelnet::kSwarmTwelveStageAdopt));
    BOOST_CHECK(run.stage_done(modelnet::kSwarmTwelveStagePay));
    BOOST_CHECK(run.stage_done(modelnet::kSwarmTwelveStageFault));
    BOOST_CHECK(run.stage_done(modelnet::kSwarmTwelveStageNext));

    const std::string digest = run.digest();
    const std::string text = run.text();
    BOOST_CHECK(!run.Run("job", payload, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(run.digest(), digest);
    BOOST_CHECK_EQUAL(run.text(), text);
    BOOST_CHECK(run.recovered());
    BOOST_CHECK(run.continued());
    BOOST_CHECK(!run.passed());
    BOOST_CHECK(!run.windows_passed());
    BOOST_CHECK_EQUAL(run.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(run.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
