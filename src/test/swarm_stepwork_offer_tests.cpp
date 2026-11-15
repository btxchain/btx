// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_experience/experience.h>
#include <modelnet/swarm_experience/kind.h>
#include <modelnet/swarm_stepwork/swarm_stepwork.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_stepwork_offer_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_id_is_work)
{
    modelnet::SwarmStepWork work;
    std::string err = "prior";
    BOOST_CHECK(!work.Offer("missing", err));
    BOOST_CHECK_EQUAL(err, "WORK");
    BOOST_CHECK(!work.Offer("", err));
    BOOST_CHECK_EQUAL(err, "WORK");
    BOOST_CHECK(!work.offered("missing"));
    BOOST_CHECK(!work.gpu());
    BOOST_CHECK_EQUAL(work.size(), 0U);
    BOOST_CHECK(work.state_hash().empty());
    BOOST_CHECK(!work.private_stored());
}

BOOST_AUTO_TEST_CASE(offer_records_a_stored_id_without_a_gpu)
{
    modelnet::SwarmStepWork work;
    std::string err = "prior";
    BOOST_REQUIRE(work.Record("pub", 1, false, err));
    const std::string hash = work.state_hash();
    const int reward = work.reward_of("pub");
    BOOST_CHECK(!work.offered("pub"));

    BOOST_REQUIRE(work.Offer("pub", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(work.offered("pub"));
    BOOST_CHECK(!work.gpu());
    BOOST_CHECK(!work.private_stored());
    BOOST_CHECK_EQUAL(work.state_hash(), hash);
    BOOST_CHECK_EQUAL(work.reward_of("pub"), reward);
    BOOST_CHECK_EQUAL(work.size(), 1U);
    BOOST_CHECK_EQUAL(work.queued_count(), 1U);

    BOOST_REQUIRE(work.Offer("pub", err));
    BOOST_CHECK(work.offered("pub"));
    BOOST_CHECK(!work.gpu());
    BOOST_CHECK_EQUAL(work.size(), 1U);
    BOOST_CHECK_EQUAL(work.state_hash(), hash);

    const int64_t outcome_ppm = static_cast<int64_t>(1) * 1000;
    modelnet::SwarmExperience stored;
    std::string store_err;
    BOOST_REQUIRE(stored.Store("pub", modelnet::kExperiencePublic, outcome_ppm, store_err));
    BOOST_CHECK_EQUAL(work.reward_of("pub"), stored.reward("pub"));
}

BOOST_AUTO_TEST_SUITE_END()
