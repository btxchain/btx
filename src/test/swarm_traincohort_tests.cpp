// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cycle.h>
#include <modelnet/swarm_traincohort/cohort.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_traincohort_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(two_members_each_take_one_matching_step)
{
    using namespace modelnet;
    SwarmTrainCohort cohort;
    std::string err;

    BOOST_CHECK(!cohort.AddMember("", err));
    BOOST_CHECK_EQUAL(err, "MEMBER");
    BOOST_REQUIRE(cohort.MemberCount() == 0);
    BOOST_REQUIRE(!cohort.gpu());
    BOOST_REQUIRE(cohort.bytes_moved() == 0);

    BOOST_REQUIRE(cohort.AddMember("a", err));
    BOOST_REQUIRE(cohort.AddMember("b", err));
    BOOST_REQUIRE(cohort.HasMember("a"));
    BOOST_REQUIRE(cohort.HasMember("b"));
    BOOST_REQUIRE(cohort.MemberStep("a") == 0);
    BOOST_REQUIRE(cohort.MemberStep("b") == 0);
    BOOST_REQUIRE(cohort.MemberHash("a").empty());
    BOOST_REQUIRE(cohort.MemberHash("b").empty());
    BOOST_REQUIRE(cohort.MemberCount() == 2);

    BOOST_CHECK(!cohort.AddMember("a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(cohort.MemberCount() == 2);
    BOOST_REQUIRE(cohort.MemberStep("a") == 0);

    BOOST_CHECK(!cohort.LocalStep("missing", err));
    BOOST_CHECK_EQUAL(err, "MEMBER");

    std::string start_err;
    BOOST_CHECK(!SwarmStartTraining(false, false, start_err));
    BOOST_CHECK_EQUAL(start_err, "DATASET");
    BOOST_CHECK(!cohort.Grant("integer-eight", false, false, err));
    BOOST_CHECK_EQUAL(err, start_err);
    BOOST_CHECK(!cohort.DatasetRecorded("integer-eight"));
    BOOST_CHECK(!SwarmStartTraining(true, true, start_err));
    BOOST_CHECK(!cohort.Grant("integer-eight", true, true, err));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_CHECK(!cohort.DatasetRecorded("integer-eight"));
    BOOST_CHECK(!cohort.LocalStep("a", err));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_REQUIRE(cohort.MemberStep("a") == 0);
    BOOST_REQUIRE(cohort.MemberHash("a").empty());

    BOOST_REQUIRE(cohort.Grant("integer-eight", true, false, err));
    BOOST_REQUIRE(cohort.DatasetRecorded("integer-eight"));
    BOOST_REQUIRE(!cohort.DatasetWithdrawn("integer-eight"));
    BOOST_REQUIRE(cohort.LiveGrant());
    BOOST_CHECK(!cohort.Grant("integer-eight", true, false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(cohort.LiveGrant());

    BOOST_REQUIRE_EQUAL(IntegerDataset().size(), 8U);
    BOOST_REQUIRE(cohort.LocalStep("a", err));
    BOOST_REQUIRE(cohort.LocalStep("b", err));
    BOOST_REQUIRE(cohort.MemberStep("a") == 1);
    BOOST_REQUIRE(cohort.MemberStep("b") == 1);
    BOOST_REQUIRE(!cohort.MemberHash("a").empty());
    BOOST_REQUIRE_EQUAL(cohort.MemberHash("a"), cohort.MemberHash("b"));

    IntegerTrainer reference;
    BOOST_REQUIRE(reference.Step(err));
    BOOST_REQUIRE(reference.ReplayMatches(reference.State(), err));
    BOOST_REQUIRE_EQUAL(cohort.MemberHash("a"), reference.State().state_hash);
    BOOST_REQUIRE_EQUAL(cohort.MemberHash("b"), reference.State().state_hash);
    BOOST_REQUIRE_EQUAL(IntegerDataset().size(), 8U);

    const std::string hash_a = cohort.MemberHash("a");
    const std::string hash_b = cohort.MemberHash("b");
    BOOST_CHECK(!cohort.LocalStep("a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!cohort.LocalStep("b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(cohort.MemberStep("a") == 1);
    BOOST_REQUIRE(cohort.MemberStep("b") == 1);
    BOOST_REQUIRE_EQUAL(cohort.MemberHash("a"), hash_a);
    BOOST_REQUIRE_EQUAL(cohort.MemberHash("b"), hash_b);
    BOOST_REQUIRE(!cohort.gpu());
    BOOST_REQUIRE(cohort.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(stale_remote_does_not_replace_the_local_hash)
{
    using namespace modelnet;
    SwarmTrainCohort cohort;
    std::string err;
    BOOST_REQUIRE(cohort.AddMember("a", err));
    BOOST_REQUIRE(cohort.AddMember("b", err));
    BOOST_REQUIRE(cohort.Grant("integer-eight", true, false, err));
    BOOST_REQUIRE(cohort.LocalStep("a", err));
    BOOST_REQUIRE(cohort.LocalStep("b", err));

    const std::string local = cohort.MemberHash("a");
    const std::string other = cohort.MemberHash("b");
    BOOST_REQUIRE(!local.empty());
    BOOST_REQUIRE_EQUAL(local, other);

    BOOST_CHECK(!cohort.OfferRemote("missing", 2, "no-member", err));
    BOOST_CHECK_EQUAL(err, "MEMBER");

    BOOST_CHECK(!cohort.OfferRemote("a", 0, "older", err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK(!cohort.OfferRemote("a", 1, "same-step", err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_REQUIRE_EQUAL(cohort.MemberHash("a"), local);
    BOOST_REQUIRE(!cohort.HasPending("a"));
    BOOST_REQUIRE(cohort.PendingHash("a").empty());

    BOOST_CHECK(!cohort.OfferRemote("a", 3, "skipped", err));
    BOOST_CHECK_EQUAL(err, "GAP");
    BOOST_REQUIRE_EQUAL(cohort.MemberHash("a"), local);
    BOOST_REQUIRE(!cohort.HasPending("a"));

    BOOST_REQUIRE(cohort.OfferRemote("a", 2, "remote-1", err));
    BOOST_REQUIRE(cohort.HasPending("a"));
    BOOST_REQUIRE_EQUAL(cohort.PendingHash("a"), "remote-1");
    BOOST_REQUIRE_EQUAL(cohort.MemberHash("a"), local);
    BOOST_REQUIRE_EQUAL(cohort.MemberHash("b"), other);

    BOOST_CHECK(!cohort.OfferRemote("a", 4, "further", err));
    BOOST_CHECK_EQUAL(err, "GAP");
    BOOST_REQUIRE_EQUAL(cohort.PendingHash("a"), "remote-1");
    BOOST_REQUIRE_EQUAL(cohort.MemberHash("a"), local);
    BOOST_REQUIRE(!cohort.gpu());
    BOOST_REQUIRE(cohort.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(average_is_refused)
{
    using namespace modelnet;
    SwarmTrainCohort cohort;
    std::string err;
    BOOST_REQUIRE(cohort.AddMember("a", err));
    BOOST_REQUIRE(cohort.AddMember("b", err));
    BOOST_REQUIRE(cohort.Grant("integer-eight", true, false, err));
    BOOST_REQUIRE(cohort.LocalStep("a", err));
    BOOST_REQUIRE(cohort.LocalStep("b", err));
    BOOST_REQUIRE(cohort.OfferRemote("a", 2, "remote-1", err));

    const std::string hash_a = cohort.MemberHash("a");
    const std::string hash_b = cohort.MemberHash("b");
    BOOST_CHECK(!cohort.Average(err));
    BOOST_CHECK_EQUAL(err, "NOT_AVERAGED");
    BOOST_REQUIRE(cohort.MemberStep("a") == 1);
    BOOST_REQUIRE(cohort.MemberStep("b") == 1);
    BOOST_REQUIRE_EQUAL(cohort.MemberHash("a"), hash_a);
    BOOST_REQUIRE_EQUAL(cohort.MemberHash("b"), hash_b);
    BOOST_REQUIRE_EQUAL(cohort.PendingHash("a"), "remote-1");
    BOOST_REQUIRE(!cohort.gpu());
    BOOST_REQUIRE(cohort.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(withdrawn_grant_does_not_step)
{
    using namespace modelnet;
    SwarmTrainCohort cohort;
    std::string err;
    BOOST_REQUIRE(cohort.AddMember("a", err));
    BOOST_REQUIRE(cohort.AddMember("c", err));
    BOOST_REQUIRE(cohort.Grant("integer-eight", true, false, err));
    BOOST_REQUIRE(cohort.LocalStep("a", err));
    const std::string hash_a = cohort.MemberHash("a");
    BOOST_REQUIRE(cohort.MemberStep("a") == 1);

    BOOST_CHECK(!cohort.Withdraw("missing-set", err));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_REQUIRE(!cohort.DatasetRecorded("missing-set"));

    BOOST_REQUIRE(cohort.Withdraw("integer-eight", err));
    BOOST_REQUIRE(cohort.DatasetWithdrawn("integer-eight"));
    BOOST_REQUIRE(!cohort.LiveGrant());

    BOOST_CHECK(!cohort.LocalStep("c", err));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_REQUIRE(cohort.MemberStep("c") == 0);
    BOOST_REQUIRE(cohort.MemberHash("c").empty());

    BOOST_CHECK(!cohort.LocalStep("a", err));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_REQUIRE(cohort.MemberStep("a") == 1);
    BOOST_REQUIRE_EQUAL(cohort.MemberHash("a"), hash_a);

    BOOST_CHECK(!cohort.Grant("integer-eight", true, false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(cohort.DatasetWithdrawn("integer-eight"));
    BOOST_CHECK(!cohort.LocalStep("c", err));
    BOOST_CHECK_EQUAL(err, "DATASET");
    BOOST_REQUIRE(cohort.MemberStep("c") == 0);
    BOOST_REQUIRE(!cohort.gpu());
    BOOST_REQUIRE(cohort.bytes_moved() == 0);
    BOOST_REQUIRE_EQUAL(IntegerDataset().size(), 8U);
}

BOOST_AUTO_TEST_SUITE_END()
