// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_experience/experience.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_experience_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(private_refusal_stores_nothing)
{
    using namespace modelnet;
    SwarmExperience plane;
    std::string err;

    BOOST_CHECK(!plane.Store("", "public_trajectory", 500000, err));
    BOOST_CHECK_EQUAL(err, "TRAJECTORY");
    BOOST_CHECK(!plane.Store("", "private_prompt", 500000, err));
    BOOST_CHECK_EQUAL(err, "TRAJECTORY");
    BOOST_REQUIRE(plane.size() == 0);
    BOOST_REQUIRE(plane.reward("") == -1);

    BOOST_CHECK(!plane.Store("secret", "private_prompt", 500000, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!plane.Store("prompt", "prompt", 1, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!plane.Store("repo", "repository", 1, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!plane.Store("cred", "credential", 1000000, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_REQUIRE(plane.size() == 0);
    BOOST_REQUIRE(plane.reward("secret") == -1);
    BOOST_REQUIRE(!plane.private_stored());
    BOOST_REQUIRE(!plane.offered("secret"));

    BOOST_CHECK(!plane.TrainFrom("secret", err));
    BOOST_CHECK_EQUAL(err, "TRAJECTORY");
    BOOST_REQUIRE(!plane.offered("secret"));

    plane.Enqueue();
    BOOST_REQUIRE(plane.queued().empty());
    plane.Enqueue();
    BOOST_REQUIRE(plane.queued().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(public_reward_is_one_at_threshold)
{
    using namespace modelnet;
    SwarmExperience plane;
    std::string err;

    BOOST_REQUIRE(plane.Store("pub", "public_trajectory", 500000, err));
    BOOST_REQUIRE(plane.reward("pub") == 1);
    BOOST_REQUIRE(plane.Store("top", "public_trajectory", 1000000, err));
    BOOST_REQUIRE(plane.reward("top") == 1);
    BOOST_REQUIRE(plane.reward("missing") == -1);
    BOOST_REQUIRE(!plane.offered("pub"));
    BOOST_REQUIRE(!plane.private_stored());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(synthetic_reward_is_zero_below_threshold)
{
    using namespace modelnet;
    SwarmExperience plane;
    std::string err;

    BOOST_REQUIRE(plane.Store("syn", "synthetic_trajectory", 499999, err));
    BOOST_REQUIRE(plane.reward("syn") == 0);
    BOOST_REQUIRE(plane.Store("zero", "synthetic_trajectory", 0, err));
    BOOST_REQUIRE(plane.reward("zero") == 0);
    BOOST_REQUIRE(plane.Store("syn-high", "synthetic_trajectory", 500000, err));
    BOOST_REQUIRE(plane.reward("syn-high") == 1);
    BOOST_REQUIRE(!plane.offered("syn"));
    BOOST_REQUIRE(plane.TrainFrom("syn", err));
    BOOST_REQUIRE(plane.offered("syn"));
    BOOST_REQUIRE(!plane.offered("zero"));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_outcome)
{
    using namespace modelnet;
    SwarmExperience plane;
    std::string err;

    BOOST_REQUIRE(plane.Store("id", "public_trajectory", 500000, err));
    BOOST_CHECK(!plane.Store("id", "public_trajectory", 0, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.reward("id") == 1);
    BOOST_REQUIRE(plane.size() == 1);

    BOOST_CHECK(!plane.Store("id", "synthetic_trajectory", 0, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.reward("id") == 1);

    BOOST_CHECK(!plane.Store("id", "public_trajectory", -1, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.reward("id") == 1);
    BOOST_REQUIRE(plane.size() == 1);

    BOOST_CHECK(!plane.Store("low", "public_trajectory", -1, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK(!plane.Store("high", "synthetic_trajectory", 1000001, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_REQUIRE(plane.reward("low") == -1);
    BOOST_REQUIRE(plane.reward("high") == -1);
    BOOST_REQUIRE(plane.size() == 1);

    BOOST_REQUIRE(plane.Store("low", "public_trajectory", 0, err));
    BOOST_REQUIRE(plane.reward("low") == 0);
    BOOST_REQUIRE(plane.size() == 2);
}

BOOST_AUTO_TEST_CASE(enqueue_follows_insertion_order)
{
    using namespace modelnet;
    SwarmExperience plane;
    std::string err;

    BOOST_REQUIRE(plane.Store("a", "public_trajectory", 500000, err));
    BOOST_CHECK(!plane.Store("nope", "private_prompt", 900000, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_REQUIRE(plane.Store("b", "synthetic_trajectory", 1, err));
    BOOST_REQUIRE(plane.Store("c", "public_trajectory", 1000000, err));

    plane.Enqueue();
    BOOST_REQUIRE_EQUAL(plane.queued().size(), 3U);
    BOOST_REQUIRE_EQUAL(plane.queued()[0], "a");
    BOOST_REQUIRE_EQUAL(plane.queued()[1], "b");
    BOOST_REQUIRE_EQUAL(plane.queued()[2], "c");

    plane.Enqueue();
    BOOST_REQUIRE_EQUAL(plane.queued().size(), 3U);
    BOOST_REQUIRE_EQUAL(plane.queued()[0], "a");
    BOOST_REQUIRE_EQUAL(plane.queued()[1], "b");
    BOOST_REQUIRE_EQUAL(plane.queued()[2], "c");

    BOOST_REQUIRE(plane.Store("d", "synthetic_trajectory", 499999, err));
    plane.Enqueue();
    BOOST_REQUIRE_EQUAL(plane.queued().size(), 4U);
    BOOST_REQUIRE_EQUAL(plane.queued()[0], "a");
    BOOST_REQUIRE_EQUAL(plane.queued()[1], "b");
    BOOST_REQUIRE_EQUAL(plane.queued()[2], "c");
    BOOST_REQUIRE_EQUAL(plane.queued()[3], "d");

    BOOST_REQUIRE(plane.reward("a") == 1);
    BOOST_REQUIRE(plane.reward("b") == 0);
    BOOST_REQUIRE(plane.reward("c") == 1);
    BOOST_REQUIRE(plane.reward("d") == 0);
    BOOST_REQUIRE(plane.reward("nope") == -1);
    BOOST_REQUIRE(!plane.private_stored());
}

BOOST_AUTO_TEST_CASE(bytes_moved_stay_zero)
{
    using namespace modelnet;
    SwarmExperience plane;
    std::string err;

    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.private_stored());
    BOOST_REQUIRE_EQUAL(IntegerDataset().size(), 8U);

    BOOST_REQUIRE(plane.Store("pub", "public_trajectory", 500000, err));
    BOOST_REQUIRE(plane.Store("syn", "synthetic_trajectory", 0, err));
    BOOST_CHECK(!plane.TrainFrom("", err));
    BOOST_CHECK_EQUAL(err, "TRAJECTORY");
    BOOST_CHECK(!plane.TrainFrom("missing", err));
    BOOST_CHECK_EQUAL(err, "TRAJECTORY");
    BOOST_REQUIRE(!plane.offered("missing"));
    BOOST_REQUIRE(!plane.offered("pub"));
    BOOST_REQUIRE(!plane.offered("syn"));

    BOOST_REQUIRE(plane.TrainFrom("pub", err));
    BOOST_REQUIRE(plane.TrainFrom("syn", err));
    BOOST_REQUIRE(plane.offered("pub"));
    BOOST_REQUIRE(plane.offered("syn"));
    BOOST_REQUIRE(plane.TrainFrom("pub", err));
    BOOST_REQUIRE(plane.offered("pub"));

    BOOST_REQUIRE(plane.reward("pub") == 1);
    BOOST_REQUIRE(plane.reward("syn") == 0);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.private_stored());
    BOOST_REQUIRE_EQUAL(IntegerDataset().size(), 8U);
}

BOOST_AUTO_TEST_SUITE_END()
