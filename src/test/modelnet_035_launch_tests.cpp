// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/training_launch.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_launch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(launch_corpus_and_tokenizer_are_frozen)
{
    using namespace modelnet;
    std::string err;
    std::string dataset;
    std::string tokenizer;
    BOOST_CHECK(LaunchDatasetDigest(dataset, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(dataset.size(), 96U);
    BOOST_CHECK(LaunchTokenizerDigest(tokenizer, err));
    BOOST_CHECK_NE(tokenizer, dataset);
}

BOOST_AUTO_TEST_CASE(launch_two_runs_match_and_weights_move)
{
    using namespace modelnet;
    std::string err;
    LaunchTrainer first;
    LaunchTrainer second;
    BOOST_REQUIRE(first.Run(2, err));
    BOOST_REQUIRE(second.Run(2, err));
    BOOST_CHECK_EQUAL(first.Checkpoint().state_hash, second.Checkpoint().state_hash);
    BOOST_CHECK_EQUAL(first.Checkpoint().cursor, 2U);
    LaunchTrainer zero;
    BOOST_REQUIRE(zero.Run(0, err));
    BOOST_CHECK_NE(first.Checkpoint().weight_hash, zero.Checkpoint().weight_hash);
    BOOST_CHECK(LaunchTrainer::CheckState(first.Checkpoint(), err));
}

BOOST_AUTO_TEST_CASE(launch_rejects_cursor_optimizer_and_checkpoint)
{
    using namespace modelnet;
    std::string err;
    LaunchTrainer trainer;
    BOOST_REQUIRE(trainer.Run(2, err));
    LaunchCheckpoint bad = trainer.Checkpoint();
    bad.cursor += 1;
    BOOST_CHECK(!LaunchTrainer::CheckState(bad, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RNG");

    bad = trainer.Checkpoint();
    bad.optimizer = "SGD_WITH_MOMENTUM";
    BOOST_CHECK(!LaunchTrainer::CheckState(bad, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ID_MISMATCH");

    bad = trainer.Checkpoint();
    bad.weight_hash[0] = bad.weight_hash[0] == '0' ? '1' : '0';
    BOOST_CHECK(!LaunchTrainer::CheckState(bad, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ID_MISMATCH");

    bad = trainer.Checkpoint();
    bad.state_hash.clear();
    BOOST_CHECK(!LaunchTrainer::CheckState(bad, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ID_MISMATCH");
}

BOOST_AUTO_TEST_CASE(launch_profile_replays_and_a_continuation_names_its_parent)
{
    using namespace modelnet;
    std::string err;
    LaunchTrainer trainer;
    BOOST_REQUIRE(trainer.Run(LAUNCH_STEPS, err));
    const LaunchCheckpoint parent = trainer.Checkpoint();
    BOOST_CHECK_EQUAL(parent.step, LAUNCH_STEPS);
    BOOST_CHECK(trainer.ReplayMatches(parent, err));
    BOOST_REQUIRE_EQUAL(trainer.Intervals().size(), 1U);
    BOOST_CHECK_EQUAL(trainer.Intervals()[0].end_exclusive, LAUNCH_STEPS);
    BOOST_CHECK(!trainer.Intervals()[0].publisher_only);

    LaunchTrainer next;
    BOOST_REQUIRE(next.Resume(parent, err));
    BOOST_REQUIRE(next.Run(LAUNCH_CONTINUE_STEPS, err));
    const LaunchCheckpoint child = next.Checkpoint();
    BOOST_CHECK_EQUAL(child.inherited_state, parent.state_hash);
    BOOST_CHECK_EQUAL(child.inherited_step, parent.step);
    BOOST_CHECK_NE(child.state_hash, parent.state_hash);
    BOOST_CHECK(LaunchTrainer::CheckState(child, err));

    std::string bytes;
    BOOST_CHECK(EncodeLaunchArtifact(child, next.Weights(), bytes, err));
    BOOST_CHECK(bytes.find(LAUNCH_PROFILE) == 0 || bytes.find(std::string("v1|") + LAUNCH_PROFILE) == 0);
}

BOOST_AUTO_TEST_CASE(launch_line_numbers_outside_their_type_are_schema)
{
    using namespace modelnet;
    std::string err;
    LaunchTrainer trainer;
    BOOST_REQUIRE(trainer.Run(2, err));
    std::string line;
    BOOST_REQUIRE(EncodeLaunchLine(std::string(96, 'a'), trainer.Checkpoint(), line, err));
    // Replace one '|' field: 3 step, 4 cursor, 10 inherited_step, 11 hits, 12 miss_mass.
    const auto with = [&line](size_t field, const std::string& value) {
        std::vector<std::string> parts{std::string()};
        for (char c : line) {
            if (c == '|') {
                parts.emplace_back();
            } else {
                parts.back().push_back(c);
            }
        }
        BOOST_REQUIRE_EQUAL(parts.size(), 13U);
        parts[field] = value;
        std::string out = parts[0];
        for (size_t i = 1; i < parts.size(); ++i) out += "|" + parts[i];
        return out;
    };
    std::string id;
    LaunchCheckpoint got;
    BOOST_CHECK(DecodeLaunchLine(line, id, got, err));

    // The ends of each type still decode.
    BOOST_CHECK(DecodeLaunchLine(with(4, "18446744073709551615"), id, got, err));
    BOOST_CHECK_EQUAL(got.cursor, UINT64_MAX);
    BOOST_CHECK(DecodeLaunchLine(with(11, "9223372036854775807"), id, got, err));
    BOOST_CHECK_EQUAL(got.hits, INT64_MAX);
    BOOST_CHECK(DecodeLaunchLine(with(12, "-9223372036854775808"), id, got, err));
    BOOST_CHECK_EQUAL(got.miss_mass, INT64_MIN);

    // One past each type is BTX035_SCHEMA, not a wrapped value.
    for (const size_t field : {size_t{3}, size_t{4}, size_t{10}}) {
        BOOST_CHECK(!DecodeLaunchLine(with(field, "18446744073709551616"), id, got, err));
        BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    }
    BOOST_CHECK(!DecodeLaunchLine(with(11, "9223372036854775808"), id, got, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
    BOOST_CHECK(!DecodeLaunchLine(with(12, "-9223372036854775809"), id, got, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCHEMA");
}

BOOST_AUTO_TEST_SUITE_END()
