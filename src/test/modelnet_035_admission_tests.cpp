// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/model_admission.h>
#include <modelnet/training_evidence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_admission_tests, BasicTestingSetup)

namespace {

const std::string kRng = "rng-frozen";
const std::string kOptimizer = "opt-frozen";
const std::string kCursor = "cursor-frozen";

modelnet::Interval Edge(uint64_t start, uint64_t end, std::string start_state, std::string end_state)
{
    modelnet::Interval interval;
    interval.start_inclusive = start;
    interval.end_exclusive = end;
    interval.start_state = std::move(start_state);
    interval.end_state = std::move(end_state);
    interval.profile = "EXACT_CHECKS";
    interval.rng = kRng;
    interval.optimizer = kOptimizer;
    interval.data_cursor = kCursor;
    interval.ancestry = "ancestry-base";
    interval.publisher_only = false;
    return interval;
}

} // namespace

BOOST_AUTO_TEST_CASE(replay_gap_is_not_full_coverage)
{
    const auto first = Edge(0, 5, "S0", "S5");
    auto joined = Edge(5, 10, "S5", "SF");
    BOOST_CHECK(modelnet::FullReplayCoverage(10, "S0", "SF", {first, joined}));

    auto gapped = joined;
    gapped.start_inclusive = 6;
    BOOST_CHECK(!modelnet::FullReplayCoverage(10, "S0", "SF", {first, gapped}));

    auto mismatched = joined;
    mismatched.start_state = "OTHER";
    BOOST_CHECK(!modelnet::FullReplayCoverage(10, "S0", "SF", {first, mismatched}));

    auto overlap = Edge(3, 10, "S3", "SF");
    BOOST_CHECK(!modelnet::FullReplayCoverage(10, "S0", "SF", {first, overlap}));

    auto past_total = Edge(0, 11, "S0", "SF");
    BOOST_CHECK(!modelnet::FullReplayCoverage(10, "S0", "SF", {past_total}));

    gapped.ancestry = "root-b";
    auto with_roots = first;
    with_roots.ancestry = "root-a";
    const modelnet::AdmissionResult denied = modelnet::Admit(
        modelnet::Assurance::PUBLIC_STRICT, true, {with_roots, gapped}, 10, "S0", "SF",
        {"root-a", "root-b"}, false);
    BOOST_CHECK(!denied.admitted);
    BOOST_CHECK(!denied.ServeAllowed());
    BOOST_CHECK_EQUAL(denied.code, "BTX035_GAP");
}

BOOST_AUTO_TEST_CASE(modified_rng_rejected)
{
    auto interval = Edge(0, 4, "S0", "S4");
    std::string err;
    BOOST_CHECK(modelnet::AcceptInterval(interval, kRng, kOptimizer, kCursor, err));
    BOOST_CHECK(err.empty());

    interval.profile = "SAMPLE";
    BOOST_CHECK(!modelnet::AcceptInterval(interval, kRng, kOptimizer, kCursor, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");

    interval.profile = "EXACT_CHECKS";
    interval.rng = "rng-modified";
    BOOST_CHECK(!modelnet::AcceptInterval(interval, kRng, kOptimizer, kCursor, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RNG");

    interval.rng = kRng;
    interval.optimizer = "opt-modified";
    BOOST_CHECK(!modelnet::AcceptInterval(interval, kRng, kOptimizer, kCursor, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RNG");

    interval.optimizer = kOptimizer;
    interval.data_cursor = "cursor-modified";
    BOOST_CHECK(!modelnet::AcceptInterval(interval, kRng, kOptimizer, kCursor, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RNG");
}

BOOST_AUTO_TEST_CASE(missing_ancestry_rejected)
{
    auto interval = Edge(0, 4, "S0", "S4");
    interval.ancestry.clear();
    std::string err;
    BOOST_CHECK(!modelnet::AcceptInterval(interval, kRng, kOptimizer, kCursor, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ANCESTRY");
}

BOOST_AUTO_TEST_CASE(publisher_only_is_not_an_independent_root)
{
    auto independent = Edge(0, 10, "S0", "SF");
    independent.ancestry = "root-independent";
    auto publisher = independent;
    publisher.ancestry = "root-publisher";
    publisher.publisher_only = true;

    BOOST_CHECK(modelnet::Independent(independent));
    BOOST_CHECK(!modelnet::Independent(publisher));
    BOOST_CHECK(modelnet::FullReplayCoverage(10, "S0", "SF", {independent, publisher}));

    const modelnet::AdmissionResult denied = modelnet::Admit(
        modelnet::Assurance::PUBLIC_STRICT, true, {independent, publisher}, 10, "S0", "SF",
        {"root-independent", "root-publisher"}, false);
    BOOST_CHECK(!denied.admitted);
    BOOST_CHECK(!denied.ServeAllowed());
    BOOST_CHECK_EQUAL(denied.code, "BTX035_REPLAY");
}

BOOST_AUTO_TEST_CASE(hash_match_alone_is_not_admission)
{
    const auto covered = Edge(0, 8, "S0", "SF");
    BOOST_CHECK(modelnet::FullReplayCoverage(8, "S0", "SF", {covered}));

    const modelnet::AdmissionResult none = modelnet::Admit(
        modelnet::Assurance::PUBLIC_STRICT, true, {covered}, 8, "S0", "SF", {}, false);
    BOOST_CHECK(!none.admitted);
    BOOST_CHECK(!none.research_execution_permit);
    BOOST_CHECK(!none.ServeAllowed());
    BOOST_CHECK_EQUAL(none.code, "BTX035_REPLAY");

    const modelnet::AdmissionResult realm = modelnet::Admit(
        modelnet::Assurance::REALM_STRICT, true, {covered}, 8, "S0", "SF", {}, false);
    BOOST_CHECK(!realm.admitted);
    BOOST_CHECK_EQUAL(realm.code, "BTX035_REPLAY");

    const modelnet::AdmissionResult one = modelnet::Admit(
        modelnet::Assurance::PUBLIC_STRICT, true, {covered}, 8, "S0", "SF", {"only-root"}, false);
    BOOST_CHECK(!one.admitted);
    BOOST_CHECK_EQUAL(one.code, "BTX035_REPLAY");
}

BOOST_AUTO_TEST_CASE(quarantine_blocks_serve_despite_hash_match)
{
    const std::string legacy_id = "legacy-model-035";
    modelnet::Quarantine(legacy_id);
    const modelnet::ServeResult served = modelnet::Serve(legacy_id, true);
    BOOST_CHECK(!served.allowed);
    BOOST_CHECK_EQUAL(served.code, "BTX035_QUARANTINE");

    const modelnet::ServeResult other = modelnet::Serve("other-legacy-model", true);
    BOOST_CHECK(!other.allowed);
    BOOST_CHECK_NE(other.code, "BTX035_QUARANTINE");
}

BOOST_AUTO_TEST_CASE(two_independent_roots_admit_strict)
{
    auto root_a = Edge(0, 8, "S0", "SF");
    root_a.ancestry = "root-a";
    auto root_b = root_a;
    root_b.ancestry = "root-b";
    const std::vector<modelnet::Interval> intervals{root_a, root_b};
    BOOST_CHECK(modelnet::FullReplayCoverage(8, "S0", "SF", intervals));

    const std::vector<std::string> roots{"root-a", "root-b"};
    const modelnet::AdmissionResult admitted = modelnet::Admit(
        modelnet::Assurance::PUBLIC_STRICT, true, intervals, 8, "S0", "SF", roots, false);
    BOOST_CHECK(admitted.admitted);
    BOOST_CHECK(admitted.code.empty());
    BOOST_CHECK(!admitted.research_execution_permit);
    BOOST_CHECK(admitted.ServeAllowed());

    const modelnet::AdmissionResult realm = modelnet::Admit(
        modelnet::Assurance::REALM_STRICT, true, intervals, 8, "S0", "SF", roots, false);
    BOOST_CHECK(realm.admitted);
    BOOST_CHECK(realm.ServeAllowed());

    const modelnet::AdmissionResult duplicated = modelnet::Admit(
        modelnet::Assurance::PUBLIC_STRICT, true, intervals, 8, "S0", "SF", {"root-a", "root-a"}, false);
    BOOST_CHECK(!duplicated.admitted);
    BOOST_CHECK_EQUAL(duplicated.code, "BTX035_REPLAY");

    const modelnet::AdmissionResult empty_root = modelnet::Admit(
        modelnet::Assurance::PUBLIC_STRICT, true, intervals, 8, "S0", "SF", {"root-a", ""}, false);
    BOOST_CHECK(!empty_root.admitted);
    BOOST_CHECK_EQUAL(empty_root.code, "BTX035_REPLAY");

    const modelnet::AdmissionResult research = modelnet::Admit(
        modelnet::Assurance::RESEARCH_ONLY, true, intervals, 8, "S0", "SF", roots, true);
    BOOST_CHECK(research.research_execution_permit);
    BOOST_CHECK(!research.admitted);
    BOOST_CHECK(!research.ServeAllowed());
}

BOOST_AUTO_TEST_SUITE_END()
