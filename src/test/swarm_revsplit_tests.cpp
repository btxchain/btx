// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_revsplit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_revsplit_tests, BasicTestingSetup)

static modelnet::SwarmRevenueSplitRequest NotedSplit()
{
    modelnet::SwarmRevenueSplitRequest split;
    split.pool_id = "pool-local";
    split.gross = 10000;
    split.sponsor_ppm = 700000;
    split.worker_ppm = 200000;
    split.reserve_ppm = 100000;
    split.want_pay = false;
    return split;
}

static void ExpectPaidStaysFalse(const modelnet::SwarmRevenueSplitResult& result)
{
    BOOST_CHECK(!result.paid);
}

static void ExpectAtomsZero(const modelnet::SwarmRevenueSplitResult& result)
{
    BOOST_CHECK_EQUAL(result.sponsor_atoms, 0);
    BOOST_CHECK_EQUAL(result.worker_atoms, 0);
    BOOST_CHECK_EQUAL(result.reserve_atoms, 0);
}

static void ExpectIllustrationAtoms(const modelnet::SwarmRevenueSplitResult& result)
{
    BOOST_CHECK_EQUAL(result.sponsor_atoms, 7000);
    BOOST_CHECK_EQUAL(result.worker_atoms, 2000);
    BOOST_CHECK_EQUAL(result.reserve_atoms, 1000);
}

BOOST_AUTO_TEST_CASE(empty_pool_id_is_split)
{
    modelnet::SwarmRevenueSplitRequest split = NotedSplit();
    split.pool_id.clear();
    split.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmRevenueSplitResult result = modelnet::SwarmNoteRevenueSplit(split, err);
    ExpectPaidStaysFalse(result);
    ExpectAtomsZero(result);
    BOOST_CHECK_EQUAL(result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");
}

BOOST_AUTO_TEST_CASE(negative_gross_is_split)
{
    modelnet::SwarmRevenueSplitRequest split = NotedSplit();
    split.gross = -1;
    split.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmRevenueSplitResult result = modelnet::SwarmNoteRevenueSplit(split, err);
    ExpectPaidStaysFalse(result);
    ExpectAtomsZero(result);
    BOOST_CHECK_EQUAL(result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");
}

BOOST_AUTO_TEST_CASE(negative_ppm_is_split)
{
    std::string err = "prior";
    modelnet::SwarmRevenueSplitRequest sponsor = NotedSplit();
    sponsor.sponsor_ppm = -1;
    sponsor.want_pay = true;
    const modelnet::SwarmRevenueSplitResult sponsor_result =
        modelnet::SwarmNoteRevenueSplit(sponsor, err);
    ExpectPaidStaysFalse(sponsor_result);
    ExpectAtomsZero(sponsor_result);
    BOOST_CHECK_EQUAL(sponsor_result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");

    modelnet::SwarmRevenueSplitRequest worker = NotedSplit();
    worker.worker_ppm = -1;
    worker.want_pay = true;
    const modelnet::SwarmRevenueSplitResult worker_result =
        modelnet::SwarmNoteRevenueSplit(worker, err);
    ExpectPaidStaysFalse(worker_result);
    ExpectAtomsZero(worker_result);
    BOOST_CHECK_EQUAL(worker_result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");

    modelnet::SwarmRevenueSplitRequest reserve = NotedSplit();
    reserve.reserve_ppm = -1;
    reserve.want_pay = true;
    const modelnet::SwarmRevenueSplitResult reserve_result =
        modelnet::SwarmNoteRevenueSplit(reserve, err);
    ExpectPaidStaysFalse(reserve_result);
    ExpectAtomsZero(reserve_result);
    BOOST_CHECK_EQUAL(reserve_result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");
}

BOOST_AUTO_TEST_CASE(ppm_overflow_is_split)
{
    modelnet::SwarmRevenueSplitRequest split = NotedSplit();
    split.gross = 10000;
    split.sponsor_ppm = INT64_MAX;
    split.worker_ppm = 1;
    split.reserve_ppm = 0;
    split.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmRevenueSplitResult result = modelnet::SwarmNoteRevenueSplit(split, err);
    ExpectPaidStaysFalse(result);
    ExpectAtomsZero(result);
    BOOST_CHECK_EQUAL(result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");
}

BOOST_AUTO_TEST_CASE(split_wins_over_sum_and_want_pay)
{
    modelnet::SwarmRevenueSplitRequest split = NotedSplit();
    split.pool_id.clear();
    split.gross = -5;
    split.sponsor_ppm = 1;
    split.worker_ppm = 1;
    split.reserve_ppm = 1;
    split.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmRevenueSplitResult result = modelnet::SwarmNoteRevenueSplit(split, err);
    ExpectPaidStaysFalse(result);
    ExpectAtomsZero(result);
    BOOST_CHECK_EQUAL(result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");
}

BOOST_AUTO_TEST_CASE(ppm_sum_other_than_1000000_is_sum)
{
    std::string err = "prior";
    modelnet::SwarmRevenueSplitRequest short_sum = NotedSplit();
    short_sum.sponsor_ppm = 700000;
    short_sum.worker_ppm = 200000;
    short_sum.reserve_ppm = 99999;
    short_sum.want_pay = true;
    const modelnet::SwarmRevenueSplitResult short_result =
        modelnet::SwarmNoteRevenueSplit(short_sum, err);
    ExpectPaidStaysFalse(short_result);
    ExpectAtomsZero(short_result);
    BOOST_CHECK_EQUAL(short_result.code, "SUM");
    BOOST_CHECK_EQUAL(err, "SUM");

    modelnet::SwarmRevenueSplitRequest zeros = NotedSplit();
    zeros.sponsor_ppm = 0;
    zeros.worker_ppm = 0;
    zeros.reserve_ppm = 0;
    zeros.want_pay = true;
    const modelnet::SwarmRevenueSplitResult zero_result =
        modelnet::SwarmNoteRevenueSplit(zeros, err);
    ExpectPaidStaysFalse(zero_result);
    ExpectAtomsZero(zero_result);
    BOOST_CHECK_EQUAL(zero_result.code, "SUM");
    BOOST_CHECK_EQUAL(err, "SUM");

    modelnet::SwarmRevenueSplitRequest wide = NotedSplit();
    wide.sponsor_ppm = INT64_MAX;
    wide.worker_ppm = 0;
    wide.reserve_ppm = 0;
    wide.want_pay = true;
    const modelnet::SwarmRevenueSplitResult wide_result =
        modelnet::SwarmNoteRevenueSplit(wide, err);
    ExpectPaidStaysFalse(wide_result);
    ExpectAtomsZero(wide_result);
    BOOST_CHECK_EQUAL(wide_result.code, "SUM");
    BOOST_CHECK_EQUAL(err, "SUM");
}

BOOST_AUTO_TEST_CASE(sum_wins_when_want_pay_is_true)
{
    modelnet::SwarmRevenueSplitRequest split = NotedSplit();
    split.gross = 9999;
    split.sponsor_ppm = 1;
    split.worker_ppm = 1;
    split.reserve_ppm = 1;
    split.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmRevenueSplitResult result = modelnet::SwarmNoteRevenueSplit(split, err);
    ExpectPaidStaysFalse(result);
    ExpectAtomsZero(result);
    BOOST_CHECK_EQUAL(result.code, "SUM");
    BOOST_CHECK_EQUAL(err, "SUM");
}

BOOST_AUTO_TEST_CASE(other_splits_are_illustration)
{
    std::string err = "prior";
    modelnet::SwarmRevenueSplitRequest other_gross = NotedSplit();
    other_gross.gross = 10001;
    const modelnet::SwarmRevenueSplitResult gross =
        modelnet::SwarmNoteRevenueSplit(other_gross, err);
    ExpectPaidStaysFalse(gross);
    ExpectAtomsZero(gross);
    BOOST_CHECK_EQUAL(gross.code, "ILLUSTRATION");
    BOOST_CHECK_EQUAL(err, "ILLUSTRATION");

    modelnet::SwarmRevenueSplitRequest other_ppm = NotedSplit();
    other_ppm.sponsor_ppm = 500000;
    other_ppm.worker_ppm = 500000;
    other_ppm.reserve_ppm = 0;
    const modelnet::SwarmRevenueSplitResult ppm = modelnet::SwarmNoteRevenueSplit(other_ppm, err);
    ExpectPaidStaysFalse(ppm);
    ExpectAtomsZero(ppm);
    BOOST_CHECK_EQUAL(ppm.code, "ILLUSTRATION");
    BOOST_CHECK_EQUAL(err, "ILLUSTRATION");

    modelnet::SwarmRevenueSplitRequest zero_gross = NotedSplit();
    zero_gross.gross = 0;
    const modelnet::SwarmRevenueSplitResult zero = modelnet::SwarmNoteRevenueSplit(zero_gross, err);
    ExpectPaidStaysFalse(zero);
    ExpectAtomsZero(zero);
    BOOST_CHECK_EQUAL(zero.code, "ILLUSTRATION");
    BOOST_CHECK_EQUAL(err, "ILLUSTRATION");
}

BOOST_AUTO_TEST_CASE(illustration_wins_when_want_pay_is_true)
{
    modelnet::SwarmRevenueSplitRequest split = NotedSplit();
    split.gross = 10000;
    split.sponsor_ppm = 700000;
    split.worker_ppm = 200001;
    split.reserve_ppm = 99999;
    split.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmRevenueSplitResult result = modelnet::SwarmNoteRevenueSplit(split, err);
    ExpectPaidStaysFalse(result);
    ExpectAtomsZero(result);
    BOOST_CHECK_EQUAL(result.code, "ILLUSTRATION");
    BOOST_CHECK_EQUAL(err, "ILLUSTRATION");
}

BOOST_AUTO_TEST_CASE(want_pay_on_the_known_illustration_is_held)
{
    modelnet::SwarmRevenueSplitRequest split = NotedSplit();
    split.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmRevenueSplitResult result = modelnet::SwarmNoteRevenueSplit(split, err);
    ExpectPaidStaysFalse(result);
    ExpectIllustrationAtoms(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(known_illustration_is_noted)
{
    modelnet::SwarmRevenueSplitRequest split = NotedSplit();
    std::string err = "prior";
    const modelnet::SwarmRevenueSplitResult result = modelnet::SwarmNoteRevenueSplit(split, err);
    ExpectPaidStaysFalse(result);
    ExpectIllustrationAtoms(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
