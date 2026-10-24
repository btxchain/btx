// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_mask/dt_mask.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_mask_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(token_mean_two_and_four_is_three_halves)
{
    modelnet::DtMask mask;
    std::string err = "prior";
    BOOST_CHECK(!mask.launched());
    BOOST_CHECK(!mask.gpu());
    BOOST_CHECK(!mask.broadcast());
    BOOST_CHECK(!mask.hardware_qualified());
    BOOST_CHECK_EQUAL(mask.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(mask.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(mask.num(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(mask.den(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(mask.sample_count(), static_cast<int64_t>(0));

    BOOST_CHECK(mask.Add("a", static_cast<int64_t>(2), static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(mask.Add("b", static_cast<int64_t>(4), static_cast<int64_t>(3), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(mask.sample_count(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(mask.gradient_of("a"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(mask.tokens_of("a"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(mask.gradient_of("b"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(mask.tokens_of("b"), static_cast<int64_t>(3));

    BOOST_CHECK(mask.Reduce(err));
    BOOST_CHECK(err.empty());
    // sum(gradient) / sum(tokens) = (2 + 4) / (1 + 3) = 6/4 = 3/2.
    BOOST_CHECK_EQUAL(mask.num(), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(mask.den(), static_cast<int64_t>(2));
    BOOST_CHECK(mask.den() > static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(mask.num() * static_cast<int64_t>(4), static_cast<int64_t>(6) * mask.den());

    // Dividing the same gradients by the sample count yields 3.
    const int64_t by_sample_count =
        (static_cast<int64_t>(2) + static_cast<int64_t>(4)) / static_cast<int64_t>(2);
    BOOST_CHECK_EQUAL(by_sample_count, static_cast<int64_t>(3));
    BOOST_CHECK(mask.num() != by_sample_count || mask.den() != static_cast<int64_t>(1));

    modelnet::DtMask flipped;
    BOOST_CHECK(flipped.Add("b", static_cast<int64_t>(4), static_cast<int64_t>(3), err));
    BOOST_CHECK(flipped.Add("a", static_cast<int64_t>(2), static_cast<int64_t>(1), err));
    BOOST_CHECK(flipped.Reduce(err));
    BOOST_CHECK_EQUAL(flipped.num(), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(flipped.den(), static_cast<int64_t>(2));

    BOOST_CHECK(!mask.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(mask.num(), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(mask.den(), static_cast<int64_t>(2));
    BOOST_CHECK(!mask.gpu());
    BOOST_CHECK(!mask.launched());
    BOOST_CHECK(!mask.broadcast());
    BOOST_CHECK(!mask.hardware_qualified());
    BOOST_CHECK_EQUAL(mask.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(mask.sample_count(), static_cast<int64_t>(2));
}

BOOST_AUTO_TEST_CASE(zero_token_count_stores_nothing)
{
    modelnet::DtMask mask;
    std::string err = "prior";
    BOOST_CHECK(!mask.Add("dropped", static_cast<int64_t>(100), static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "MASK");
    BOOST_CHECK_EQUAL(err, modelnet::DT_MASK_MASK);
    BOOST_CHECK(!mask.has_sample("dropped"));
    BOOST_CHECK_EQUAL(mask.sample_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(mask.gradient_of("dropped"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(mask.tokens_of("dropped"), static_cast<int64_t>(0));

    BOOST_CHECK(!mask.Add("negative", static_cast<int64_t>(8), static_cast<int64_t>(-3), err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_MASK_MASK);
    BOOST_CHECK(!mask.has_sample("negative"));
    BOOST_CHECK_EQUAL(mask.sample_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!mask.Reduce(err));
    BOOST_CHECK_EQUAL(err, "SAMPLE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_MASK_SAMPLE);
    BOOST_CHECK_EQUAL(mask.num(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(mask.den(), static_cast<int64_t>(1));

    const int64_t num_before = mask.num();
    const int64_t den_before = mask.den();
    BOOST_CHECK(!mask.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(mask.num(), num_before);
    BOOST_CHECK_EQUAL(mask.den(), den_before);
    BOOST_CHECK_EQUAL(mask.num(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(mask.den(), static_cast<int64_t>(1));

    BOOST_CHECK(mask.Add("a", static_cast<int64_t>(2), static_cast<int64_t>(1), err));
    BOOST_CHECK(mask.Add("b", static_cast<int64_t>(4), static_cast<int64_t>(3), err));
    BOOST_CHECK(!mask.has_sample("dropped"));
    BOOST_CHECK_EQUAL(mask.sample_count(), static_cast<int64_t>(2));
    BOOST_CHECK(mask.Reduce(err));
    BOOST_CHECK_EQUAL(mask.num(), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(mask.den(), static_cast<int64_t>(2));
}

BOOST_AUTO_TEST_CASE(empty_sample_and_replay_keep_the_first)
{
    modelnet::DtMask mask;
    std::string err = "prior";
    BOOST_CHECK(!mask.Add("", static_cast<int64_t>(2), static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "SAMPLE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_MASK_SAMPLE);
    BOOST_CHECK_EQUAL(mask.sample_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(mask.num(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(mask.den(), static_cast<int64_t>(1));

    BOOST_CHECK(mask.Add("a", static_cast<int64_t>(2), static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!mask.Add("a", static_cast<int64_t>(9), static_cast<int64_t>(7), err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(mask.has_sample("a"));
    BOOST_CHECK_EQUAL(mask.sample_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(mask.gradient_of("a"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(mask.tokens_of("a"), static_cast<int64_t>(1));

    BOOST_CHECK(mask.Reduce(err));
    BOOST_CHECK_EQUAL(mask.num(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(mask.den(), static_cast<int64_t>(1));
    BOOST_CHECK(!mask.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(mask.num(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(mask.den(), static_cast<int64_t>(1));
    BOOST_CHECK(!mask.launched());
    BOOST_CHECK(!mask.gpu());
    BOOST_CHECK(!mask.broadcast());
    BOOST_CHECK(!mask.hardware_qualified());
    BOOST_CHECK_EQUAL(mask.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_CASE(negative_gradient_sum_keeps_a_positive_denominator)
{
    modelnet::DtMask mask;
    std::string err = "prior";
    BOOST_CHECK(mask.Add("a", static_cast<int64_t>(-2), static_cast<int64_t>(1), err));
    BOOST_CHECK(mask.Add("b", static_cast<int64_t>(-4), static_cast<int64_t>(3), err));
    BOOST_CHECK(mask.Reduce(err));
    BOOST_CHECK(err.empty());
    // (-2 + -4) / (1 + 3) = -6/4 = -3/2.
    BOOST_CHECK_EQUAL(mask.num(), static_cast<int64_t>(-3));
    BOOST_CHECK_EQUAL(mask.den(), static_cast<int64_t>(2));
    BOOST_CHECK(mask.den() > static_cast<int64_t>(0));
    BOOST_CHECK(!mask.hardware_qualified());
    BOOST_CHECK_EQUAL(mask.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
