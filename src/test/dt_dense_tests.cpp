// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_dense/dt_dense.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

namespace {

std::vector<float> PatternInput()
{
    std::vector<float> input(static_cast<std::size_t>(modelnet::DtDense::kSequence * modelnet::DtDense::kHidden));
    for (int t = 0; t < modelnet::DtDense::kSequence; ++t) {
        for (int c = 0; c < modelnet::DtDense::kHidden; ++c) {
            const float sign = ((t + c) % 2 == 0) ? 1.f : -1.f;
            input[static_cast<std::size_t>(t * modelnet::DtDense::kHidden + c)] =
                0.08f * (static_cast<float>(t + 1) + 0.1f * static_cast<float>(c + 1)) * sign;
        }
    }
    return input;
}

float SquaredLoss(const std::vector<float>& output)
{
    float sum = 0.f;
    for (const float value : output) sum += value * value;
    return 0.5f * sum;
}

void AddPosition(std::vector<float>& input, int position, float delta)
{
    for (int c = 0; c < modelnet::DtDense::kHidden; ++c) {
        input[static_cast<std::size_t>(position * modelnet::DtDense::kHidden + c)] += delta;
    }
}

bool PrefixSame(const std::vector<float>& left, const std::vector<float>& right, int positions)
{
    const int count = positions * modelnet::DtDense::kHidden;
    if (static_cast<int>(left.size()) < count || static_cast<int>(right.size()) < count) return false;
    for (int i = 0; i < count; ++i) {
        if (left[static_cast<std::size_t>(i)] != right[static_cast<std::size_t>(i)]) return false;
    }
    return true;
}

bool PositionDiffers(const std::vector<float>& left, const std::vector<float>& right, int position)
{
    for (int c = 0; c < modelnet::DtDense::kHidden; ++c) {
        const std::size_t index = static_cast<std::size_t>(position * modelnet::DtDense::kHidden + c);
        if (left[index] != right[index]) return true;
    }
    return false;
}

bool AnyNonzero(const std::vector<float>& values)
{
    for (const float value : values) {
        if (value != 0.f) return true;
    }
    return false;
}

bool SameFloats(const std::vector<float>& left, const std::vector<float>& right)
{
    if (left.size() != right.size()) return false;
    for (std::size_t i = 0; i < left.size(); ++i) {
        if (left[i] != right[i]) return false;
    }
    return true;
}

std::vector<float> Add(const std::vector<float>& left, const std::vector<float>& right)
{
    std::vector<float> sum(left.size(), 0.f);
    for (std::size_t i = 0; i < left.size() && i < right.size(); ++i) sum[i] = left[i] + right[i];
    return sum;
}

void AdamWStep(std::vector<float>& weight, std::vector<float>& moment1, std::vector<float>& moment2, std::int64_t& step,
               const std::vector<float>& grad, float lr, float beta1, float beta2, float eps, float weight_decay)
{
    step += static_cast<std::int64_t>(1);
    const float bias1 = 1.f - std::pow(beta1, static_cast<float>(step));
    const float bias2 = 1.f - std::pow(beta2, static_cast<float>(step));
    const float decay = 1.f - lr * weight_decay;
    const float step_size = lr / bias1;
    const float inv_bias2 = 1.f / std::sqrt(bias2);
    for (std::size_t i = 0; i < weight.size(); ++i) {
        const float g = grad[i];
        weight[i] *= decay;
        moment1[i] = beta1 * moment1[i] + (1.f - beta1) * g;
        moment2[i] = beta2 * moment2[i] + (1.f - beta2) * g * g;
        const float denom = std::sqrt(moment2[i]) * inv_bias2 + eps;
        weight[i] -= step_size * moment1[i] / denom;
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(dt_dense_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(profile_geometry_and_quiet_counters)
{
    modelnet::DtDense dense;
    BOOST_CHECK_EQUAL(std::string(dense.profile()), "dense_gqa_v1");
    BOOST_CHECK(!dense.qualified_v41());
    BOOST_CHECK(!dense.gpu());
    BOOST_CHECK(!dense.launched());
    BOOST_CHECK(!dense.broadcast());
    BOOST_CHECK_EQUAL(dense.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(dense.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(dense.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(dense.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(dense.adam_step(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(dense.hidden(), 8);
    BOOST_CHECK_EQUAL(dense.heads(), 2);
    BOOST_CHECK_EQUAL(dense.kv_heads(), 1);
    BOOST_CHECK_EQUAL(dense.sequence(), 4);
    BOOST_CHECK_EQUAL(dense.hidden() % dense.heads(), 0);
    BOOST_CHECK_EQUAL(dense.heads() % dense.kv_heads(), 0);
    BOOST_REQUIRE_EQUAL(dense.Weight().size(), static_cast<std::size_t>(8));
    for (int i = 0; i < 8; ++i) {
        const float expected = 0.05f * static_cast<float>(i + 1);
        BOOST_CHECK(dense.Weight()[static_cast<std::size_t>(i)] != 0.f);
        BOOST_CHECK_EQUAL(dense.Weight()[static_cast<std::size_t>(i)], expected);
    }
}

BOOST_AUTO_TEST_CASE(causal_mask_does_not_read_future)
{
    modelnet::DtDense dense;
    const std::vector<float> weight_before = dense.Weight();
    const std::vector<float> base = PatternInput();
    std::string err = "prior";
    BOOST_REQUIRE(dense.Forward(base, err));
    BOOST_CHECK(err.empty());
    const std::vector<float> original = dense.Output();
    BOOST_REQUIRE_EQUAL(original.size(), static_cast<std::size_t>(32));
    BOOST_CHECK(AnyNonzero(original));
    BOOST_CHECK_EQUAL(dense.SquaredLoss(), SquaredLoss(original));

    std::vector<float> future = base;
    AddPosition(future, 3, 0.5f);
    BOOST_REQUIRE(dense.Forward(future, err));
    const std::vector<float> after_future = dense.Output();
    BOOST_CHECK(PrefixSame(original, after_future, 3));
    BOOST_CHECK(PositionDiffers(original, after_future, 3));

    std::vector<float> mid = base;
    AddPosition(mid, 2, 0.5f);
    BOOST_REQUIRE(dense.Forward(mid, err));
    const std::vector<float> after_mid = dense.Output();
    BOOST_CHECK(PrefixSame(original, after_mid, 2));
    BOOST_CHECK(PositionDiffers(original, after_mid, 2));
    BOOST_CHECK(PositionDiffers(original, after_mid, 3));

    std::vector<float> self = base;
    AddPosition(self, 0, 0.5f);
    BOOST_REQUIRE(dense.Forward(self, err));
    BOOST_CHECK(PositionDiffers(original, dense.Output(), 0));
    BOOST_CHECK(SameFloats(dense.Weight(), weight_before));
    BOOST_CHECK_EQUAL(dense.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!dense.launched());
}

BOOST_AUTO_TEST_CASE(duplicate_contribution_does_not_change_sum)
{
    modelnet::DtDense dense;
    std::string err = "prior";
    BOOST_REQUIRE(dense.Forward(PatternInput(), err));
    BOOST_REQUIRE(dense.Backward(err));
    const std::vector<float> head0 = dense.ConsumerGradient(modelnet::DT_DENSE_HEAD0);
    const std::vector<float> head1 = dense.ConsumerGradient(modelnet::DT_DENSE_HEAD1);
    BOOST_REQUIRE(AnyNonzero(head0));
    BOOST_REQUIRE(AnyNonzero(head1));
    BOOST_CHECK(SameFloats(Add(head0, head1), dense.AnalyticGradient()));

    BOOST_CHECK(dense.NoteContribution(modelnet::DT_DENSE_HEAD0, head0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(SameFloats(dense.ContributionSum(), head0));

    const std::vector<float> before = dense.ContributionSum();
    BOOST_CHECK(!dense.NoteContribution(modelnet::DT_DENSE_HEAD0, head0, err));
    BOOST_CHECK_EQUAL(err, "DUPLICATE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_DENSE_DUPLICATE);
    BOOST_CHECK(SameFloats(dense.ContributionSum(), before));

    BOOST_CHECK(dense.NoteContribution(modelnet::DT_DENSE_HEAD1, head1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(SameFloats(dense.ContributionSum(), Add(head0, head1)));
    BOOST_CHECK(!SameFloats(dense.ContributionSum(), Add(Add(head0, head0), head1)));
}

BOOST_AUTO_TEST_CASE(missing_contribution_does_not_step)
{
    modelnet::DtDense dense;
    std::string err = "prior";
    BOOST_REQUIRE(dense.Forward(PatternInput(), err));
    BOOST_REQUIRE(dense.Backward(err));
    const std::vector<float> head0 = dense.ConsumerGradient(modelnet::DT_DENSE_HEAD0);
    const std::vector<float> weight_before = dense.Weight();
    const std::vector<float> moment1_before = dense.Moment1();
    const std::vector<float> moment2_before = dense.Moment2();

    BOOST_CHECK(dense.NoteContribution(modelnet::DT_DENSE_HEAD0, head0, err));
    BOOST_CHECK(!dense.StepAdam(0.01f, 0.9f, 0.999f, 1e-8f, 0.01f, err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK_EQUAL(err, modelnet::DT_DENSE_MISSING);
    BOOST_CHECK(SameFloats(dense.Weight(), weight_before));
    BOOST_CHECK(SameFloats(dense.Moment1(), moment1_before));
    BOOST_CHECK(SameFloats(dense.Moment2(), moment2_before));
    BOOST_CHECK_EQUAL(dense.adam_step(), static_cast<int64_t>(0));
    BOOST_CHECK(SameFloats(dense.ContributionSum(), head0));

    BOOST_CHECK(!dense.NoteContribution(modelnet::DT_DENSE_HEAD0, head0, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_DENSE_DUPLICATE);
    BOOST_CHECK(SameFloats(dense.Weight(), weight_before));
    BOOST_CHECK_EQUAL(dense.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(dense.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(adamw_step_changes_weight_and_reuses_moments)
{
    modelnet::DtDense dense;
    std::string err = "prior";
    BOOST_REQUIRE(dense.Forward(PatternInput(), err));
    BOOST_REQUIRE(dense.Backward(err));
    const std::vector<float> head0 = dense.ConsumerGradient(modelnet::DT_DENSE_HEAD0);
    const std::vector<float> head1 = dense.ConsumerGradient(modelnet::DT_DENSE_HEAD1);
    const std::vector<float> grad = Add(head0, head1);
    const float lr = 0.01f;
    const float beta1 = 0.9f;
    const float beta2 = 0.999f;
    const float eps = 1e-8f;
    const float weight_decay = 0.01f;

    const std::vector<float> weight_before = dense.Weight();
    BOOST_CHECK(dense.NoteContribution(modelnet::DT_DENSE_HEAD0, head0, err));
    BOOST_CHECK(dense.NoteContribution(modelnet::DT_DENSE_HEAD1, head1, err));
    BOOST_CHECK(dense.StepAdam(lr, beta1, beta2, eps, weight_decay, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!SameFloats(dense.Weight(), weight_before));
    BOOST_CHECK_EQUAL(dense.adam_step(), static_cast<int64_t>(1));

    for (std::size_t i = 0; i < grad.size(); ++i) {
        const float expect_m = (1.f - beta1) * grad[i];
        const float expect_v = (1.f - beta2) * grad[i] * grad[i];
        BOOST_CHECK(std::fabs(dense.Moment1()[i] - expect_m) <= 1e-6f);
        BOOST_CHECK(std::fabs(dense.Moment2()[i] - expect_v) <= 1e-8f);
    }

    const std::vector<float> after_first = dense.Weight();
    const std::vector<float> moment1_after = dense.Moment1();
    const std::vector<float> moment2_after = dense.Moment2();
    BOOST_CHECK(!dense.StepAdam(lr, beta1, beta2, eps, weight_decay, err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_DENSE_MISSING);
    BOOST_CHECK(SameFloats(dense.Weight(), after_first));
    BOOST_CHECK(SameFloats(dense.Moment1(), moment1_after));
    BOOST_CHECK(SameFloats(dense.Moment2(), moment2_after));
    BOOST_CHECK_EQUAL(dense.adam_step(), static_cast<int64_t>(1));

    BOOST_CHECK(dense.NoteContribution(modelnet::DT_DENSE_HEAD0, head0, err));
    BOOST_CHECK(dense.NoteContribution(modelnet::DT_DENSE_HEAD1, head1, err));
    BOOST_CHECK(dense.StepAdam(lr, beta1, beta2, eps, weight_decay, err));
    BOOST_CHECK(!SameFloats(dense.Weight(), after_first));
    BOOST_CHECK_EQUAL(dense.adam_step(), static_cast<int64_t>(2));

    std::vector<float> expect_w = weight_before;
    std::vector<float> expect_m(grad.size(), 0.f);
    std::vector<float> expect_v(grad.size(), 0.f);
    std::int64_t expect_step = static_cast<int64_t>(0);
    AdamWStep(expect_w, expect_m, expect_v, expect_step, grad, lr, beta1, beta2, eps, weight_decay);
    AdamWStep(expect_w, expect_m, expect_v, expect_step, grad, lr, beta1, beta2, eps, weight_decay);
    BOOST_CHECK_EQUAL(expect_step, static_cast<int64_t>(2));
    for (std::size_t i = 0; i < expect_w.size(); ++i) {
        BOOST_CHECK(std::fabs(dense.Weight()[i] - expect_w[i]) <= 1e-6f);
        BOOST_CHECK(std::fabs(dense.Moment1()[i] - expect_m[i]) <= 1e-6f);
        BOOST_CHECK(std::fabs(dense.Moment2()[i] - expect_v[i]) <= 1e-8f);
        const float reset_m = (1.f - beta1) * grad[i];
        if (std::fabs(grad[i]) > 1e-4f) {
            BOOST_CHECK(std::fabs(dense.Moment1()[i] - reset_m) > 1e-4f);
        }
    }
    BOOST_CHECK_EQUAL(dense.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(dense.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(dense.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!dense.launched());
    BOOST_CHECK(!dense.broadcast());
}

BOOST_AUTO_TEST_CASE(finite_difference_matches_analytic_gradient)
{
    modelnet::DtDense dense;
    std::string err = "prior";
    const std::vector<float> input = PatternInput();
    BOOST_REQUIRE(dense.Forward(input, err));
    BOOST_REQUIRE(dense.Backward(err));
    BOOST_CHECK(std::fabs(dense.SquaredLoss() - SquaredLoss(dense.Output())) <= 0.f);
    const std::vector<float> origin = dense.Weight();
    const std::vector<float> analytic = dense.AnalyticGradient();
    BOOST_REQUIRE_EQUAL(analytic.size(), origin.size());

    const float h = 1e-3f;
    for (std::size_t k = 0; k < origin.size(); ++k) {
        BOOST_REQUIRE(std::fabs(analytic[k]) > 1e-4f);
        BOOST_REQUIRE(dense.SetWeight(k, origin[k] + h));
        BOOST_REQUIRE(dense.Forward(input, err));
        const float loss_plus = SquaredLoss(dense.Output());
        BOOST_REQUIRE(dense.SetWeight(k, origin[k] - h));
        BOOST_REQUIRE(dense.Forward(input, err));
        const float loss_minus = SquaredLoss(dense.Output());
        const float numerical = (loss_plus - loss_minus) / (2.f * h);
        BOOST_CHECK_MESSAGE(std::fabs(numerical - analytic[k]) <= 1e-2f,
                            "scalar " << k << " numerical " << numerical << " analytic " << analytic[k]);
        BOOST_REQUIRE(dense.SetWeight(k, origin[k]));
    }
}

BOOST_AUTO_TEST_CASE(absent_engines_do_not_change_weights)
{
    modelnet::DtDense dense;
    const std::vector<float> weight_before = dense.Weight();
    const std::vector<float> moment1_before = dense.Moment1();
    const std::vector<float> moment2_before = dense.Moment2();
    std::string err = "prior";

    BOOST_CHECK(!dense.GpuStep(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!dense.GpuStep("deepep", err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!dense.GpuStep("deepgemm", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!dense.GpuStep("dualpipe", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(SameFloats(dense.Weight(), weight_before));
    BOOST_CHECK(SameFloats(dense.Moment1(), moment1_before));
    BOOST_CHECK(SameFloats(dense.Moment2(), moment2_before));
    BOOST_CHECK(!dense.gpu());
    BOOST_CHECK(!dense.qualified_v41());
    BOOST_CHECK(!dense.launched());
    BOOST_CHECK(!dense.broadcast());
    BOOST_CHECK_EQUAL(dense.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(dense.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(dense.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(dense.adam_step(), static_cast<int64_t>(0));

    BOOST_REQUIRE(dense.Forward(PatternInput(), err));
    BOOST_REQUIRE(dense.Backward(err));
    BOOST_REQUIRE(dense.NoteContribution(modelnet::DT_DENSE_HEAD0, dense.ConsumerGradient(modelnet::DT_DENSE_HEAD0), err));
    BOOST_REQUIRE(dense.NoteContribution(modelnet::DT_DENSE_HEAD1, dense.ConsumerGradient(modelnet::DT_DENSE_HEAD1), err));
    BOOST_REQUIRE(dense.StepAdam(0.01f, 0.9f, 0.999f, 1e-8f, 0.01f, err));
    const std::vector<float> stepped = dense.Weight();
    const std::vector<float> stepped_m = dense.Moment1();
    const std::vector<float> stepped_v = dense.Moment2();
    const std::int64_t stepped_t = dense.adam_step();
    BOOST_CHECK(!dense.GpuStep(err));
    BOOST_CHECK(!dense.GpuStep("deepep", err));
    BOOST_CHECK(!dense.GpuStep("deepgemm", err));
    BOOST_CHECK(!dense.GpuStep("dualpipe", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(SameFloats(dense.Weight(), stepped));
    BOOST_CHECK(SameFloats(dense.Moment1(), stepped_m));
    BOOST_CHECK(SameFloats(dense.Moment2(), stepped_v));
    BOOST_CHECK_EQUAL(dense.adam_step(), stepped_t);
    BOOST_CHECK(!dense.gpu());
    BOOST_CHECK_EQUAL(dense.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_SUITE_END()
