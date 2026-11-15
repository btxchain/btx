// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_dense/dt_dense.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>

namespace modelnet {
namespace {

constexpr float kQuery[DtDense::kHeads][DtDense::kHeadDim] = {
    {0.30f, -0.20f, 0.10f, 0.25f},
    {-0.15f, 0.35f, 0.20f, -0.10f},
};

float HeadScale()
{
    return 1.f / std::sqrt(static_cast<float>(DtDense::kHeadDim));
}

std::size_t ProbAt(int head, int row, int col)
{
    return static_cast<std::size_t>((head * DtDense::kSequence + row) * DtDense::kSequence + col);
}

std::size_t LaneAt(int position, int lane)
{
    return static_cast<std::size_t>(position * DtDense::kHeadDim + lane);
}

bool AllFinite(const std::vector<float>& values)
{
    for (const float value : values) {
        if (!std::isfinite(value)) return false;
    }
    return true;
}

} // namespace

DtDense::DtDense()
    : m_weight(kHidden),
      m_grad(kHidden, 0.f),
      m_sum(kHidden, 0.f),
      m_m(kHidden, 0.f),
      m_v(kHidden, 0.f)
{
    m_consumer_grad[0].assign(kHidden, 0.f);
    m_consumer_grad[1].assign(kHidden, 0.f);
    for (int i = 0; i < kHidden; ++i) {
        m_weight[static_cast<std::size_t>(i)] = 0.05f * static_cast<float>(i + 1);
    }
}

const char* DtDense::profile() const
{
    return DT_DENSE_PROFILE;
}

bool DtDense::qualified_v41() const
{
    return false;
}

bool DtDense::gpu() const
{
    return false;
}

bool DtDense::launched() const
{
    return false;
}

bool DtDense::broadcast() const
{
    return false;
}

std::string DtDense::automatic_spend() const
{
    return std::string{NIFDT_AUTOMATIC_SPEND};
}

std::int64_t DtDense::bytes_moved() const
{
    return static_cast<std::int64_t>(0);
}

std::int64_t DtDense::atoms_moved() const
{
    return static_cast<std::int64_t>(0);
}

int DtDense::hidden() const
{
    return kHidden;
}

int DtDense::heads() const
{
    return kHeads;
}

int DtDense::kv_heads() const
{
    return kKvHeads;
}

int DtDense::sequence() const
{
    return kSequence;
}

const std::vector<float>& DtDense::Weight() const
{
    return m_weight;
}

bool DtDense::SetWeight(std::size_t index, float value)
{
    if (index >= m_weight.size() || !std::isfinite(value)) return false;
    m_weight[index] = value;
    return true;
}

bool DtDense::Forward(const std::vector<float>& input, std::string& err)
{
    const std::size_t width = static_cast<std::size_t>(kSequence * kHidden);
    if (input.size() != width) {
        err = DT_DENSE_SHAPE;
        return false;
    }
    if (!AllFinite(input) || !AllFinite(m_weight)) {
        err = DT_DENSE_NONFINITE;
        return false;
    }

    const float scale = HeadScale();
    std::vector<float> output(width, 0.f);
    std::vector<float> value(static_cast<std::size_t>(kSequence * kHeadDim), 0.f);
    std::vector<float> prob(static_cast<std::size_t>(kHeads * kSequence * kSequence), 0.f);

    for (int i = 0; i < kSequence; ++i) {
        // Value at i is mixed only into outputs at rows >= i.
        for (int c = 0; c < kHeadDim; ++c) {
            const float x_lo = input[static_cast<std::size_t>(i * kHidden + c)];
            const float x_hi = input[static_cast<std::size_t>(i * kHidden + kHeadDim + c)];
            const float w_lo = m_weight[static_cast<std::size_t>(c)];
            const float w_hi = m_weight[static_cast<std::size_t>(kHeadDim + c)];
            value[LaneAt(i, c)] = w_lo * x_hi + w_hi * x_lo;
        }
        for (int head = 0; head < kHeads; ++head) {
            std::array<float, kSequence> scores{};
            float max_score = 0.f;
            for (int j = 0; j <= i; ++j) {
                float dot = 0.f;
                for (int c = 0; c < kHeadDim; ++c) {
                    const float x_lo = input[static_cast<std::size_t>(j * kHidden + c)];
                    const float x_hi = input[static_cast<std::size_t>(j * kHidden + kHeadDim + c)];
                    const float w_lo = m_weight[static_cast<std::size_t>(c)];
                    const float w_hi = m_weight[static_cast<std::size_t>(kHeadDim + c)];
                    const float key = w_lo * x_lo + w_hi * x_hi;
                    dot += kQuery[head][c] * key;
                }
                const float score = scale * dot;
                scores[static_cast<std::size_t>(j)] = score;
                if (j == 0 || score > max_score) max_score = score;
            }
            float denom = 0.f;
            for (int j = 0; j <= i; ++j) {
                const float e = std::exp(scores[static_cast<std::size_t>(j)] - max_score);
                prob[ProbAt(head, i, j)] = e;
                denom += e;
            }
            for (int j = 0; j <= i; ++j) {
                prob[ProbAt(head, i, j)] /= denom;
            }
            for (int c = 0; c < kHeadDim; ++c) {
                float acc = 0.f;
                for (int j = 0; j <= i; ++j) {
                    acc += prob[ProbAt(head, i, j)] * value[LaneAt(j, c)];
                }
                output[static_cast<std::size_t>(i * kHidden + head * kHeadDim + c)] = acc;
            }
        }
    }

    if (!AllFinite(output) || !AllFinite(value) || !AllFinite(prob)) {
        err = DT_DENSE_NONFINITE;
        return false;
    }

    m_output = std::move(output);
    m_value = std::move(value);
    m_prob = std::move(prob);
    m_input = input;
    std::fill(m_grad.begin(), m_grad.end(), 0.f);
    std::fill(m_consumer_grad[0].begin(), m_consumer_grad[0].end(), 0.f);
    std::fill(m_consumer_grad[1].begin(), m_consumer_grad[1].end(), 0.f);
    m_have_forward = true;
    err.clear();
    return true;
}

const std::vector<float>& DtDense::Output() const
{
    return m_output;
}

float DtDense::SquaredLoss() const
{
    float sum = 0.f;
    for (const float value : m_output) sum += value * value;
    return 0.5f * sum;
}

bool DtDense::Backward(std::string& err)
{
    if (!m_have_forward || m_output.size() != static_cast<std::size_t>(kSequence * kHidden)) {
        err = DT_DENSE_FORWARD;
        return false;
    }

    const float scale = HeadScale();
    std::vector<float> head_grad[2] = {
        std::vector<float>(kHidden, 0.f),
        std::vector<float>(kHidden, 0.f),
    };

    for (int head = 0; head < kHeads; ++head) {
        std::vector<float> d_key(static_cast<std::size_t>(kSequence * kHeadDim), 0.f);
        std::vector<float> d_value(static_cast<std::size_t>(kSequence * kHeadDim), 0.f);
        for (int i = 0; i < kSequence; ++i) {
            std::array<float, kHeadDim> dy{};
            for (int c = 0; c < kHeadDim; ++c) {
                dy[static_cast<std::size_t>(c)] =
                    m_output[static_cast<std::size_t>(i * kHidden + head * kHeadDim + c)];
            }
            std::array<float, kSequence> d_prob{};
            float dot = 0.f;
            for (int j = 0; j <= i; ++j) {
                float mixed = 0.f;
                for (int c = 0; c < kHeadDim; ++c) {
                    mixed += m_value[LaneAt(j, c)] * dy[static_cast<std::size_t>(c)];
                }
                d_prob[static_cast<std::size_t>(j)] = mixed;
                dot += m_prob[ProbAt(head, i, j)] * mixed;
            }
            for (int j = 0; j <= i; ++j) {
                const float p = m_prob[ProbAt(head, i, j)];
                const float d_score = p * (d_prob[static_cast<std::size_t>(j)] - dot);
                for (int c = 0; c < kHeadDim; ++c) {
                    d_value[LaneAt(j, c)] += p * dy[static_cast<std::size_t>(c)];
                    d_key[LaneAt(j, c)] += d_score * scale * kQuery[head][c];
                }
            }
        }
        for (int j = 0; j < kSequence; ++j) {
            for (int c = 0; c < kHeadDim; ++c) {
                const float x_lo = m_input[static_cast<std::size_t>(j * kHidden + c)];
                const float x_hi = m_input[static_cast<std::size_t>(j * kHidden + kHeadDim + c)];
                head_grad[head][static_cast<std::size_t>(c)] +=
                    d_key[LaneAt(j, c)] * x_lo + d_value[LaneAt(j, c)] * x_hi;
                head_grad[head][static_cast<std::size_t>(kHeadDim + c)] +=
                    d_key[LaneAt(j, c)] * x_hi + d_value[LaneAt(j, c)] * x_lo;
            }
        }
    }

    std::vector<float> total(kHidden, 0.f);
    for (int i = 0; i < kHidden; ++i) {
        const std::size_t index = static_cast<std::size_t>(i);
        total[index] = head_grad[0][index] + head_grad[1][index];
    }
    if (!AllFinite(head_grad[0]) || !AllFinite(head_grad[1]) || !AllFinite(total)) {
        err = DT_DENSE_NONFINITE;
        return false;
    }

    m_consumer_grad[0] = std::move(head_grad[0]);
    m_consumer_grad[1] = std::move(head_grad[1]);
    m_grad = std::move(total);
    err.clear();
    return true;
}

const std::vector<float>& DtDense::AnalyticGradient() const
{
    return m_grad;
}

const std::vector<float>& DtDense::ConsumerGradient(const std::string& consumer) const
{
    const int id = ConsumerIndex(consumer);
    if (id < 0) return m_empty;
    return m_consumer_grad[id];
}

bool DtDense::NoteContribution(const std::string& consumer, const std::vector<float>& gradient, std::string& err)
{
    const int id = ConsumerIndex(consumer);
    if (id < 0) {
        err = DT_DENSE_CONSUMER;
        return false;
    }
    if (gradient.size() != m_weight.size()) {
        err = DT_DENSE_SHAPE;
        return false;
    }
    if (!AllFinite(gradient)) {
        err = DT_DENSE_NONFINITE;
        return false;
    }
    if (m_got[id]) {
        err = DT_DENSE_DUPLICATE;
        return false;
    }
    m_got[id] = true;
    for (std::size_t i = 0; i < gradient.size(); ++i) {
        m_sum[i] += gradient[i];
    }
    err.clear();
    return true;
}

const std::vector<float>& DtDense::ContributionSum() const
{
    return m_sum;
}

bool DtDense::StepAdam(float lr, float beta1, float beta2, float eps, float weight_decay, std::string& err)
{
    if (!m_got[0] || !m_got[1]) {
        err = DT_DENSE_MISSING;
        return false;
    }
    if (!(std::isfinite(lr) && std::isfinite(beta1) && std::isfinite(beta2) && std::isfinite(eps) &&
          std::isfinite(weight_decay) && lr > 0.f && beta1 >= 0.f && beta1 < 1.f && beta2 >= 0.f && beta2 < 1.f &&
          eps > 0.f && weight_decay >= 0.f)) {
        err = DT_DENSE_OPT_CONFIG;
        return false;
    }
    if (!AllFinite(m_sum)) {
        err = DT_DENSE_NONFINITE;
        return false;
    }

    // Decoupled AdamW. Decay hits the owner before the moment update.
    // Bias correction uses the stored step, so a later step sees these moments.
    m_adam_step += 1;
    const float bias1 = 1.f - std::pow(beta1, static_cast<float>(m_adam_step));
    const float bias2 = 1.f - std::pow(beta2, static_cast<float>(m_adam_step));
    const float decay = 1.f - lr * weight_decay;
    const float step_size = lr / bias1;
    const float inv_bias2 = 1.f / std::sqrt(bias2);
    for (std::size_t i = 0; i < m_weight.size(); ++i) {
        const float g = m_sum[i];
        m_weight[i] *= decay;
        m_m[i] = beta1 * m_m[i] + (1.f - beta1) * g;
        m_v[i] = beta2 * m_v[i] + (1.f - beta2) * g * g;
        const float denom = std::sqrt(m_v[i]) * inv_bias2 + eps;
        m_weight[i] -= step_size * m_m[i] / denom;
    }
    m_got[0] = false;
    m_got[1] = false;
    std::fill(m_sum.begin(), m_sum.end(), 0.f);
    err.clear();
    return true;
}

const std::vector<float>& DtDense::Moment1() const
{
    return m_m;
}

const std::vector<float>& DtDense::Moment2() const
{
    return m_v;
}

std::int64_t DtDense::adam_step() const
{
    return m_adam_step;
}

bool DtDense::RefuseAbsent(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool DtDense::GpuStep(std::string& err)
{
    return RefuseAbsent(err);
}

bool DtDense::GpuStep(const std::string& engine, std::string& err)
{
    if (engine == "deepep" || engine == "deepgemm" || engine == "dualpipe" || !NifDtEngineLinked(engine)) {
        return RefuseAbsent(err);
    }
    err = NIFDT_UNQUALIFIED;
    return false;
}

int DtDense::ConsumerIndex(const std::string& consumer) const
{
    if (consumer == DT_DENSE_HEAD0) return 0;
    if (consumer == DT_DENSE_HEAD1) return 1;
    return -1;
}

} // namespace modelnet
