// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_mask/dt_mask.h>
#include <modelnet/nifdt_contract/contract.h>

#include <limits>

namespace modelnet {
namespace {

bool FitsInt64(__int128 v)
{
    return v <= static_cast<__int128>(std::numeric_limits<int64_t>::max()) &&
           v >= static_cast<__int128>(std::numeric_limits<int64_t>::min());
}

__int128 Gcd128(__int128 a, __int128 b)
{
    if (a < 0) a = -a;
    if (b < 0) b = -b;
    while (b != 0) {
        const __int128 t = a % b;
        a = b;
        b = t;
    }
    return a == 0 ? 1 : a;
}

/** Reduce num/den into int64 with a positive denominator. */
bool ReduceToInt64(__int128 num, __int128 den, int64_t& out_num, int64_t& out_den)
{
    if (den == 0) return false;
    const __int128 g = Gcd128(num, den);
    num /= g;
    den /= g;
    if (den < 0) {
        num = -num;
        den = -den;
    }
    if (den <= 0 || !FitsInt64(num) || !FitsInt64(den)) return false;
    out_num = static_cast<int64_t>(num);
    out_den = static_cast<int64_t>(den);
    return true;
}

} // namespace

bool DtMask::Add(const std::string& sample, int64_t gradient, int64_t tokens, std::string& err)
{
    if (sample.empty()) {
        err = DT_MASK_SAMPLE;
        return false;
    }
    if (tokens < 1) {
        err = DT_MASK_MASK;
        return false;
    }
    if (m_samples.find(sample) != m_samples.end()) {
        err = NIFDT_REPLAY;
        return false;
    }

    Sample row;
    row.gradient = gradient;
    row.tokens = tokens;
    m_samples.emplace(sample, row);
    err.clear();
    return true;
}

bool DtMask::Reduce(std::string& err)
{
    if (m_samples.empty()) {
        err = DT_MASK_SAMPLE;
        return false;
    }

    __int128 sum_gradient = 0;
    __int128 sum_tokens = 0;
    for (const auto& entry : m_samples) {
        sum_gradient += entry.second.gradient;
        sum_tokens += entry.second.tokens;
    }
    // Each stored sample contributes a token count of at least 1.
    // The mean is sum(gradient) / sum(tokens), not sum(gradient) / sample count.
    if (sum_tokens <= 0) {
        err = DT_MASK_SAMPLE;
        return false;
    }

    int64_t reduced_num = 0;
    int64_t reduced_den = 1;
    if (!ReduceToInt64(sum_gradient, sum_tokens, reduced_num, reduced_den)) {
        err = DT_MASK_OVERFLOW;
        return false;
    }
    m_num = reduced_num;
    m_den = reduced_den;
    err.clear();
    return true;
}

bool DtMask::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

int64_t DtMask::sample_count() const
{
    return static_cast<int64_t>(m_samples.size());
}

bool DtMask::has_sample(const std::string& sample) const
{
    return m_samples.find(sample) != m_samples.end();
}

int64_t DtMask::gradient_of(const std::string& sample) const
{
    const auto it = m_samples.find(sample);
    if (it == m_samples.end()) return static_cast<int64_t>(0);
    return it->second.gradient;
}

int64_t DtMask::tokens_of(const std::string& sample) const
{
    const auto it = m_samples.find(sample);
    if (it == m_samples.end()) return static_cast<int64_t>(0);
    return it->second.tokens;
}

} // namespace modelnet
