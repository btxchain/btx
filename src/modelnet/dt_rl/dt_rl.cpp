// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_rl/dt_rl.h>

#include <algorithm>
#include <cmath>
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

struct Frac {
    int64_t num{0};
    int64_t den{1};
};

/** Reduce num/den into int64 with a positive denominator. */
bool ReduceToInt64(__int128 num, __int128 den, Frac& out)
{
    if (den == 0) return false;
    const __int128 g = Gcd128(num, den);
    num /= g;
    den /= g;
    if (den < 0) {
        num = -num;
        den = -den;
    }
    if (den == 0 || !FitsInt64(num) || !FitsInt64(den)) return false;
    out.num = static_cast<int64_t>(num);
    out.den = static_cast<int64_t>(den);
    return true;
}

} // namespace

bool DtRl::Stale(uint64_t version) const
{
    // version < current_version() - 2. Lag of 2 is still admitted.
    // current_version() <= 2 has no representable version below that line.
    if (m_version <= 2) return false;
    return version < m_version - 2;
}

bool DtRl::Future(uint64_t version) const
{
    return version > m_version;
}

bool DtRl::Add(const std::string& group,
               const std::string& sample,
               int64_t reward,
               int64_t logp,
               uint64_t version,
               bool complete,
               bool self_scored,
               std::string& err)
{
    if (group.empty()) {
        err = DT_RL_GROUP;
        return false;
    }
    if (sample.empty()) {
        err = DT_RL_SAMPLE;
        return false;
    }
    if (self_scored) {
        err = DT_RL_SELF;
        return false;
    }
    if (m_samples.count(sample) != 0) {
        err = DT_RL_DEDUP;
        return false;
    }
    if (Future(version)) {
        err = DT_RL_FUTURE;
        return false;
    }
    if (Stale(version)) {
        err = DT_RL_STALE;
        return false;
    }

    Sample rec;
    rec.reward = reward;
    rec.logp = logp;
    rec.version = version;
    rec.complete = complete;
    m_samples.emplace(sample, rec);
    m_groups[group].order.push_back(sample);
    err.clear();
    return true;
}

bool DtRl::SetVersion(uint64_t version)
{
    if (version < m_version) return false;
    m_version = version;
    return true;
}

bool DtRl::Advantage(const std::string& group, std::string& err)
{
    if (group.empty()) {
        err = DT_RL_GROUP;
        return false;
    }
    const auto git = m_groups.find(group);
    if (git == m_groups.end()) {
        err = DT_RL_GROUP;
        return false;
    }

    std::vector<Sample*> eligible;
    __int128 sum = 0;
    for (const std::string& id : git->second.order) {
        Sample& sample = m_samples[id];
        if (!sample.complete) continue;
        eligible.push_back(&sample);
        sum += sample.reward;
    }
    if (eligible.size() < 2) {
        err = DT_RL_GROUP;
        return false;
    }
    if (!FitsInt64(sum)) {
        err = DT_RL_GROUP;
        return false;
    }

    const int64_t n = static_cast<int64_t>(eligible.size());
    Frac mean;
    if (!ReduceToInt64(sum, n, mean)) {
        err = DT_RL_GROUP;
        return false;
    }

    struct Pending {
        Sample* sample;
        Frac advantage;
    };
    std::vector<Pending> pending;
    pending.reserve(eligible.size());
    for (Sample* sample : eligible) {
        const __int128 num = static_cast<__int128>(sample->reward) * n - sum;
        Pending row;
        row.sample = sample;
        if (!ReduceToInt64(num, n, row.advantage)) {
            err = DT_RL_GROUP;
            return false;
        }
        pending.push_back(row);
    }

    for (const std::string& id : git->second.order) {
        Sample& sample = m_samples[id];
        sample.advantage_set = false;
        sample.adv_num = 0;
        sample.adv_den = 1;
    }
    for (const Pending& row : pending) {
        row.sample->advantage_set = true;
        row.sample->adv_num = row.advantage.num;
        row.sample->adv_den = row.advantage.den;
    }
    git->second.has_mean = true;
    git->second.mean_num = mean.num;
    git->second.mean_den = mean.den;
    err.clear();
    return true;
}

bool DtRl::advantage(const std::string& sample, int64_t& num, int64_t& den) const
{
    const auto it = m_samples.find(sample);
    if (it == m_samples.end() || !it->second.advantage_set) return false;
    num = it->second.adv_num;
    den = it->second.adv_den;
    return true;
}

double DtRl::Clip(double ratio, double advantage, std::string& err) const
{
    // Products are computed at scale 1000 so 0.2 is the integer 200 and
    // the clamp window is [800, 1200] thousandths. The double is chosen/1e6.
    constexpr double kScale = 1000.0;
    constexpr int64_t kOne = 1000;
    constexpr int64_t kEps = 200;
    constexpr int64_t kLo = kOne - kEps;
    constexpr int64_t kHi = kOne + kEps;

    if (!std::isfinite(ratio) || !std::isfinite(advantage)) {
        err = "NONFINITE";
        return std::numeric_limits<double>::quiet_NaN();
    }
    const double r_scaled = ratio * kScale;
    const double a_scaled = advantage * kScale;
    const double hi = static_cast<double>(std::numeric_limits<int64_t>::max());
    const double lo = static_cast<double>(std::numeric_limits<int64_t>::min());
    if (!(r_scaled <= hi && r_scaled >= lo && a_scaled <= hi && a_scaled >= lo)) {
        err = "NONFINITE";
        return std::numeric_limits<double>::quiet_NaN();
    }

    const int64_t r = std::llround(r_scaled);
    const int64_t a = std::llround(a_scaled);
    const int64_t clamped = std::min(std::max(r, kLo), kHi);
    const __int128 unclipped = static_cast<__int128>(r) * static_cast<__int128>(a);
    const __int128 clipped = static_cast<__int128>(clamped) * static_cast<__int128>(a);
    const __int128 chosen = unclipped < clipped ? unclipped : clipped;
    err.clear();
    return static_cast<double>(chosen) / (kScale * kScale);
}

bool DtRl::has_sample(const std::string& sample) const
{
    return m_samples.count(sample) != 0;
}

bool DtRl::has_mean(const std::string& group) const
{
    const auto it = m_groups.find(group);
    return it != m_groups.end() && it->second.has_mean;
}

int64_t DtRl::reward_of(const std::string& sample) const
{
    const auto it = m_samples.find(sample);
    if (it == m_samples.end()) return 0;
    return it->second.reward;
}

int64_t DtRl::logp_of(const std::string& sample) const
{
    const auto it = m_samples.find(sample);
    if (it == m_samples.end()) return 0;
    return it->second.logp;
}

uint64_t DtRl::version_of(const std::string& sample) const
{
    const auto it = m_samples.find(sample);
    if (it == m_samples.end()) return 0;
    return it->second.version;
}

int64_t DtRl::mean_num(const std::string& group) const
{
    const auto it = m_groups.find(group);
    if (it == m_groups.end() || !it->second.has_mean) return 0;
    return it->second.mean_num;
}

int64_t DtRl::mean_den(const std::string& group) const
{
    const auto it = m_groups.find(group);
    if (it == m_groups.end() || !it->second.has_mean) return 1;
    return it->second.mean_den;
}

int64_t DtRl::stored_count() const
{
    return static_cast<int64_t>(m_samples.size());
}

} // namespace modelnet
