// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_rollout/dt_rollout.h>

namespace modelnet {

const DtRollout::Sample* DtRollout::Find(const std::string& sample) const
{
    const auto it = m_samples.find(sample);
    if (it == m_samples.end()) return nullptr;
    return &it->second;
}

bool DtRollout::Route(const std::string& sample, uint64_t version, bool compatible, std::string& err)
{
    if (sample.empty()) {
        err = DT_ROLLOUT_SAMPLE;
        return false;
    }
    if (m_samples.find(sample) != m_samples.end()) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (!compatible) {
        err = DT_ROLLOUT_ROUTE;
        return false;
    }
    Sample row;
    row.version = version;
    m_samples.emplace(sample, row);
    err.clear();
    return true;
}

bool DtRollout::Finish(const std::string& sample, int64_t tokens, bool early, std::string& err)
{
    const auto it = m_samples.find(sample);
    if (it == m_samples.end()) {
        err = DT_ROLLOUT_SAMPLE;
        return false;
    }
    if (tokens < static_cast<int64_t>(1)) {
        err = DT_ROLLOUT_LENGTH;
        return false;
    }
    if (it->second.done) {
        err = NIFDT_REPLAY;
        return false;
    }
    it->second.done = true;
    it->second.early = early;
    it->second.tokens = tokens;
    err.clear();
    return true;
}

bool DtRollout::Replenish(int64_t need, std::string& err)
{
    if (need < static_cast<int64_t>(1)) {
        err = DT_ROLLOUT_LENGTH;
        return false;
    }
    if (finished_count() < need) {
        err = DT_ROLLOUT_SHORT;
        return false;
    }
    m_replenished = true;
    err.clear();
    return true;
}

bool DtRollout::Seal(std::string& err)
{
    m_sealed = true;
    err.clear();
    return true;
}

bool DtRollout::SwitchGenerate(std::string& err)
{
    if (m_open && !m_sealed) {
        err = DT_ROLLOUT_MODE;
        return false;
    }
    m_generating = true;
    err.clear();
    return true;
}

bool DtRollout::has_sample(const std::string& sample) const
{
    return Find(sample) != nullptr;
}

uint64_t DtRollout::version_of(const std::string& sample) const
{
    const Sample* row = Find(sample);
    if (row == nullptr) return static_cast<uint64_t>(0);
    return row->version;
}

int64_t DtRollout::tokens_of(const std::string& sample) const
{
    const Sample* row = Find(sample);
    if (row == nullptr || !row->done) return static_cast<int64_t>(0);
    return row->tokens;
}

bool DtRollout::finished(const std::string& sample) const
{
    const Sample* row = Find(sample);
    return row != nullptr && row->done && !row->early;
}

bool DtRollout::is_short(const std::string& sample) const
{
    const Sample* row = Find(sample);
    return row != nullptr && row->done && row->early;
}

int64_t DtRollout::finished_count() const
{
    int64_t count = static_cast<int64_t>(0);
    for (const auto& item : m_samples) {
        if (item.second.done && !item.second.early) {
            count += static_cast<int64_t>(1);
        }
    }
    return count;
}

int64_t DtRollout::short_count() const
{
    int64_t count = static_cast<int64_t>(0);
    for (const auto& item : m_samples) {
        if (item.second.done && item.second.early) {
            count += static_cast<int64_t>(1);
        }
    }
    return count;
}

int64_t DtRollout::routed_count() const
{
    return static_cast<int64_t>(m_samples.size());
}

} // namespace modelnet
