// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_cohort/dt_cohort.h>

namespace modelnet {

bool DtCohort::Admit(const std::string& member, const std::string& base, uint64_t epoch, std::string& err)
{
    (void)epoch;
    if (member.empty() || base.empty()) {
        err = "MEMBER";
        return false;
    }
    if (m_frozen) {
        err = "FROZEN";
        return false;
    }
    if (m_members.count(member)) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_members[member] = Member{base, false, 0};
    err.clear();
    return true;
}

bool DtCohort::Freeze(std::string& err)
{
    if (m_members.empty()) {
        err = "MEMBER";
        return false;
    }
    m_frozen = true;
    err.clear();
    return true;
}

bool DtCohort::OuterUpdate(const std::string& member, const std::string& base, int64_t delta, std::string& err)
{
    const auto it = m_members.find(member);
    if (it == m_members.end()) {
        err = "MEMBER";
        return false;
    }
    if (it->second.base != base) {
        err = "BASE";
        return false;
    }
    it->second.delta = delta;
    it->second.delta_set = true;
    err.clear();
    return true;
}

bool DtCohort::Commit(bool quorum, std::string& err)
{
    if (m_partition) {
        err = "PARTITION";
        return false;
    }
    if (!m_frozen) {
        err = "FROZEN";
        return false;
    }
    if (!quorum) {
        err = "QUORUM";
        return false;
    }
    int64_t sum = 0;
    int64_t n = 0;
    for (const auto& item : m_members) {
        if (!item.second.delta_set) {
            err = "MISSING";
            return false;
        }
        sum += item.second.delta;
        n += 1;
    }
    if (n < 1) {
        err = "MISSING";
        return false;
    }
    m_head = sum / n;
    m_head_count = 1;
    err.clear();
    return true;
}

bool DtCohort::Partition(std::string& err)
{
    m_partition = true;
    err.clear();
    return true;
}

} // namespace modelnet
