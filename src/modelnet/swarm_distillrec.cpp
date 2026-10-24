// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_distillrec.h>

#include <utility>

namespace modelnet {

bool SwarmDistillRec::Record(const std::string& child, const std::string& teacher, const std::string& digest, std::string& err)
{
    if (child.empty() || teacher.empty() || digest.empty()) {
        err = "DISTILL";
        return false;
    }
    if (child == teacher) {
        err = "SELF";
        return false;
    }
    if (m_records.find(child) != m_records.end()) {
        err = "REPLAY";
        return false;
    }
    Row row;
    row.teacher = teacher;
    row.digest = digest;
    m_records.emplace(child, std::move(row));
    err.clear();
    return true;
}

bool SwarmDistillRec::Merge(const std::string& left, const std::string& right, std::string& err)
{
    (void)left;
    (void)right;
    err = "NOT_MERGED";
    return false;
}

bool SwarmDistillRec::Has(const std::string& child) const
{
    return m_records.find(child) != m_records.end();
}

} // namespace modelnet
