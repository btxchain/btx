// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sigcover/ledger.h>

#include <modelnet/swarm_sigcover/cover.h>
#include <modelnet/swarm_sigcover/limits.h>
#include <modelnet/swarm_sigcover/names.h>
#include <modelnet/swarm_sigcover/preimage.h>
#include <modelnet/swarm_sigcover/record.h>

#include <cstdint>
#include <string>
#include <utility>

namespace modelnet {

bool SwarmSigCoverLedger::Apply(const std::string& id, const SwarmSigCoverPlan& plan)
{
    if (!plan.accepted) {
        return false;
    }
    if (!plan.mark_covered && !plan.mark_preimage) {
        return false;
    }
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) {
        SwarmSigCoverRecord created;
        if (plan.mark_covered) {
            SwarmSigCoverCommitCover(created);
        }
        if (plan.mark_preimage) {
            SwarmSigCoverCommitPreimage(created);
        }
        m_rows.emplace(id, std::move(created));
        return true;
    }
    if (plan.mark_covered) {
        SwarmSigCoverCommitCover(it->second);
    }
    if (plan.mark_preimage) {
        SwarmSigCoverCommitPreimage(it->second);
    }
    return true;
}

bool SwarmSigCoverLedger::Cover(const std::string& id, bool covers_outputs, std::string& err)
{
    if (!SwarmSigCoverIdPresent(id, err)) {
        return false;
    }
    const SwarmSigCoverRecord* row = Find(id);
    const bool already_covered = row != nullptr && SwarmSigCoverRowCovered(*row);
    const SwarmSigCoverPlan plan = SwarmSigCoverPlanCover(already_covered, covers_outputs, err);
    if (!plan.accepted) {
        return false;
    }
    return Apply(id, plan);
}

bool SwarmSigCoverLedger::Preimage(const std::string& id, int64_t length, std::string& err)
{
    if (!SwarmSigCoverIdPresent(id, err)) {
        return false;
    }
    const SwarmSigCoverRecord* row = Find(id);
    const bool described = row != nullptr &&
                           SwarmSigCoverRowPreimageLen(*row) == static_cast<int>(kSwarmSigCoverPreimageLen);
    const SwarmSigCoverPlan plan = SwarmSigCoverPlanPreimage(described, length, err);
    if (!plan.accepted) {
        return false;
    }
    return Apply(id, plan);
}

bool SwarmSigCoverLedger::covered(const std::string& id) const
{
    const SwarmSigCoverRecord* row = Find(id);
    return row != nullptr && SwarmSigCoverRowCovered(*row);
}

int SwarmSigCoverLedger::preimage_len(const std::string& id) const
{
    const SwarmSigCoverRecord* row = Find(id);
    if (row == nullptr) {
        return kSwarmSigCoverPreimageAbsent;
    }
    return SwarmSigCoverRowPreimageLen(*row);
}

const SwarmSigCoverRecord* SwarmSigCoverLedger::Find(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) {
        return nullptr;
    }
    return &it->second;
}

} // namespace modelnet
