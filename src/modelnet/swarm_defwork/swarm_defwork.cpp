// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_defwork/swarm_defwork.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>

namespace modelnet {

namespace {

bool KnownLevel(const std::string& level)
{
    return level == kSwarmDefWorkD0 || level == kSwarmDefWorkD1 || level == kSwarmDefWorkD2 ||
           level == kSwarmDefWorkD3 || level == kSwarmDefWorkD4;
}

bool Preauthorized(const std::string& level)
{
    return level == kSwarmDefWorkD0 || level == kSwarmDefWorkD1 || level == kSwarmDefWorkD2;
}

} // namespace

const SwarmDefWork::Action* SwarmDefWork::Find(const std::string& action_id) const
{
    const auto it = m_actions.find(action_id);
    if (it == m_actions.end()) {
        return nullptr;
    }
    return &it->second;
}

SwarmDefWork::Action* SwarmDefWork::Find(const std::string& action_id)
{
    const auto it = m_actions.find(action_id);
    if (it == m_actions.end()) {
        return nullptr;
    }
    return &it->second;
}

bool SwarmDefWork::Propose(const std::string& case_id, const std::string& action_id, const std::string& level, const std::string& asset, int64_t blast, std::string& err)
{
    if (case_id.empty() || action_id.empty() || asset.empty()) {
        err = kSwarmDefWorkAction;
        return false;
    }
    if (blast < 0) {
        err = kSwarmDefWorkBlast;
        return false;
    }
    if (!KnownLevel(level)) {
        err = kSwarmDefWorkLevel;
        return false;
    }
    if (level == kSwarmDefWorkD4) {
        err = kSwarmDefWorkRefused;
        return false;
    }
    if (Find(action_id) != nullptr) {
        err = kSwarmDefWorkReplay;
        return false;
    }

    Action record;
    record.case_id = case_id;
    record.level = level;
    record.asset = asset;
    record.blast = blast;
    m_actions.emplace(action_id, std::move(record));
    if (level == kSwarmDefWorkD3) {
        err = kSwarmDefWorkNeedApproval;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmDefWork::Approve(const std::string& case_id, const std::string& action_id, bool human, std::string& err)
{
    if (!human) {
        err = kSwarmDefWorkNeedApproval;
        return false;
    }
    Action* action = Find(action_id);
    if (action == nullptr || action->case_id != case_id) {
        err = kSwarmDefWorkAction;
        return false;
    }
    if (Preauthorized(action->level)) {
        err = kSwarmDefWorkReplay;
        return true;
    }
    if (action->level != kSwarmDefWorkD3) {
        err = kSwarmDefWorkRefused;
        return false;
    }
    if (action->approved) {
        err = kSwarmDefWorkReplay;
        return true;
    }
    action->approved = true;
    err.clear();
    return true;
}

bool SwarmDefWork::Execute(const std::string& case_id, const std::string& action_id, const std::string& asset, int64_t blast, std::string& err)
{
    if (m_ambiguous.find(action_id) != m_ambiguous.end()) {
        err = kSwarmDefWorkAmbiguous;
        return false;
    }
    Action* action = Find(action_id);
    if (action == nullptr) {
        err = kSwarmDefWorkAction;
        return false;
    }
    if (action->case_id != case_id || action->asset != asset || action->blast != blast) {
        err = kSwarmDefWorkPrecondition;
        return false;
    }
    if (action->level == kSwarmDefWorkD4) {
        err = kSwarmDefWorkRefused;
        return false;
    }
    if (action->level == kSwarmDefWorkD3 && !action->approved) {
        err = kSwarmDefWorkNeedApproval;
        return false;
    }
    if (action->receipt) {
        err = kSwarmDefWorkReplay;
        return false;
    }
    if (action->rolled_back) {
        err = kSwarmDefWorkRollback;
        return false;
    }
    action->receipt = true;
    err.clear();
    return true;
}

bool SwarmDefWork::Unknown(const std::string& action_id, std::string& err)
{
    m_ambiguous.insert(action_id);
    err = kSwarmDefWorkAmbiguous;
    return false;
}

bool SwarmDefWork::Rollback(const std::string& action_id, bool canary_ok, std::string& err)
{
    Action* action = Find(action_id);
    if (action == nullptr) {
        err = kSwarmDefWorkAction;
        return false;
    }
    if (action->rolled_back || !canary_ok) {
        action->rolled_back = true;
        err = kSwarmDefWorkRollback;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmDefWork::Retaliate(const std::string& target, std::string& err)
{
    // The target is ignored. Nothing is stored and nothing is erased.
    (void)target;
    err = kSwarmDefWorkOutOfScope;
    return false;
}

bool SwarmDefWork::proposed(const std::string& action_id) const
{
    return Find(action_id) != nullptr;
}

bool SwarmDefWork::approved(const std::string& action_id) const
{
    const Action* action = Find(action_id);
    return action != nullptr && action->approved;
}

bool SwarmDefWork::has_receipt(const std::string& action_id) const
{
    const Action* action = Find(action_id);
    return action != nullptr && action->receipt;
}

int64_t SwarmDefWork::receipt_count() const
{
    int64_t count = 0;
    for (const auto& entry : m_actions) {
        if (entry.second.receipt) {
            ++count;
        }
    }
    return count;
}

bool SwarmDefWork::rolled_back(const std::string& action_id) const
{
    const Action* action = Find(action_id);
    return action != nullptr && action->rolled_back;
}

bool SwarmDefWork::ambiguous(const std::string& action_id) const
{
    return m_ambiguous.find(action_id) != m_ambiguous.end();
}

std::string SwarmDefWork::asset_of(const std::string& action_id) const
{
    const Action* action = Find(action_id);
    if (action == nullptr) {
        return {};
    }
    return action->asset;
}

std::string SwarmDefWork::level_of(const std::string& action_id) const
{
    const Action* action = Find(action_id);
    if (action == nullptr) {
        return {};
    }
    return action->level;
}

int64_t SwarmDefWork::blast_of(const std::string& action_id) const
{
    const Action* action = Find(action_id);
    if (action == nullptr) {
        return 0;
    }
    return action->blast;
}

bool SwarmDefWork::launched() const
{
    return kSwarmDefWorkLaunched;
}

bool SwarmDefWork::gpu() const
{
    return kSwarmDefWorkGpu;
}

bool SwarmDefWork::broadcast() const
{
    return kSwarmDefWorkBroadcast;
}

bool SwarmDefWork::connected() const
{
    return kSwarmDefWorkConnected;
}

std::string SwarmDefWork::automatic_spend() const
{
    return std::string{kSwarmDefWorkAutomaticSpend};
}

int64_t SwarmDefWork::atoms_moved() const
{
    return kSwarmDefWorkAtomsMoved;
}

} // namespace modelnet
