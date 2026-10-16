// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/action_authority.h>

#include <cctype>
#include <mutex>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

bool Fail(std::string& err, const char* code)
{
    err = code;
    return false;
}

bool NamesWalletSpend(const std::string& effect)
{
    std::string lower;
    lower.reserve(effect.size());
    for (unsigned char c : effect) {
        lower.push_back(static_cast<char>(std::tolower(c)));
    }
    return lower.find("wallet") != std::string::npos || lower.find("spend") != std::string::npos;
}

} // namespace

bool ResearchMaySpend()
{
    return false;
}

bool ActionGate::Issue(const ActionPermit& permit, std::string& err)
{
    if (permit.permit_id.empty() || permit.effect.empty() || permit.generation == 0) {
        return Fail(err, "BTX035_PERMIT");
    }
    // LocalCapabilityGrant is not a spend authority. ResearchMaySpend() is false.
    if (NamesWalletSpend(permit.effect)) {
        return Fail(err, "BTX035_PERMIT");
    }
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_permits.find(permit.permit_id) != m_permits.end()) {
        return Fail(err, "BTX035_PERMIT");
    }
    Issued row;
    row.permit = permit;
    m_permits.emplace(permit.permit_id, std::move(row));
    err.clear();
    return true;
}

bool ActionGate::Consume(const std::string& permit_id, const std::string& effect, uint64_t generation, int64_t now_ms,
                         const std::string& fingerprint, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_revoked) return Fail(err, "BTX035_REVOKED");
    if (m_paused) return Fail(err, "BTX035_PAUSED");
    auto it = m_permits.find(permit_id);
    if (it == m_permits.end()) return Fail(err, "BTX035_PERMIT");
    Issued& row = it->second;
    if (row.permit.effect != effect || row.permit.generation != generation ||
        row.permit.parameter_fingerprint != fingerprint) {
        return Fail(err, "BTX035_PERMIT");
    }
    if (row.consumed) return Fail(err, "BTX035_REPLAY");
    if (now_ms > row.permit.not_after_ms) return Fail(err, "BTX035_EXPIRED");
    row.consumed = true;
    err.clear();
    return true;
}

bool ActionGate::Attenuate(const std::vector<std::string>& parent_effects, const std::vector<std::string>& child_effects,
                           std::string& err) const
{
    if (child_effects.empty()) return Fail(err, "BTX035_ATTENUATE");
    const std::unordered_set<std::string> parent(parent_effects.begin(), parent_effects.end());
    for (const std::string& effect : child_effects) {
        // A child effect outside the parent, or any wallet-spend effect, is escalation.
        if (effect.empty() || parent.find(effect) == parent.end() || NamesWalletSpend(effect)) {
            return Fail(err, "BTX035_ATTENUATE");
        }
    }
    err.clear();
    return true;
}

void ActionGate::Pause()
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_paused = true;
}

void ActionGate::Resume()
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (!m_revoked) m_paused = false;
}

void ActionGate::Revoke()
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_revoked = true;
}

void ActionGate::CancelLogical(const std::string& op)
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_ops[op].logical_state = "CANCELLED";
}

void ActionGate::ReportPhysical(const std::string& op, const std::string& physical_state)
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_ops[op].physical_state = physical_state;
}

bool ActionGate::UnknownEffect(const std::string& op)
{
    std::lock_guard<std::mutex> lock(m_mu);
    Operation& row = m_ops[op];
    row.uncertainty = "UNKNOWN";
    return false;
}

OperationDisposition ActionGate::Disposition(const std::string& op) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_ops.find(op);
    if (it == m_ops.end()) return {};
    OperationDisposition out;
    out.logical_state = it->second.logical_state;
    out.physical_state = it->second.physical_state;
    out.uncertainty = it->second.uncertainty;
    return out;
}

} // namespace modelnet
