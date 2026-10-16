// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/capability_bridge.h>

#include <string>

namespace modelnet {
namespace {

bool GrantExpired(const LocalCapabilityGrant& grant, int64_t now_ms)
{
    return grant.expires_at_ms > 0 && now_ms > grant.expires_at_ms;
}

bool EffectListed(const LocalCapabilityGrant& grant, const std::string& effect)
{
    if (effect.empty() || !grant.json.isObject() || !grant.json.exists("effects") || !grant.json["effects"].isArray()) {
        return false;
    }
    for (const auto& entry : grant.json["effects"].getValues()) {
        if (entry.isStr() && entry.get_str() == effect) return true;
    }
    return false;
}

} // namespace

bool PermitFromGrant(const LocalCapabilityGrant& grant, const std::string& effect, const std::string& fingerprint,
                     int64_t now_ms, ActionPermit& out_permit, std::string& err)
{
    out_permit = ActionPermit{};
    // Research authority does not become a spend authority.
    if (ResearchMaySpend() || grant.grant_id.empty() || GrantExpired(grant, now_ms) || !EffectListed(grant, effect)) {
        err = "BTX035_PERMIT";
        return false;
    }

    static uint64_t next_permit = 0;
    out_permit.permit_id = grant.grant_id + "/" + std::to_string(++next_permit);
    out_permit.grant_id = grant.grant_id;
    out_permit.generation = 1;
    out_permit.effect = effect;
    out_permit.not_after_ms = grant.expires_at_ms > 0 ? grant.expires_at_ms : now_ms;
    out_permit.parameter_fingerprint = fingerprint;

    ActionGate gate;
    if (!gate.Issue(out_permit, err)) {
        out_permit = ActionPermit{};
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
