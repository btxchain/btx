// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/ext01/ext01.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/git_origin/git_origin.h>
#include <modelnet/git_attestation/git_attestation.h>
#include <modelnet/agent_lineage/agent_lineage.h>
#include <modelnet/agent_guard/agent_guard.h>
#include <modelnet/incident/incident.h>
#include <modelnet/realm_promotion/realm_promotion.h>
#include <modelnet/fleet_rollout/fleet_rollout.h>
#include <modelnet/git_remote/git_remote.h>
#include <modelnet/slice_source/slice_source.h>
#include <modelnet/slice_views/slice_views.h>
#include <modelnet/slice_replay/slice_replay.h>
#include <modelnet/slice_wan/slice_wan.h>
#include <modelnet/slice_qualify/slice_qualify.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Ext01::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }

    GitOrigin origin;
    if (!origin.Record("origin-a", std::string(64, 'a'), err)) {
        return false;
    }

    GitAttestation attestation;
    if (!attestation.Attest("tree-a", std::string(64, 'a'), err)) {
        return false;
    }

    AgentLineage lineage;
    if (!lineage.Line("agent-a", "agent-b", err)) {
        return false;
    }

    AgentGuard guard;
    if (!guard.Permit("guard-a", "permit-a", err) || guard.process_present()) {
        return false;
    }

    Incident incident;
    if (!incident.File("inc-a", "note-a", err) || incident.effect_sent()) {
        return false;
    }

    RealmPromotion promotion;
    if (!promotion.Propose("promo-a", "candidate-a", err) || promotion.qualified()) {
        return false;
    }

    FleetRollout rollout;
    if (!rollout.Start("roll-a", "staged-a", err) || rollout.launched()) {
        return false;
    }

    GitRemote remote;
    if (!remote.Add("origin-a", "https://example.invalid/repo", err)) {
        return false;
    }

    SliceSource source;
    if (!source.Pass(err)) {
        return false;
    }

    SliceViews views;
    if (!views.Pass(err)) {
        return false;
    }

    SliceReplay replay;
    if (!replay.Pass(err)) {
        return false;
    }

    SliceWan wan;
    if (!wan.Pass(err)) {
        return false;
    }

    SliceQualify qualify;
    if (qualify.Observe("journey-a", err) || err != "JOURNEY") {
        return false;
    }
    if (qualify.Observe("windows", err) || err != NIFDT_UNQUALIFIED) {
        return false;
    }
    if (qualify.Observe("macos", err) || err != NIFDT_UNQUALIFIED) {
        return false;
    }
    if (qualify.Observe("gpu", err) || err != NIFDT_UNQUALIFIED) {
        return false;
    }

    m_done = true;
    err.clear();
    return true;
}

bool Ext01::Hosts(int64_t n, std::string& err)
{
    if (n == static_cast<int64_t>(1)) {
        err.clear();
        return true;
    }
    err = "HOSTS";
    return false;
}

bool Ext01::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Ext01::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Ext01::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Ext01::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
