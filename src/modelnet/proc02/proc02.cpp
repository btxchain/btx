// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/proc02/proc02.h>

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_generation/codes.h>
#include <modelnet/swarm_generation/generation.h>

#include <string>

namespace modelnet {

bool Proc02::RunTwoCycles(std::string& err)
{
    if (m_cycles == 2) {
        err.clear();
        return true;
    }
    if (m_attempted) {
        err = m_err;
        return false;
    }
    m_attempted = true;
    if (!Drive("", err) || m_cycles != 1) {
        if (err.empty()) err = NIFDT_UNQUALIFIED;
        m_err = err;
        return false;
    }
    if (!Drive("-c2", err) || m_cycles != 2) {
        if (err.empty()) err = NIFDT_UNQUALIFIED;
        m_err = err;
        return false;
    }
    err.clear();
    m_err.clear();
    return true;
}

bool Proc02::Drive(const std::string& suffix, std::string& err)
{
    const std::string weakness = std::string("slow-decode") + suffix;
    const std::string experiment = std::string("try-recipe") + suffix;
    const std::string task = std::string("try-recipe") + suffix;
    if (!m_engine.Identify(weakness, err)) return false;
    if (!m_engine.Propose(experiment, err)) return false;
    if (!m_engine.Eligible(true, true, err)) return false;
    if (!m_engine.Allocate(8, 25, err)) return false;
    if (!m_engine.SelectTask(task, true, err)) return false;
    // The attempt is stored. The trainer stays absent, and Produce still runs.
    if (!m_engine.Execute(err) && err != NIFDT_ENGINE_ABSENT) return false;

    const std::string produce_parent = suffix.empty() ? std::string("base-parent") : m_engine.parent();
    const std::string recipe = std::string("recipe") + suffix;
    const std::string weights = std::string("weights") + suffix;
    const std::string nonce = std::string("candidate") + suffix;
    if (!m_engine.Produce(produce_parent, recipe, weights, nonce, err)) return false;
    const std::string id = m_engine.candidate_id();
    if (id.empty() || (!m_parent.empty() && id == m_parent)) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (!m_engine.VerifyProvenance(id, produce_parent, err)) return false;
    if (!m_engine.Evaluate(id, "ada", "bea", "train", "vision", false, false, false, err)) return false;
    if (!m_engine.Evaluate(id, "ada", "cy", "train", "audio", false, false, false, err)) return false;
    if (!m_engine.Promote(id, err)) return false;
    if (!m_engine.Stage(kSwarmGenerationCodeStable, id, kSwarmGenerationFollow, err)) return false;
    if (!m_engine.Adopt(kSwarmGenerationCodeStable, err)) return false;

    const int cycle_before = m_engine.cycle();
    const std::string parent_before = m_engine.parent();
    if (!m_engine.Continue(err)) return false;
    if (m_engine.cycle() != cycle_before + 1 || m_engine.parent().empty() || m_engine.parent() == parent_before ||
        m_engine.parent() != id) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    m_parent = m_engine.parent();
    m_cycles = m_engine.cycle();
    return true;
}

} // namespace modelnet
