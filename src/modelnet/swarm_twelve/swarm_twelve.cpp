// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_twelve/swarm_twelve.h>

#include <modelnet/swarm_decode/codes.h>
#include <modelnet/swarm_decode/names.h>
#include <modelnet/swarm_faultboard/codes.h>
#include <modelnet/swarm_generation/codes.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

const char* kPayHeld = "HELD";
const char* kFollow = "follow";
const char* kChannel = "chan";
const char* kRecipe = "recipe";
const char* kWeights = "weights";
const char* kNonce = "1";
const char* kNonceNext = "2";

} // namespace

bool SwarmTwelveRun::AcceptRefusal(bool ok, std::string& err, const char* code, const char* stage)
{
    if (ok) return true;
    if (err == code) {
        m_codes[stage] = code;
        return true;
    }
    return false;
}

void SwarmTwelveRun::Done(const char* stage)
{
    m_done.insert(stage);
}

bool SwarmTwelveRun::Run(const std::string& id, const std::string& payload, std::string& err)
{
    if (id.empty()) {
        err = kSwarmTwelveWork;
        return false;
    }
    if (payload.empty()) {
        err = kSwarmTwelvePayload;
        return false;
    }
    if (m_finished.find(id) != m_finished.end()) {
        err = kSwarmTwelveReplay;
        return false;
    }

    if (!Form(id, err)) return false;
    if (!Agent(payload, err)) return false;
    if (!Accelerate(id, payload, err)) return false;
    if (!ExperienceOf(id, err)) return false;
    if (!Train(err)) return false;
    if (!Descendants(id, err)) return false;
    if (!Evaluate(id, err)) return false;
    if (!Graduate(err)) return false;
    if (!AdoptHead(err)) return false;
    if (!Pay(id, err)) return false;
    if (!Fault(id, err)) return false;
    if (!Next(id, err)) return false;

    m_finished.insert(id);
    err.clear();
    return true;
}

bool SwarmTwelveRun::Form(const std::string& id, std::string& err)
{
    // The id is recorded here. No form plane is called and no file is written.
    m_formed.insert(id);
    err.clear();
    Done(kSwarmTwelveStageForm);
    return true;
}

bool SwarmTwelveRun::Agent(const std::string& payload, std::string& err)
{
    if (!m_allowed) {
        if (!m_agent.Allow("work/", err)) return false;
        m_allowed = true;
    }
    if (!m_agent.Execute("sha256", "work/job", payload, err)) return false;
    Done(kSwarmTwelveStageAgent);
    return true;
}

bool SwarmTwelveRun::Accelerate(const std::string& id, const std::string& payload, std::string& err)
{
    if (!m_decode.Open(id, kSwarmDecodeMemory, err)) return false;
    if (!m_decode.Prompt(id, payload, false, err)) return false;
    // Pull until the memory engine reports DONE. A production engine is not opened.
    while (m_decode.Pull(id, err)) {
    }
    if (err != kSwarmDecodeDone) return false;
    Done(kSwarmTwelveStageAccelerate);
    return true;
}

bool SwarmTwelveRun::ExperienceOf(const std::string& id, std::string& err)
{
    if (!m_experience.Store(id, "public_trajectory", 1000, err)) return false;
    m_experience.Enqueue();
    Done(kSwarmTwelveStageExperience);
    return true;
}

bool SwarmTwelveRun::Train(std::string& err)
{
    // One CPU integer step. GpuRun is not called.
    if (!m_cycle.Run(1, err)) return false;
    m_state_hash = m_cycle.state_hash();
    Done(kSwarmTwelveStageTrain);
    return true;
}

bool SwarmTwelveRun::Descendants(const std::string& id, std::string& err)
{
    // Produce stores a candidate from four non-empty fields. It does not read
    // the training attempt. Execute always returns ENGINE_ABSENT; that code is
    // kept and Produce still runs. Identify through SelectTask are the calls
    // that precede Execute on this engine, and each returns true for these
    // arguments. Promote, Stage, Adopt, and Continue are not required to store
    // the candidate.
    if (!m_generation.Identify(id, err)) return false;
    if (!m_generation.Propose(id, err)) return false;
    if (!m_generation.Eligible(true, true, err)) return false;
    if (!m_generation.Allocate(1, 0, err)) return false;
    if (!m_generation.SelectTask(id, true, err)) return false;
    if (!AcceptRefusal(m_generation.Execute(err), err, kSwarmGenerationEngineAbsent, kSwarmTwelveStageDescendants)) {
        return false;
    }
    if (!m_generation.Produce(id, kRecipe, kWeights, kNonce, err)) return false;
    m_candidate = m_generation.candidate_id();
    if (m_candidate.empty()) {
        err = kSwarmGenerationCandidate;
        return false;
    }
    Done(kSwarmTwelveStageDescendants);
    return true;
}

bool SwarmTwelveRun::Evaluate(const std::string& id, std::string& err)
{
    if (!m_eval.OpenExperiment(id, err)) return false;
    if (!m_eval.BindCandidate(id, m_candidate, err)) return false;
    if (!m_eval.CommitSuite(id, "suite", err)) return false;
    if (!m_eval.Report(id, m_candidate, "author", "eval-a", "author-domain", "lab-a", false, false, false, err)) {
        return false;
    }
    if (!m_eval.Report(id, m_candidate, "author", "eval-b", "author-domain", "lab-b", false, false, false, err)) {
        return false;
    }
    Done(kSwarmTwelveStageEvaluate);
    return true;
}

bool SwarmTwelveRun::Graduate(std::string& err)
{
    // Promote certifies the candidate on the evaluation engine.
    // Realm promotion and exact replay are left unset. passed() stays false.
    if (!m_eval.Promote(m_candidate, err)) return false;
    Done(kSwarmTwelveStageGraduate);
    return true;
}

bool SwarmTwelveRun::AdoptHead(std::string& err)
{
    if (!m_eval.Stage(kChannel, m_candidate, kFollow, err)) return false;
    if (!m_eval.Adopt(kChannel, err)) return false;
    m_adopted = true;
    Done(kSwarmTwelveStageAdopt);
    return true;
}

bool SwarmTwelveRun::Pay(const std::string& id, std::string& err)
{
    if (!m_economy_open) {
        if (!m_economy.Open("ch", "pool-a", "pool-b", err)) return false;
        m_economy_open = true;
    }
    // PayWork returns HELD. Settle is not called, so the route stays unqualified.
    if (!AcceptRefusal(m_economy.PayWork("pool-a", id, "worker", err), err, kPayHeld, kSwarmTwelveStagePay)) {
        return false;
    }
    Done(kSwarmTwelveStagePay);
    return true;
}

bool SwarmTwelveRun::Fault(const std::string& id, std::string& err)
{
    // The claim stays in this process. No hardware fault is injected.
    if (!m_fault.KeepClaim(id, "worker", err)) return false;
    if (!AcceptRefusal(m_fault.WorkerDisconnect(id, err), err, kSwarmFaultDisconnected, kSwarmTwelveStageFault)) {
        return false;
    }
    if (!AcceptRefusal(m_fault.CoordinatorGone(err), err, kSwarmFaultDurable, kSwarmTwelveStageFault)) {
        return false;
    }
    m_recovered = m_fault.has_claim(id);
    if (!m_recovered) return false;
    Done(kSwarmTwelveStageFault);
    return true;
}

bool SwarmTwelveRun::Next(const std::string& id, std::string& err)
{
    // Continue advances a parent only when a generation channel already has a
    // qualified active head, and it does not store a candidate. This walk does
    // not stage on the generation engine, so a second Produce with a different
    // nonce stores the next id.
    if (!m_generation.Produce(id, kRecipe, kWeights, kNonceNext, err)) return false;
    m_next = m_generation.candidate_id();
    if (m_candidate.empty() || m_next.empty() || m_candidate == m_next) {
        err = kSwarmGenerationCandidate;
        return false;
    }
    Done(kSwarmTwelveStageNext);
    return true;
}

std::string SwarmTwelveRun::digest() const
{
    return m_agent.result();
}

const std::string& SwarmTwelveRun::text() const
{
    return m_decode.text();
}

int64_t SwarmTwelveRun::tokens() const
{
    return m_decode.tokens();
}

int SwarmTwelveRun::reward_of(const std::string& id) const
{
    return m_experience.reward(id);
}

const std::string& SwarmTwelveRun::state_hash() const
{
    return m_state_hash;
}

uint64_t SwarmTwelveRun::steps() const
{
    return m_cycle.steps();
}

const std::string& SwarmTwelveRun::candidate_id() const
{
    return m_candidate;
}

const std::string& SwarmTwelveRun::next_candidate_id() const
{
    return m_next;
}

bool SwarmTwelveRun::qualified(const std::string& candidate) const
{
    return m_eval.qualified(candidate);
}

bool SwarmTwelveRun::qualified() const
{
    return m_economy.qualified();
}

bool SwarmTwelveRun::promoted() const
{
    return !m_candidate.empty() && m_eval.promoted(m_candidate);
}

bool SwarmTwelveRun::realm_promoted() const
{
    return m_eval.realm_promoted();
}

bool SwarmTwelveRun::passed() const
{
    return false;
}

bool SwarmTwelveRun::adopted() const
{
    return m_adopted;
}

bool SwarmTwelveRun::recovered() const
{
    return m_recovered;
}

bool SwarmTwelveRun::continued() const
{
    return !m_candidate.empty() && !m_next.empty() && m_candidate != m_next;
}

bool SwarmTwelveRun::stage_done(const std::string& name) const
{
    return m_done.find(name) != m_done.end();
}

const std::string& SwarmTwelveRun::stage_code(const std::string& name) const
{
    const auto found = m_codes.find(name);
    if (found == m_codes.end()) return m_blank;
    return found->second;
}

bool SwarmTwelveRun::gpu_passed() const
{
    return false;
}

bool SwarmTwelveRun::windows_passed() const
{
    return false;
}

bool SwarmTwelveRun::launched() const
{
    return false;
}

bool SwarmTwelveRun::gpu() const
{
    return false;
}

bool SwarmTwelveRun::broadcast() const
{
    return false;
}

bool SwarmTwelveRun::fault_hardware() const
{
    return false;
}

int64_t SwarmTwelveRun::atoms_moved() const
{
    return m_economy.atoms_moved();
}

std::string SwarmTwelveRun::automatic_spend() const
{
    return m_economy.automatic_spend();
}

} // namespace modelnet
