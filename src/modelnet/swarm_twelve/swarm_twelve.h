// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TWELVE_H
#define BITCOIN_MODELNET_SWARM_TWELVE_H

#include <modelnet/swarm_agentexec/swarm_agentexec.h>
#include <modelnet/swarm_decode/swarm_decode_run.h>
#include <modelnet/swarm_economyclass/swarm_economyclass.h>
#include <modelnet/swarm_evalengine/engine.h>
#include <modelnet/swarm_experience/experience.h>
#include <modelnet/swarm_faultboard/swarm_faultboard.h>
#include <modelnet/swarm_generation/generation.h>
#include <modelnet/swarm_intcycle/swarm_intcycle.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>

namespace modelnet {

/** Empty id. No stage runs. */
inline constexpr char kSwarmTwelveWork[] = "WORK";

/** Empty payload. No stage runs. */
inline constexpr char kSwarmTwelvePayload[] = "PAYLOAD";

/** This id already finished all twelve stages. Side effects are not repeated. */
inline constexpr char kSwarmTwelveReplay[] = "REPLAY";

inline constexpr char kSwarmTwelveStageForm[] = "form";
inline constexpr char kSwarmTwelveStageAgent[] = "agent";
inline constexpr char kSwarmTwelveStageAccelerate[] = "accelerate";
inline constexpr char kSwarmTwelveStageExperience[] = "experience";
inline constexpr char kSwarmTwelveStageTrain[] = "train";
inline constexpr char kSwarmTwelveStageDescendants[] = "descendants";
inline constexpr char kSwarmTwelveStageEvaluate[] = "evaluate";
inline constexpr char kSwarmTwelveStageGraduate[] = "graduate";
inline constexpr char kSwarmTwelveStageAdopt[] = "adopt";
inline constexpr char kSwarmTwelveStagePay[] = "pay";
inline constexpr char kSwarmTwelveStageFault[] = "fault";
inline constexpr char kSwarmTwelveStageNext[] = "next";

/**
 * Twelve in-process swarm stages on the existing engines.
 *
 * form records the id in memory. agent hashes through SwarmAgentExec.
 * accelerate pulls a memory decode. experience stores a public_trajectory.
 * train takes one integer CPU step. descendants records ENGINE_ABSENT from
 * generation Execute, then Produce stores a candidate. evaluate, graduate,
 * and adopt use the evaluation engine. pay records HELD. fault keeps the
 * claim. next stores a second candidate with a different nonce.
 *
 * passed(), gpu_passed(), windows_passed(), launched(), gpu(), broadcast(),
 * and fault_hardware() stay false. automatic_spend() stays "0".
 * Settlement qualified() stays false. atoms_moved() stays 0.
 * realm_promoted() stays false.
 */
class SwarmTwelveRun {
public:
    /**
     * Walk form, agent, accelerate, experience, train, descendants,
     * evaluate, graduate, adopt, pay, fault, and next.
     * An empty id sets err to WORK and does nothing.
     * An empty payload sets err to PAYLOAD and does nothing.
     * An id that already finished sets err to REPLAY and does not repeat
     * side effects. A false engine result stops the walk, except the
     * recorded refusals ENGINE_ABSENT on generation Execute and HELD on
     * pay, and the fault refusals that leave the claim in place.
     */
    bool Run(const std::string& id, const std::string& payload, std::string& err);

    /** Digest stored by SwarmAgentExec. This class does not hash. */
    std::string digest() const;
    /** Decode text. At most the first 8 bytes of the public prompt. */
    const std::string& text() const;
    int64_t tokens() const;
    int reward_of(const std::string& id) const;
    const std::string& state_hash() const;
    uint64_t steps() const;
    const std::string& candidate_id() const;
    const std::string& next_candidate_id() const;

    /** Evaluation-engine qualification for one candidate. */
    bool qualified(const std::string& candidate) const;
    /** Settlement qualification. Stays false. */
    bool qualified() const;
    bool promoted() const;
    bool realm_promoted() const;
    bool passed() const;
    bool adopted() const;
    bool recovered() const;
    bool continued() const;
    bool stage_done(const std::string& name) const;
    const std::string& stage_code(const std::string& name) const;

    bool gpu_passed() const;
    bool windows_passed() const;
    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    bool fault_hardware() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;

private:
    bool Form(const std::string& id, std::string& err);
    bool Agent(const std::string& payload, std::string& err);
    bool Accelerate(const std::string& id, const std::string& payload, std::string& err);
    bool ExperienceOf(const std::string& id, std::string& err);
    bool Train(std::string& err);
    bool Descendants(const std::string& id, std::string& err);
    bool Evaluate(const std::string& id, std::string& err);
    bool Graduate(std::string& err);
    bool AdoptHead(std::string& err);
    bool Pay(const std::string& id, std::string& err);
    bool Fault(const std::string& id, std::string& err);
    bool Next(const std::string& id, std::string& err);

    /** A matching refusal is stored on the stage and the walk continues. */
    bool AcceptRefusal(bool ok, std::string& err, const char* code, const char* stage);
    void Done(const char* stage);

    SwarmAgentExec m_agent;
    SwarmDecodeRun m_decode;
    SwarmExperience m_experience;
    SwarmIntCycle m_cycle;
    SwarmGenerationEngine m_generation;
    SwarmEvaluationEngine m_eval;
    SwarmEconomyClass m_economy;
    SwarmFaultBoard m_fault;

    bool m_allowed{false};
    bool m_economy_open{false};
    bool m_adopted{false};
    bool m_recovered{false};
    std::string m_state_hash;
    std::string m_candidate;
    std::string m_next;
    std::string m_blank;
    std::set<std::string> m_formed;
    std::set<std::string> m_finished;
    std::set<std::string> m_done;
    std::map<std::string, std::string> m_codes;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TWELVE_H
