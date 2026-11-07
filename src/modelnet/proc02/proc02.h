// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROC02_PROC02_H
#define BITCOIN_MODELNET_PROC02_PROC02_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_generation/generation.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Proc02. DS-LEARN-006. Two defensive research cycles on one engine.
 *
 * RunTwoCycles calls Identify, Propose, Eligible, Allocate, SelectTask,
 * Execute, Produce, VerifyProvenance, Evaluate, Promote, Stage, Adopt,
 * and Continue. Evaluate runs twice, with two evaluators and two domains,
 * so the candidate qualifies. After the first Continue succeeds, the same
 * sequence starts again at Identify. The second weakness, experiment, task,
 * recipe, weights, and candidate nonce use the suffix -c2. The second
 * Produce parent is the parent stored by the first Continue.
 *
 * Execute records the attempt and returns NIFDT_ENGINE_ABSENT. Produce
 * still stores the candidate. cycles() becomes 2 only after both Continue
 * calls succeed and each one advances the parent. A later RunTwoCycles
 * returns true and leaves cycles() at 2.
 *
 * passed(), release_qualified(), gpu_passed(), windows_passed(),
 * hardware_qualified(), and launched() stay false.
 * automatic_spend() returns NIFDT_AUTOMATIC_SPEND.
 * bytes_moved() stays 0.
 * This class opens no socket, starts no process, and calls no RPC,
 * wallet, or file.
 */
class Proc02 {
public:
    bool RunTwoCycles(std::string& err);
    int cycles() const { return m_cycles; }
    std::string parent_after() const { return m_parent; }

    bool passed() const { return false; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    bool launched() const { return false; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool Drive(const std::string& suffix, std::string& err);

    SwarmGenerationEngine m_engine;
    int m_cycles{0};
    std::string m_parent;
    bool m_attempted{false};
    std::string m_err;
};

} // namespace modelnet

#endif
