// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP28_GRP28_H
#define BITCOIN_MODELNET_GRP28_GRP28_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_economyclass/swarm_economyclass.h>
#include <modelnet/swarm_evalengine/engine.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Group 28. Node behaviors 8, 9, and 10.
 * A candidate is staged only by SwarmEvaluationEngine::Stage.
 * Adopt is a separate call on that engine.
 * PayWork keeps the economy HELD code. Settle stays unqualified.
 * qualified(), release_qualified(), and hardware_qualified() stay false.
 * hosts() and physical_hosts() stay 1. bytes_moved() stays 0.
 * automatic_spend() stays "0". Nothing is broadcast. No atoms move.
 */
class Grp28 {
public:
    bool OpenExperiment(const std::string& id, std::string& err);
    bool BindCandidate(const std::string& experiment, const std::string& candidate, std::string& err);
    bool CommitSuite(const std::string& experiment, const std::string& suite, std::string& err);
    bool Report(const std::string& experiment,
                const std::string& candidate,
                const std::string& author,
                const std::string& evaluator,
                const std::string& author_domain,
                const std::string& evaluator_domain,
                bool author_sees_holdout,
                bool safety_regression,
                bool broad_regression,
                std::string& err);
    bool Promote(const std::string& candidate, std::string& err);
    bool Stage(const std::string& channel, const std::string& candidate, const std::string& policy, std::string& err);
    bool Adopt(const std::string& channel, std::string& err);

    bool OpenChannel(const std::string& channel, const std::string& pool_a, const std::string& pool_b, std::string& err);
    bool PayWork(const std::string& pool, const std::string& work, const std::string& worker, std::string& err);
    bool Settle(std::string& err);
    bool Spend(std::string& err);

    bool promoted(const std::string& candidate) const { return m_eval.promoted(candidate); }
    std::string staged(const std::string& channel) const { return m_eval.staged(channel); }
    std::string active(const std::string& channel) const { return m_eval.active(channel); }
    std::size_t adoption_count(const std::string& channel) const { return m_eval.adoption_count(channel); }

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int hosts() const { return 1; }
    int physical_hosts() const { return 1; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    int64_t atoms_moved() const;
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    SwarmEvaluationEngine m_eval;
    SwarmEconomyClass m_economy;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_GRP28_GRP28_H
