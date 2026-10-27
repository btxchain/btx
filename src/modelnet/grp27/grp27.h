// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP27_GRP27_H
#define BITCOIN_MODELNET_GRP27_GRP27_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_evalengine/engine.h>
#include <modelnet/dt_sockagree/dt_sockagree.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Group 27. Node behaviors 5, 6, and 7 on one host.
 * Two ranks compare, descendants need independent evaluators, and a
 * self-grade is refused. This is not two hosts and not a GPU allreduce.
 *
 * Compare forwards to DtSockAgree::Compare. hosts() and physical_hosts()
 * stay 1. classification() is SIMULATION_NOT_HARDWARE_MEASUREMENT.
 * bytes_moved() stays 0 and does not read the compare object's byte count.
 *
 * Grade calls SwarmEvaluationEngine OpenExperiment, BindCandidate,
 * CommitSuite, then Report. A setup step that returns REPLAY keeps the
 * first record and Report still runs. author == evaluator surfaces SELF.
 * The same domain surfaces NOT_QUORUM. Promote is not called.
 *
 * qualified(), release_qualified(), and hardware_qualified() stay false
 * even when eval_qualified(candidate) is true. eval_qualified forwards
 * the evaluation engine. launched(), gpu(), and broadcast() stay false.
 * automatic_spend() stays "0".
 */
class Grp27 {
public:
    bool Compare(int64_t left, int64_t right, std::string& err);
    bool Grade(const std::string& experiment,
               const std::string& candidate,
               const std::string& author,
               const std::string& evaluator,
               const std::string& author_domain,
               const std::string& evaluator_domain,
               bool author_sees_holdout,
               bool safety_regression,
               bool broad_regression,
               std::string& err);

    bool agreed() const;
    bool eval_qualified(const std::string& candidate) const;
    std::string classification() const;

    bool Vendor(std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Spend(std::string& err);

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    DtSockAgree m_agree;
    SwarmEvaluationEngine m_eval;
};

} // namespace modelnet

#endif
