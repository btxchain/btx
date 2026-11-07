// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_H
#define BITCOIN_MODELNET_SWARM_GENERATION_H

#include <modelnet/swarm_generation/adoption.h>
#include <modelnet/swarm_generation/baseline.h>
#include <modelnet/swarm_generation/branch.h>
#include <modelnet/swarm_generation/certificate.h>
#include <modelnet/swarm_generation/challenger.h>
#include <modelnet/swarm_generation/channel.h>
#include <modelnet/swarm_generation/commitment.h>
#include <modelnet/swarm_generation/floor.h>
#include <modelnet/swarm_generation/frontier.h>
#include <modelnet/swarm_generation/lineage.h>
#include <modelnet/swarm_generation/negative.h>
#include <modelnet/swarm_generation/performance.h>
#include <modelnet/swarm_generation/population.h>
#include <modelnet/swarm_generation/rollback.h>
#include <modelnet/swarm_generation/specialist.h>
#include <modelnet/swarm_generation/strategy.h>
#include <modelnet/swarm_generation/training.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-memory evolutionary generation engine for one family.
 *
 * Identify stores a weakness. Propose puts an experiment on the frontier.
 * Eligible requires both a license and an operator grant. Allocate stores
 * an integer exploration share and does not rank niches. SelectTask stores
 * a granted task. Execute records a training attempt and does not start a
 * process. Produce stores a candidate id and does not write a file.
 * VerifyProvenance checks the parent. Evaluate stores independent reports
 * and qualifies only after two distinct evaluators and domains. KeepNegative
 * retains a result across promotion. Compare forks incompatible pairs and
 * does not average weights. Promote stores a certificate. KeepSpecialist
 * stores a specialist without replacing general/stable. Distribute does not
 * move bytes. Stage follow sets a channel's staged head. Adopt makes that
 * head active and remembers the previous head. Continue advances the parent
 * from an adopted qualified head.
 *
 * launched(), gpu(), broadcast(), realm_promoted(), and exact_replay_admitted()
 * stay false. bytes_moved() and atoms_moved() stay 0. automatic_spend() stays
 * "0". running() stays false. general_stable() stays "general/stable".
 */
class SwarmGenerationEngine {
public:
    bool Identify(const std::string& weakness, std::string& err);
    bool Propose(const std::string& experiment, std::string& err);
    bool Eligible(bool license_allows, bool operator_grant, std::string& err);
    bool Allocate(int slots, int exploration_percent, std::string& err);
    bool SelectTask(const std::string& task, bool data_grant, std::string& err);
    bool Execute(std::string& err);
    bool Produce(const std::string& parent, const std::string& recipe, const std::string& weights, const std::string& nonce, std::string& err);
    bool VerifyProvenance(const std::string& candidate_id, const std::string& parent, std::string& err);
    bool Evaluate(const std::string& candidate_id, const std::string& author, const std::string& evaluator,
                  const std::string& author_domain, const std::string& evaluator_domain, bool author_sees_holdout,
                  bool safety_regression, bool broad_regression, std::string& err);
    bool KeepNegative(const std::string& result, std::string& err);
    bool Compare(const std::string& left, const std::string& right, bool compatible, std::string& err);
    bool Promote(const std::string& candidate_id, std::string& err);
    bool KeepSpecialist(const std::string& name, const std::string& candidate_id, std::string& err);
    bool Distribute(const std::string& candidate_id, std::string& err);
    bool Stage(const std::string& channel, const std::string& candidate_id, const std::string& policy, std::string& err);
    bool Adopt(const std::string& channel, std::string& err);
    bool Continue(std::string& err);

    std::size_t weakness_count() const { return m_strategy.weakness_count(); }
    std::size_t proposal_count() const { return m_frontier.count(); }
    bool eligible() const { return m_strategy.eligible(); }
    int exploration_slots() const { return m_strategy.exploration_slots(); }
    std::size_t task_count() const { return m_strategy.task_count(); }
    std::size_t training_count() const { return m_training.count(); }
    bool running() const { return m_floor.running(); }
    const std::string& candidate_id() const { return m_population.last_id(); }
    bool verified(const std::string& candidate_id) const { return m_population.verified(candidate_id); }
    std::size_t report_count(const std::string& candidate_id) const { return m_commitment.count(candidate_id); }
    bool qualified(const std::string& candidate_id) const { return m_commitment.qualified(candidate_id); }
    std::size_t negative_count() const { return m_negatives.count(); }
    bool negative_kept(const std::string& result) const { return m_negatives.contains(result); }
    bool forked() const { return m_branches.forked(); }
    bool promoted(const std::string& candidate_id) const { return m_certificates.promoted(candidate_id); }
    std::size_t specialist_count() const { return m_specialists.count(); }
    const std::string& staged(const std::string& channel) const { return m_channels.staged(channel); }
    const std::string& active(const std::string& channel) const { return m_channels.active(channel); }
    std::size_t rollback_count() const { return m_rollbacks.count(); }
    int cycle() const { return m_lineage.cycle(); }
    const std::string& parent() const { return m_lineage.parent(); }
    const std::string& general_stable() const { return m_baseline.general_stable(); }
    bool launched() const { return m_floor.launched(); }
    bool gpu() const { return m_floor.gpu(); }
    int64_t bytes_moved() const { return m_floor.bytes_moved(); }
    int64_t atoms_moved() const { return m_floor.atoms_moved(); }
    const std::string& automatic_spend() const { return m_floor.automatic_spend(); }
    bool broadcast() const { return m_floor.broadcast(); }
    bool realm_promoted() const { return m_floor.realm_promoted(); }
    bool exact_replay_admitted() const { return m_floor.exact_replay_admitted(); }

private:
    SwarmGenerationLineage m_lineage;
    SwarmGenerationBaseline m_baseline;
    SwarmGenerationSpecialists m_specialists;
    SwarmGenerationBranches m_branches;
    SwarmGenerationFrontier m_frontier;
    SwarmGenerationPopulation m_population;
    SwarmGenerationCommitment m_commitment;
    SwarmGenerationPerformance m_performance;
    SwarmGenerationTraining m_training;
    SwarmGenerationNegatives m_negatives;
    SwarmGenerationStrategy m_strategy;
    SwarmGenerationChallengers m_challengers;
    SwarmGenerationCertificates m_certificates;
    SwarmGenerationChannels m_channels;
    SwarmGenerationAdoptions m_adoptions;
    SwarmGenerationRollbacks m_rollbacks;
    SwarmGenerationFloor m_floor;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_H
