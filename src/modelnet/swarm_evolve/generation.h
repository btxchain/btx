// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVOLVE_GENERATION_H
#define BITCOIN_MODELNET_SWARM_EVOLVE_GENERATION_H

#include <modelnet/swarm_evolve/experience.h>
#include <modelnet/swarm_evolve/graduate_gate.h>
#include <modelnet/swarm_evolve/invoice.h>
#include <modelnet/swarm_evolve/lineage_gate.h>
#include <modelnet/swarm_evolve/measure.h>
#include <modelnet/swarm_evolve/recover.h>
#include <modelnet/swarm_evolve/train_gate.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-process driver for two evolutionary generations.
 *
 * Experience stores public_trajectory and synthetic_trajectory only.
 * Train takes one IntegerTrainer step when the dataset size is 8 and
 * ReplayMatches is true, then a second call is REPLAY. Measure accepts
 * two distinct authors, two distinct domains, and a score spread within
 * 10000, without averaging the scores. Graduate refuses realm promotion.
 * Adopt makes the graduated id the next parent. Continue opens generation
 * 2 only after generation 1 is adopted. Pay records an invoice on the
 * earned counter. Recover drops the coordinator id.
 */
class SwarmGeneration {
public:
    SwarmGeneration(std::string subject, std::string baseline_parent, std::string coordinator_id);

    bool Experience(const std::string& kind, const std::string& body, std::string& err);
    bool Train(std::string& err);
    bool Measure(const SwarmEvolveScoreReport& report, std::string& err);
    bool Graduate(const SwarmEvolveGraduateRequest& request, std::string& err);
    bool Adopt(std::string& err);
    bool Average(const std::string& left, const std::string& right, std::string& err);
    bool Continue(std::string& err);
    bool Pay(int64_t atoms, std::string& err);
    bool Recover(std::string& err);

    int Index() const { return m_index; }
    std::size_t ExperienceSize() const { return m_experience.Size(); }
    const std::vector<SwarmEvolveExperienceItem>& ExperienceItems() const { return m_experience.Items(); }

    bool Trained() const { return m_train.Trained(); }
    uint64_t Step() const { return m_train.StepIndex(); }
    const std::string& StateHash() const { return m_train.StateHash(); }
    const IntegerState& State() const { return m_train.State(); }
    bool GpuRan() const { return m_train.GpuRan(); }

    bool MeasureAccepted() const { return m_measure.Accepted(); }
    const std::vector<int64_t>& Scores() const { return m_measure.Scores(); }

    bool Graduated() const { return m_graduate.Graduated(); }
    const std::string& GraduatedId() const { return m_graduate.Id(); }
    bool RealmPromoted() const { return m_graduate.RealmPromoted(); }
    bool ExactReplayAdmitted() const { return m_graduate.ExactReplayAdmitted(); }

    const std::string& Parent() const { return m_lineage.Parent(); }
    std::vector<std::string> Heads(const std::string& channel) const { return m_lineage.Heads(channel); }
    bool Adopted() const { return m_adopted; }

    int64_t EarnedAtoms() const { return m_invoice.Earned(); }
    const std::string& AutomaticSpend() const { return m_invoice.AutomaticSpend(); }
    bool Broadcast() const { return m_invoice.Broadcast(); }

    const std::string& CoordinatorId() const { return m_recover.CoordinatorId(); }
    int64_t BytesMoved() const { return m_recover.BytesMoved(); }
    bool Mined() const { return m_recover.Mined(); }

private:
    std::string m_subject;
    int m_index{1};
    bool m_adopted{false};
    std::string m_checkpoint_id;

    SwarmEvolveExperience m_experience;
    SwarmEvolveTrain m_train;
    SwarmEvolveMeasure m_measure;
    SwarmEvolveGraduate m_graduate;
    SwarmEvolveLineage m_lineage;
    SwarmEvolveInvoice m_invoice;
    SwarmEvolveRecover m_recover;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVOLVE_GENERATION_H
