// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_SCHEDSIM_DT_SCHEDSIM_H
#define BITCOIN_MODELNET_DT_SCHEDSIM_DT_SCHEDSIM_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <set>
#include <string>

namespace modelnet {

/** Modeled schedule. Slot counts are not a hardware measurement. */
inline constexpr char DT_SCHEDSIM_CLASSIFICATION[] = "SIMULATION_NOT_HARDWARE_MEASUREMENT";

/** microbatches or stages is below 1. Nothing is stored. */
inline constexpr char DT_SCHEDSIM_SHAPE[] = "SHAPE";

/** The previous stage of this microbatch is not ready. The slot stays uncounted. */
inline constexpr char DT_SCHEDSIM_DEPENDENCY[] = "DEPENDENCY";

/**
 * Integer pipeline schedule. Bubble results are slot counts.
 *
 * Plan stores microbatches and stages when both are at least 1. Either
 * value below 1 is SHAPE and stores nothing. A product that does not fit
 * in int64 is SHAPE and stores nothing.
 *
 * bubbles_gpipe() is (stages - 1) * microbatches. bubbles_1f1b() is
 * (stages - 1). Both stay 0 until a Plan succeeds. A later rejected Plan
 * leaves the stored counts in place.
 *
 * Plan records one dependency from the forward of microbatch i on stage s
 * to stage s + 1 for every in-range microbatch and every stage that has a
 * successor. dependencies() is that edge count.
 *
 * Forward marks slot (microbatch, stage) ready. Stage 0 has no previous
 * stage. A later stage whose previous stage for that same microbatch is
 * missing returns DEPENDENCY and does not count the slot as ready.
 * Indexes are 0-based and stay inside the stored plan. An index outside
 * that plan is SHAPE and stores nothing.
 *
 * DualPipe returns false with NIFDT_ENGINE_ABSENT. Bubble counts stay as
 * they were. classification() is DT_SCHEDSIM_CLASSIFICATION.
 * hardware_qualified(), launched(), gpu(), and broadcast() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 */
class DtSchedSim {
public:
    bool Plan(int64_t microbatches, int64_t stages, std::string& err);
    bool Forward(int64_t microbatch, int64_t stage, std::string& err);
    bool DualPipe(std::string& err);

    int64_t bubbles_gpipe() const { return m_bubbles_gpipe; }
    int64_t bubbles_1f1b() const { return m_bubbles_1f1b; }
    int64_t dependencies() const { return m_dependencies; }
    int64_t ready_slots() const { return static_cast<int64_t>(m_ready.size()); }
    int64_t microbatches() const { return m_microbatches; }
    int64_t stages() const { return m_stages; }

    bool slot_ready(int64_t microbatch, int64_t stage) const;
    /** True when Plan recorded an edge from this forward to the next stage. */
    bool dependency_to_next(int64_t microbatch, int64_t stage) const;

    const char* classification() const { return DT_SCHEDSIM_CLASSIFICATION; }
    bool hardware_qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Slot {
        int64_t microbatch{0};
        int64_t stage{0};
        bool operator<(const Slot& other) const
        {
            if (microbatch != other.microbatch) return microbatch < other.microbatch;
            return stage < other.stage;
        }
    };

    bool InPlan(int64_t microbatch, int64_t stage) const;

    int64_t m_microbatches{0};
    int64_t m_stages{0};
    int64_t m_bubbles_gpipe{0};
    int64_t m_bubbles_1f1b{0};
    int64_t m_dependencies{0};
    bool m_planned{false};
    std::set<Slot> m_ready;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_SCHEDSIM_DT_SCHEDSIM_H
