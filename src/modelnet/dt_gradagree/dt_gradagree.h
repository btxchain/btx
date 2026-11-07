// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_GRADAGREE_DT_GRADAGREE_H
#define BITCOIN_MODELNET_DT_GRADAGREE_DT_GRADAGREE_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Local integer comparison. Slot counts are not a hardware measurement. */
inline constexpr char DT_GRADAGREE_CLASSIFICATION[] = "SIMULATION_NOT_HARDWARE_MEASUREMENT";

/** Rank other than 0 or 1. Nothing is stored. */
inline constexpr char DT_GRADAGREE_RANK[] = "RANK";

/** Fewer than two stored ranks. agreed() stays false. */
inline constexpr char DT_GRADAGREE_MISSING[] = "MISSING";

/** The two stored gradients differ. agreed() stays false. */
inline constexpr char DT_GRADAGREE_DISAGREE[] = "DISAGREE";

/** Agree already succeeded. agreed() stays true. */
inline constexpr char DT_GRADAGREE_UNCHANGED[] = "UNCHANGED";

/**
 * Local integer comparison of two ranks on one host (DT-SIM-006).
 *
 * Submit stores one int64 gradient for rank 0 or rank 1. Any other rank
 * is RANK and stores nothing. A second Submit of the same rank is
 * NIFDT_REPLAY and keeps the first value. submitted() counts stored ranks.
 *
 * Agree compares the two stored gradients. Fewer than two stored ranks is
 * MISSING and agreed() stays false. Differing values are DISAGREE and
 * agreed() stays false. Equal values return true and agreed() becomes true.
 * A second Agree after that success is UNCHANGED and agreed() stays true.
 *
 * Gpu returns false with NIFDT_ENGINE_ABSENT and does not change agreed().
 * This object does not run a GPU allreduce and does not represent two
 * physical hosts. hosts() and physical_hosts() stay 1.
 * classification() is DT_GRADAGREE_CLASSIFICATION.
 * hardware_qualified(), launched(), gpu(), and broadcast() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0.
 * No socket is opened.
 */
class DtGradAgree {
public:
    bool Submit(int64_t rank, int64_t value, std::string& err);
    bool Agree(std::string& err);
    bool Gpu(std::string& err);

    int64_t submitted() const;
    bool agreed() const { return m_agreed; }
    /** Stored gradient for rank 0 or 1, or 0 when that rank is absent. */
    int64_t gradient(int64_t rank) const;

    const char* classification() const { return DT_GRADAGREE_CLASSIFICATION; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    bool hardware_qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }

private:
    bool Slot(int64_t rank, int& slot) const;

    bool m_has[2]{false, false};
    int64_t m_value[2]{0, 0};
    bool m_agreed{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_GRADAGREE_DT_GRADAGREE_H
