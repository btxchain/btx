// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_REPLAY_CHECK_REPLAY_CHECK_H
#define BITCOIN_MODELNET_REPLAY_CHECK_REPLAY_CHECK_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/training_integer.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Stored replay of the integer trainer.
 *
 * Run rejects steps below 1 with STEPS and does not call the trainer.
 * Otherwise it calls IntegerTrainer::Run and stores a copy of State().
 * Check calls IntegerTrainer::ReplayMatches on that stored copy.
 * A match returns true.
 *
 * Tamper sets the stored hash to "bad" and calls IntegerTrainer::CheckState
 * on that copy. The result is false with BTX035_ID_MISMATCH. The trainer's
 * own state is a different object from that copy.
 *
 * pairs() is IntegerDataset().size(), the frozen eight pairs.
 * Gpu returns NIFDT_ENGINE_ABSENT and does not change either state.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * qualified_v41(), qualified(), and release_qualified() stay false.
 * hosts() and physical_hosts() are 1. bytes_moved() is 0.
 * launched(), gpu(), and broadcast() stay false.
 * No socket and no process.
 */
class ReplayCheck {
public:
    bool Run(uint64_t steps, std::string& err);
    bool Check(std::string& err);
    bool Tamper(std::string& err);

    int64_t pairs() const;

    bool Gpu(std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);

    const IntegerState& State() const { return m_trainer.State(); }
    const IntegerState& Stored() const { return m_stored; }

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified_v41() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    int hosts() const { return 1; }
    int physical_hosts() const { return 1; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    IntegerTrainer m_trainer;
    IntegerState m_stored;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_REPLAY_CHECK_REPLAY_CHECK_H
