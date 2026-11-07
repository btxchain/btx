// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_MAXSTEPS_H
#define BTX_MODELNET_SWARM_MAXSTEPS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note of a maximum step count for one node. node_id names the
 * note. max_steps is the count the note was asked to allow. want_train
 * asks this note to start training.
 *
 * training stays false on every path. This note does not start training.
 * Zero max steps means training stays off. No hostnames or IPs are used.
 */
struct SwarmMaxSteps {
    std::string node_id;
    int64_t max_steps{0};
    bool want_train{false};
};

/**
 * Outcome of noting a maximum step count. training stays false: this
 * note does not start training. Zero max steps means training stays off.
 */
struct SwarmMaxStepsResult {
    std::string code;
    bool training{false};
};

/**
 * Note a maximum step count without starting training.
 * Order, first match wins: an empty node_id or max_steps below 0 is
 * STEPS. training stays false and err is STEPS. max_steps of 0 is
 * CPU_ONLY. training stays false and err is CPU_ONLY. This wins even
 * when want_train is true. Zero max steps means training stays off.
 * want_train is HELD. training stays false and err is cleared. This
 * note does not start training. Otherwise the note is NOTED. training
 * stays false and err is cleared.
 * training stays false on every path. No hostnames or IPs are used.
 */
SwarmMaxStepsResult SwarmNoteMaxSteps(const SwarmMaxSteps& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_MAXSTEPS_H
