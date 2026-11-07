// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTHREAD_H
#define BTX_MODELNET_SWARM_NOTNOTHREAD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about the CPU thread cap on one node. thread_count is
 * the requested thread count. want_train asks this note to train.
 *
 * CPU threads above 64 are capped. This note trains nothing. training
 * stays false, and applied_threads stays 0, on every path.
 */
struct SwarmNotNoThread {
    std::string node_id;
    int64_t thread_count{0};
    bool want_train{false};
};

/**
 * Outcome of noting a CPU thread cap. training stays false, and
 * applied_threads stays 0, on every path. CPU threads above 64 are
 * capped. This note trains nothing.
 */
struct SwarmNotNoThreadResult {
    std::string code;
    bool training{false};
    int64_t applied_threads{0};
};

/**
 * Note a CPU thread cap without training. Order, first match wins: an
 * empty node_id is NODE. If thread_count is greater than 64, the note
 * is CAPPED even when want_train is false. want_train is CAPPED.
 * Otherwise the note is NOTED and err is cleared. training stays false
 * and applied_threads stays 0 on every path. CPU threads above 64 are
 * capped, and this note trains nothing.
 */
SwarmNotNoThreadResult SwarmNoteNotNoThread(const SwarmNotNoThread& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTHREAD_H
