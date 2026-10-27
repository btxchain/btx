// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CPUCAP_H
#define BTX_MODELNET_SWARM_CPUCAP_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note of a CPU thread request for one node. node_id names the
 * note. requested_threads is the count the note was asked to use.
 * want_launch asks this note to start those threads.
 *
 * launched stays false on every path. Nothing is started. No hostnames
 * or IPs are used.
 */
struct SwarmCpuCap {
    std::string node_id;
    int64_t requested_threads{0};
    bool want_launch{false};
};

/**
 * Outcome of noting a CPU thread request. launched stays false: this
 * note does not launch threads. Nothing is started. The cap is 64.
 * The minimum when a count is accepted is 1.
 */
struct SwarmCpuCapResult {
    int64_t threads_used{0};
    bool launched{false};
    std::string code;
};

/**
 * Note a CPU thread request without launching threads.
 * Order, first match wins: an empty node_id or requested_threads below
 * 1 is CPU. threads_used is 0, launched stays false, and err is CPU.
 * requested_threads above 64 is CAPPED. threads_used is 64, launched
 * stays false, and err is CAPPED. This wins even when want_launch is
 * true. The extra threads are not used.
 * want_launch is HELD. threads_used equals requested_threads, launched
 * stays false, and err is cleared. This note does not launch threads.
 * Otherwise the note is NOTED. threads_used equals requested_threads,
 * launched stays false, and err is cleared.
 * launched stays false on every path. Nothing is started. No hostnames
 * or IPs are used.
 */
SwarmCpuCapResult SwarmNoteCpuCap(const SwarmCpuCap& cap, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CPUCAP_H
