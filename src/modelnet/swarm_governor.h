// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_GOVERNOR_H
#define BTX_MODELNET_SWARM_GOVERNOR_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one node's worker request. node_id names the note.
 * idle_off, battery, thermal, and metered each ask this note to drain
 * workers. requested_workers is the count the note was asked to run.
 *
 * This note does not start workers. workers_running stays 0 on every
 * path. Nothing is launched. No hostnames or IPs are used.
 */
struct SwarmGovernor {
    std::string node_id;
    bool idle_off{false};
    bool battery{false};
    bool thermal{false};
    bool metered{false};
    int64_t requested_workers{0};
};

/**
 * Outcome of noting a worker request. workers_running stays 0 on every
 * path: this note does not start workers and nothing is launched.
 */
struct SwarmGovernorResult {
    int64_t workers_running{0};
    std::string code;
};

/**
 * Note a worker request without starting workers.
 * Order, first match wins: an empty node_id or requested_workers below
 * 0 is GOVERNOR. idle_off, battery, thermal, or metered is DRAIN: any
 * one of those drains the workers to zero. requested_workers above 0
 * is HELD and err is cleared. Otherwise the note is NOTED and err is
 * cleared. workers_running stays 0 on every path. This note does not
 * start workers and nothing is launched.
 */
SwarmGovernorResult SwarmNoteGovernor(const SwarmGovernor& governor, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_GOVERNOR_H
