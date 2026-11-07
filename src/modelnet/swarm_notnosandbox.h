// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSANDBOX_H
#define BTX_MODELNET_SWARM_NOTNOSANDBOX_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note that a job might raise a sandbox.
 * want_raise asks this note to raise one.
 *
 * A sandbox raise request stays capped and moves no bytes. raised stays
 * false and bytes stays 0 on every path.
 */
struct SwarmNotNoSandbox {
    std::string job_id;
    bool want_raise{false};
};

/**
 * Outcome of noting that a sandbox raise request stays capped.
 * raised stays false and bytes stays 0 on every path.
 */
struct SwarmNotNoSandboxResult {
    std::string code;
    bool raised{false};
    int64_t bytes{0};
};

/**
 * Note that a sandbox raise request stays capped and moves no bytes.
 * Order, first match wins: an empty job_id is JOB. want_raise is CAPPED.
 * Otherwise the note is NOTED and err is cleared. raised stays false and
 * bytes stays 0 on every path.
 */
SwarmNotNoSandboxResult SwarmNoteNotNoSandbox(const SwarmNotNoSandbox& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSANDBOX_H
