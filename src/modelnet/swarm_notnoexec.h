// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEXEC_H
#define BTX_MODELNET_SWARM_NOTNOEXEC_H

#include <string>

namespace modelnet {

/**
 * A local note about one sandbox. want_exec asks this note to launch
 * a process in that sandbox.
 *
 * This note launches no process. launched and bytes_moved stay false
 * on every path.
 */
struct SwarmNotNoExec {
    std::string sandbox_id;
    bool want_exec{false};
};

/**
 * Outcome of noting a sandbox. launched and bytes_moved stay false on
 * every path: this note launches no process.
 */
struct SwarmNotNoExecResult {
    std::string code;
    bool launched{false};
    bool bytes_moved{false};
};

/**
 * Note a sandbox without launching a process.
 * Order, first match wins: an empty sandbox_id is SANDBOX.
 * want_exec is NOT_LAUNCHED. Otherwise the note is NOTED and err
 * is clear. launched and bytes_moved stay false on every path. This
 * note launches no process.
 */
SwarmNotNoExecResult SwarmNoteNotNoExec(const SwarmNotNoExec& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEXEC_H
