// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOWFLOW_H
#define BTX_MODELNET_SWARM_NOTNOWFLOW_H

#include <string>

namespace modelnet {

/**
 * A local note about a workflow. workflow_id names the workflow.
 * want_launch asks this note to launch it.
 *
 * This note launches no workflow. launched and bytes_moved stay false
 * on every path.
 */
struct SwarmNotNoWflow {
    std::string workflow_id;
    bool want_launch{false};
};

/**
 * Outcome of noting a workflow. launched and bytes_moved stay false on
 * every path: this note launches no workflow.
 */
struct SwarmNotNoWflowResult {
    std::string code;
    bool launched{false};
    bool bytes_moved{false};
};

/**
 * Note a workflow without launching it.
 * Order, first match wins: an empty workflow_id is WORKFLOW.
 * want_launch is NOT_LAUNCHED.
 * Otherwise the note is NOTED and err is clear.
 * launched and bytes_moved stay false on every path. This note launches
 * no workflow.
 */
SwarmNotNoWflowResult SwarmNoteNotNoWflow(const SwarmNotNoWflow& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOWFLOW_H
