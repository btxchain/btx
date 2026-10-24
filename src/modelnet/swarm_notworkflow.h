// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTWORKFLOW_H
#define BITCOIN_MODELNET_SWARM_NOTWORKFLOW_H

#include <string>

namespace modelnet {

/**
 * A local note about one workflow. want_complete asks this note to
 * complete the workflow.
 *
 * The workflow has not been run. completed stays false and passed stays
 * false on every path.
 */
struct SwarmNotWorkflow {
    std::string workflow_id;
    bool want_complete{false};
};

/**
 * Outcome of noting a workflow. completed stays false and passed stays
 * false: the workflow has not been run.
 */
struct SwarmNotWorkflowResult {
    std::string code;
    bool completed{false};
    bool passed{false};
};

/**
 * Note a workflow without running it. Order, first match wins: an empty
 * workflow_id is TASK. want_complete is NOT_RUN. Otherwise the note is
 * NOTED and err is cleared. completed stays false and passed stays false
 * on every path. The workflow has not been run.
 */
SwarmNotWorkflowResult SwarmNoteNotWorkflow(const SwarmNotWorkflow& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTWORKFLOW_H
