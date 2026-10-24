// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOSIDECAR_H
#define BTX_MODELNET_SWARM_NOSIDECAR_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_exec asks this note to exec
 * btx-swarmd or btx-paynetd.
 *
 * btxd does not exec btx-swarmd or btx-paynetd. launched stays false
 * on every path.
 */
struct SwarmNoSidecar {
    std::string node_id;
    bool want_exec{false};
};

/**
 * Outcome of noting a node. launched stays false on every path:
 * a note is recorded and btxd does not exec btx-swarmd or btx-paynetd.
 */
struct SwarmNoSidecarResult {
    std::string code;
    bool launched{false};
};

/**
 * Note a node without launching a sidecar.
 * Order, first match wins: an empty node_id is SIDECAR.
 * want_exec is NOT_LAUNCHED. Otherwise the note is NOTED and err is clear.
 * launched stays false on every path. btxd does not exec btx-swarmd or
 * btx-paynetd.
 */
SwarmNoSidecarResult SwarmNoteNoSidecar(const SwarmNoSidecar& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOSIDECAR_H
