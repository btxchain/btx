// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PRIVATEOFF_H
#define BTX_MODELNET_SWARM_PRIVATEOFF_H

#include <string>

namespace modelnet {

/** Caller record for a private-prompt decision. Without a device file, private prompts stay off. */
struct SwarmPrivateOff {
    std::string node_id;
    bool no_device{false};
    bool want_enable{false};
};

/** Classification answer. enabled stays false on every path. */
struct SwarmPrivateOffResult {
    std::string code;
    bool enabled{false};
};

/**
 * Keeps private prompts off. enabled is false on every path.
 * Empty node_id is NODE. no_device is NOT_PRIVATE, including when want_enable
 * is false. want_enable is HELD. Otherwise the code is NOTED and err is cleared.
 */
SwarmPrivateOffResult SwarmKeepPrivateOff(const SwarmPrivateOff& node, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PRIVATEOFF_H
