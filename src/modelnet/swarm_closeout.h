// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CLOSEOUT_H
#define BTX_MODELNET_SWARM_CLOSEOUT_H

#include <string>

namespace modelnet {

/**
 * Local close-out margin. The margin is 160 blocks and stays 160 blocks.
 * A shrink request does not change it. This class does not broadcast,
 * spend, spawn a child process, open a network connection, or use a
 * hostname or IP.
 */
class SwarmCloseOut {
public:
    /** Close margin in blocks. Always 160. */
    int margin() const;

    /**
     * requested == 160 clears err and returns true. requested < 1, or any
     * requested other than 160, sets err to MARGIN and returns false.
     * margin() stays 160 on every path.
     */
    bool Shrink(int requested, std::string& err);
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CLOSEOUT_H
