// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOSEMARGIN_BLANK_H
#define BITCOIN_MODELNET_SWARM_CLOSEMARGIN_BLANK_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Accepts a block count that can be recorded.
 * A count other than 160 is MARGIN. The caller stores nothing on that result.
 */
class SwarmCloseMarginHoldBlank {
public:
    bool accept(int64_t blocks, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOSEMARGIN_BLANK_H
