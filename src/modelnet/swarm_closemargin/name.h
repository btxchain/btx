// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOSEMARGIN_NAME_H
#define BITCOIN_MODELNET_SWARM_CLOSEMARGIN_NAME_H

#include <cstdint>

namespace modelnet {

/**
 * Copies a close-margin block count as the recorded request.
 * Only 160 is copied. Any other count copies nothing.
 * No payload bytes are copied.
 */
class SwarmCloseMarginHoldName {
public:
    int64_t copy(int64_t blocks) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOSEMARGIN_NAME_H
