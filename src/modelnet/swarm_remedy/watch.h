// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REMEDY_WATCH_H
#define BITCOIN_MODELNET_SWARM_REMEDY_WATCH_H

#include <modelnet/swarm_paymesh.h>

namespace modelnet {

/**
 * Report a watched sequence. The revocation argument is const.
 * Watching a sequence does not release a secret.
 */
class SwarmRemedyWatch {
public:
    SwarmRemedyReport Observe(int observed_sequence, int latest_sequence, int height, int refund_height,
                              const SwarmRevocation& revocation) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REMEDY_WATCH_H
