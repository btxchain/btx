// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REMEDY_SUPERSEDE_H
#define BITCOIN_MODELNET_SWARM_REMEDY_SUPERSEDE_H

#include <modelnet/swarm_paymesh.h>

#include <string>

namespace modelnet {

/**
 * Build the next revocation and hand the current one to SwarmSupersede.
 * A sequence that does not advance is STALE. prior_out and next_out are
 * written only after SwarmSupersede accepts the pair. released is whatever
 * SwarmSupersede left on the prior. This step does not assign it true.
 */
class SwarmRemedySupersede {
public:
    bool Apply(const SwarmRevocation& current, int sequence, unsigned char fill, SwarmRevocation& prior_out,
               SwarmRevocation& next_out, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REMEDY_SUPERSEDE_H
