// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRIVFAM_KNOWN_H
#define BITCOIN_MODELNET_SWARM_PRIVFAM_KNOWN_H

#include <modelnet/swarm_privfam/roster.h>

#include <string>

namespace modelnet {

/**
 * True when family was stored by Offer.
 * An empty family is not known. A public refusal is not known, because
 * a public offer stores nothing.
 */
bool SwarmPrivFamKnown(const SwarmPrivFamRoster& roster, const std::string& family);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRIVFAM_KNOWN_H
