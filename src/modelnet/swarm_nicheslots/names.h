// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NICHESLOTS_NAMES_H
#define BITCOIN_MODELNET_SWARM_NICHESLOTS_NAMES_H

#include <string>

namespace modelnet {

/**
 * True only for the exact names general, coding, and research.
 * Any other spelling, case, or surrounding space is not a niche.
 */
bool SwarmNicheSlotsKnown(const std::string& niche);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NICHESLOTS_NAMES_H
