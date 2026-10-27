// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_CODES_H
#define BITCOIN_MODELNET_SWARM_CAPACT_CODES_H

namespace modelnet {

/** The capability name is empty. Nothing is stored and nothing is recorded. */
inline constexpr char kSwarmCapActCapability[] = "CAPABILITY";

/** The name is already granted, or the action is already recorded. The first one stays. */
inline constexpr char kSwarmCapActReplay[] = "REPLAY";

/** Act ran before that name was granted. Nothing is recorded. */
inline constexpr char kSwarmCapActNotActed[] = "NOT_ACTED";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_CODES_H
