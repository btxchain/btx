// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCHEDWITNESS_CODES_H
#define BITCOIN_MODELNET_SWARM_SCHEDWITNESS_CODES_H

namespace modelnet {

/** Empty witness. Nothing is stored. */
inline constexpr char kSwarmSchedWitnessWitness[] = "WITNESS";

/** A second Sign of a witness already stored. The first witness stays. */
inline constexpr char kSwarmSchedWitnessReplay[] = "REPLAY";

/**
 * The witness is stored and the signature is refused.
 * signed_ok() stays false.
 */
inline constexpr char kSwarmSchedWitnessNotSigned[] = "NOT_SIGNED";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCHEDWITNESS_CODES_H
