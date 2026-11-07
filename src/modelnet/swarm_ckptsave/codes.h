// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTSAVE_CODES_H
#define BITCOIN_MODELNET_SWARM_CKPTSAVE_CODES_H

namespace modelnet {

/** Empty name. Nothing is stored. */
inline constexpr char kSwarmCkptSaveCheckpoint[] = "CHECKPOINT";

/** A second Request of a name already stored. The first request stays. */
inline constexpr char kSwarmCkptSaveReplay[] = "REPLAY";

/**
 * The name is stored and the save is refused.
 * saved() stays false.
 */
inline constexpr char kSwarmCkptSaveHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTSAVE_CODES_H
