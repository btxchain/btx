// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRIVFAM_CODES_H
#define BITCOIN_MODELNET_SWARM_PRIVFAM_CODES_H

namespace modelnet {

/** family is empty. Nothing is stored. */
inline constexpr char kSwarmPrivFamFamily[] = "FAMILY";

/** private_flag is false. Nothing is stored. */
inline constexpr char kSwarmPrivFamPublic[] = "PUBLIC";

/** The family is already stored. The first privacy flag stays. */
inline constexpr char kSwarmPrivFamReplay[] = "REPLAY";

/** A stored private family is not published. */
inline constexpr char kSwarmPrivFamNotPublished[] = "NOT_PUBLISHED";

/** AddSeed holds the host. The DNS list stays empty. */
inline constexpr char kSwarmPrivFamHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRIVFAM_CODES_H
