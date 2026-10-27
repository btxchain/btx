// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DESCENDANTS_CODES_H
#define BITCOIN_MODELNET_SWARM_DESCENDANTS_CODES_H

namespace modelnet {

/** Empty id, empty child, or an id this plane has not stored. */
inline constexpr char kDescendantLineage[] = "LINEAGE";

/** The id or the child is already stored. The first record stays. */
inline constexpr char kDescendantReplay[] = "REPLAY";

/** Fork names a parent this plane has not stored. */
inline constexpr char kDescendantParent[] = "PARENT";

/** Child id is the parent id. Nothing is stored. */
inline constexpr char kDescendantSelf[] = "SELF";

/** Incompatible child is stored as its own head. The parent head stays. */
inline constexpr char kDescendantFork[] = "FORK";

/** Average is refused. No head is replaced or merged. */
inline constexpr char kDescendantNotAveraged[] = "NOT_AVERAGED";

/** Channel is not general, coding, or research. Nothing is stored. */
inline constexpr char kDescendantNiche[] = "NICHE";

/** Author is empty or is the child. The score is not stored. */
inline constexpr char kDescendantNotScored[] = "NOT_SCORED";

/** The score is not independent. It is not stored. */
inline constexpr char kDescendantHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DESCENDANTS_CODES_H
