// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ROUTEBOOK_CODES_H
#define BITCOIN_MODELNET_SWARM_ROUTEBOOK_CODES_H

namespace modelnet {

/** Empty route, empty hop, or a route that has no stored hops. Nothing is stored. */
inline constexpr char SWARM_ROUTEBOOK_ROUTE[] = "ROUTE";

/** cltv_expiry below 0 on a hop that is not already stored. Nothing is stored. */
inline constexpr char SWARM_ROUTEBOOK_EXPIRY[] = "EXPIRY";

/** The same route and hop were added again. The first expiry stays. */
inline constexpr char SWARM_ROUTEBOOK_REPLAY[] = "REPLAY";

/** upstream_delta is below hop_count times the close margin. The delta is not stored. */
inline constexpr char SWARM_ROUTEBOOK_SLACK[] = "SLACK";

/** preimage_len is other than 32. Nothing is claimed. */
inline constexpr char SWARM_ROUTEBOOK_PREIMAGE[] = "PREIMAGE";

/** A 32-byte hashlock length is not a settled route. */
inline constexpr char SWARM_ROUTEBOOK_NOT_ROUTE[] = "NOT_ROUTE";

/** The sighash description does not cover outputs. No covering description is stored. */
inline constexpr char SWARM_ROUTEBOOK_NOT_SIGNED[] = "NOT_SIGNED";

/** Claim stays refused. No atoms move and nothing is broadcast. */
inline constexpr char SWARM_ROUTEBOOK_UNQUALIFIED[] = "UNQUALIFIED";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ROUTEBOOK_CODES_H
