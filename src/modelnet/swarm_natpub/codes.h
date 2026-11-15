// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NATPUB_CODES_H
#define BITCOIN_MODELNET_SWARM_NATPUB_CODES_H

namespace modelnet {

/** The endpoint is empty. Nothing is stored. */
inline constexpr char kSwarmNatPubEndpoint[] = "ENDPOINT";

/**
 * A non-empty endpoint was stored and left unpublished.
 * The call still returns false. published() stays false.
 */
inline constexpr char kSwarmNatPubHeld[] = "HELD";

/** A second Claim of an endpoint already stored. The first endpoint stays. */
inline constexpr char kSwarmNatPubReplay[] = "REPLAY";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NATPUB_CODES_H
