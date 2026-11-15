// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REMEDY_CODES_H
#define BITCOIN_MODELNET_SWARM_REMEDY_CODES_H

namespace modelnet {

/** sequence below 1. Nothing is stored. */
inline constexpr char kSwarmRemedySequence[] = "SEQUENCE";
/** The same open, or the same member revoke, was already accepted. */
inline constexpr char kSwarmRemedyReplay[] = "REPLAY";
/** Supersede sequence did not advance. The stored revocation stays. */
inline constexpr char kSwarmRemedyStale[] = "STALE";
/** Read of a revoked member. The read is not recorded. */
inline constexpr char kSwarmRemedyNotRead[] = "NOT_READ";
/** Revoke or read was given an empty member. */
inline constexpr char kSwarmRemedyMember[] = "MEMBER";
/** Script hash or counterparty pubkey is empty or unusable. */
inline constexpr char kSwarmRemedyKey[] = "KEY";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REMEDY_CODES_H
