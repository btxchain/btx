// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SIGCOVER_CODES_H
#define BITCOIN_MODELNET_SWARM_SIGCOVER_CODES_H

namespace modelnet {

/** Empty id on Cover, Preimage, or BindKey. Nothing is stored. */
inline constexpr char SWARM_SIGCOVER_SIGHASH[] = "SIGHASH";

/**
 * The sighash description does not cover outputs, or a key was offered.
 * A covered row stays covered. No key is stored.
 */
inline constexpr char SWARM_SIGCOVER_NOT_SIGNED[] = "NOT_SIGNED";

/** The same covered id, or the same 32-byte preimage description, was repeated. */
inline constexpr char SWARM_SIGCOVER_REPLAY[] = "REPLAY";

/** Preimage length is other than 32. Nothing is stored and a stored 32 stays. */
inline constexpr char SWARM_SIGCOVER_PREIMAGE[] = "PREIMAGE";

/** Claim stays refused. No atoms move and nothing is broadcast. */
inline constexpr char SWARM_SIGCOVER_UNQUALIFIED[] = "UNQUALIFIED";

/** Penalty stays refused. Nothing is stored and secp_penalty stays false. */
inline constexpr char SWARM_SIGCOVER_NOT_PENALTY[] = "NOT_PENALTY";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SIGCOVER_CODES_H
