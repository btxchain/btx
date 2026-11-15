// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GUESTHOLD_CODES_H
#define BITCOIN_MODELNET_SWARM_GUESTHOLD_CODES_H

namespace modelnet {

/** Empty name. Nothing is stored. */
inline constexpr char kSwarmGuestHoldGuest[] = "GUEST";

/** A second Check of a name already stored. The first check stays. */
inline constexpr char kSwarmGuestHoldReplay[] = "REPLAY";

/**
 * The name is stored and the check does not pass.
 * passed() stays false. logged_in() stays false.
 */
inline constexpr char kSwarmGuestHoldNotPassed[] = "NOT_PASSED";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GUESTHOLD_CODES_H
