// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_IDLEDRAIN_REASON_H
#define BITCOIN_MODELNET_SWARM_IDLEDRAIN_REASON_H

#include <string>

namespace modelnet {

/** Exact drain reason. Any other spelling is refused. */
inline constexpr char kSwarmIdleDrainBattery[] = "battery";

/** Exact drain reason. Any other spelling is refused. */
inline constexpr char kSwarmIdleDrainThermal[] = "thermal";

/** Exact drain reason. Any other spelling is refused. */
inline constexpr char kSwarmIdleDrainMetered[] = "metered";

/**
 * The three idle conditions that drain workers.
 * Matches only the exact strings battery, thermal, and metered.
 * A different case, a prefix, or a suffix does not match.
 */
class SwarmIdleDrainReason {
public:
    bool Matches(const std::string& reason) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_IDLEDRAIN_REASON_H
