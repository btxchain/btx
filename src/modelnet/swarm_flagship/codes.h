// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FLAGSHIP_CODES_H
#define BITCOIN_MODELNET_SWARM_FLAGSHIP_CODES_H

#include <string>

namespace modelnet {

/** The stage name is not one of the thirteen flagship stages. Nothing is stored. */
inline constexpr char kSwarmFlagshipStage[] = "STAGE";

/** The evidence id is empty. Nothing is stored. */
inline constexpr char kSwarmFlagshipEvidence[] = "EVIDENCE";

/** An earlier stage has no stored evidence. Nothing is stored. */
inline constexpr char kSwarmFlagshipOrder[] = "ORDER";

/** The same stage already holds this evidence id. The first id stays. */
inline constexpr char kSwarmFlagshipReplay[] = "REPLAY";

/** The same stage already holds a different evidence id. The first id stays. */
inline constexpr char kSwarmFlagshipConflict[] = "CONFLICT";

/**
 * A listed stage was asked to pass.
 * Recording evidence does not make this succeed.
 * passed(), gpu_passed(), windows_passed(), and pay_passed() stay false.
 */
inline constexpr char kSwarmFlagshipNotPassed[] = "NOT_PASSED";

inline bool SwarmFlagshipRefuse(std::string& err, const char* code)
{
    err = code;
    return false;
}

inline bool SwarmFlagshipAccept(std::string& err)
{
    err.clear();
    return true;
}

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FLAGSHIP_CODES_H
