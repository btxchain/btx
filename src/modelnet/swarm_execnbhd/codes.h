// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXECNBHD_CODES_H
#define BITCOIN_MODELNET_SWARM_EXECNBHD_CODES_H

#include <string>

namespace modelnet {

/** Empty peer id. Nothing is stored. */
inline constexpr char SWARM_EXECNBHD_PEER[] = "PEER";

/** rtt_ms is below 0. Nothing is stored. */
inline constexpr char SWARM_EXECNBHD_RTT[] = "RTT";

/** Empty trust-domain id. Nothing is stored. */
inline constexpr char SWARM_EXECNBHD_DOMAIN[] = "DOMAIN";

/** The peer is not authorized. Nothing is stored. */
inline constexpr char SWARM_EXECNBHD_NOT_AUTHORIZED[] = "NOT_AUTHORIZED";

/** The peer is not compatible, or two seated peers are in different trust domains. */
inline constexpr char SWARM_EXECNBHD_NOT_COMPAT[] = "NOT_COMPAT";

/** The same peer id, or the same neighborhood id, was presented again. The first stays. */
inline constexpr char SWARM_EXECNBHD_REPLAY[] = "REPLAY";

/** Fallback cannot connect. The peer is not stored and not seated by this call. */
inline constexpr char SWARM_EXECNBHD_NOT_CONNECTED[] = "NOT_CONNECTED";

/** The peer is unknown or is not seated. No page is shared. */
inline constexpr char SWARM_EXECNBHD_NOT_SEATED[] = "NOT_SEATED";

/** Empty neighborhood id. Nothing is stored. */
inline constexpr char SWARM_EXECNBHD_NEIGHBORHOOD[] = "NEIGHBORHOOD";

/** A different neighborhood id was presented. The first id stays. */
inline constexpr char SWARM_EXECNBHD_HELD[] = "HELD";

inline bool SwarmExecNbhdRefuse(std::string& err, const char* code)
{
    err = code;
    return false;
}

inline bool SwarmExecNbhdAccept(std::string& err)
{
    err.clear();
    return true;
}

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXECNBHD_CODES_H
