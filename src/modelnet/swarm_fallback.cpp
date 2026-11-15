// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fallback.h>

#include <cstdint>

namespace modelnet {

SwarmFallbackResult SwarmNoteFallback(const SwarmFallback& fallback, std::string& err)
{
    SwarmFallbackResult result;
    result.connected = false;
    result.socket_opened = false;
    if (fallback.peer_id.empty() || fallback.rtt_ms < 0) {
        result.code = "FALLBACK";
        result.connected = false;
        result.socket_opened = false;
        err = "FALLBACK";
        return result;
    }
    // UNAUTHORIZED wins even when want_connect is true. This note does
    // not open a socket.
    if (!fallback.authorized) {
        result.code = "UNAUTHORIZED";
        result.connected = false;
        result.socket_opened = false;
        err = "UNAUTHORIZED";
        return result;
    }
    // NOT_FALLBACK wins even when want_connect is true. A peer already
    // in the chosen set is not a fallback. This note does not open a socket.
    if (fallback.inside_chosen) {
        result.code = "NOT_FALLBACK";
        result.connected = false;
        result.socket_opened = false;
        err = "NOT_FALLBACK";
        return result;
    }
    // This note does not open a socket.
    if (fallback.want_connect) {
        result.code = "HELD";
        result.connected = false;
        result.socket_opened = false;
        err.clear();
        return result;
    }
    // authorized true, inside_chosen false, rtt_ms 10, and want_connect
    // false is NOTED.
    result.code = "NOTED";
    result.connected = false;
    result.socket_opened = false;
    err.clear();
    return result;
}

} // namespace modelnet
