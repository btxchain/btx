// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FALLBACK_H
#define BTX_MODELNET_SWARM_FALLBACK_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one fallback route. A fallback route is an extra
 * authorized peer outside the chosen neighborhood. peer_id is an opaque
 * id. authorized is whether the peer is authorized. inside_chosen is
 * whether the peer is already in the chosen set. rtt_ms is the
 * round-trip time in milliseconds. want_connect asks this note to connect.
 *
 * This note does not connect it and does not open a socket. connected and
 * socket_opened stay false on every path. No hostnames or IPs are used.
 */
struct SwarmFallback {
    std::string peer_id;
    bool authorized{false};
    bool inside_chosen{false};
    int64_t rtt_ms{0};
    bool want_connect{false};
};

/**
 * Outcome of noting a fallback route. connected and socket_opened stay
 * false: this note does not connect and does not open a socket.
 */
struct SwarmFallbackResult {
    bool connected{false};
    bool socket_opened{false};
    std::string code;
};

/**
 * Note a fallback route without connecting or opening a socket.
 * Order, first match wins: an empty peer_id or rtt_ms below 0 is
 * FALLBACK. !authorized is UNAUTHORIZED. That wins even when want_connect
 * is true. inside_chosen is NOT_FALLBACK. A peer already in the chosen
 * set is not a fallback. That wins even when want_connect is true.
 * want_connect is HELD and err is cleared. This note does not open a
 * socket. Otherwise the note is NOTED and err is cleared. authorized
 * true, inside_chosen false, rtt_ms 10, and want_connect false is NOTED.
 * connected and socket_opened stay false on every path. No hostnames or
 * IPs are used.
 */
SwarmFallbackResult SwarmNoteFallback(const SwarmFallback& fallback, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FALLBACK_H
