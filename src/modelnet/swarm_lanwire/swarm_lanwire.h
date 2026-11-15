// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LANWIRE_H
#define BITCOIN_MODELNET_SWARM_LANWIRE_H

#include <modelnet/swarm_lanwire/codes.h>
#include <modelnet/swarm_lanwire/limits.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One datagram on 127.0.0.1.
 *
 * Exchange sends one UDP datagram to the same 127.0.0.1 port it just
 * bound, receives that datagram, and compares the bytes. An empty payload
 * is PAYLOAD and opens no socket. On success, received() equals the
 * payload, packets() is 1, local_received() is true, and bytes_moved() is
 * the received size. The socket is closed before Exchange returns, including
 * when bind, send, receive, or the byte compare fails. A failed Exchange
 * does not change a previously stored payload.
 *
 * Wan returns false with NO_ROUTE. It does not create a socket and does
 * not invent an internet path. wan_received() stays false.
 *
 * Scan returns false with NOT_SCAN. It does not send.
 *
 * connected(), launched(), gpu(), and broadcast() stay false.
 * automatic_spend() returns "0".
 */
class SwarmLanWire {
public:
    bool Exchange(const std::vector<unsigned char>& payload, std::string& err);
    bool Wan(std::string& err);
    bool Scan(const std::string& prefix, std::string& err);

    const std::vector<unsigned char>& received() const;
    int64_t packets() const;
    bool local_received() const;
    bool wan_received() const;

    bool connected() const;
    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    std::string automatic_spend() const;
    int64_t bytes_moved() const;

private:
    std::vector<unsigned char> m_received;
    int64_t m_packets{kSwarmLanWirePacketsIdle};
    bool m_local_received{false};
    int64_t m_bytes_moved{kSwarmLanWireBytesIdle};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LANWIRE_H
