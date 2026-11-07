// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVWIRE_H
#define BITCOIN_MODELNET_SWARM_KVWIRE_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Local KV page wire.
 *
 * Transfer moves a page body across a socketpair. An empty body is PAGE
 * and moves nothing. A non-empty body is written in full to one end of
 * socketpair(AF_UNIX, SOCK_STREAM, 0, fds) and read from the other end
 * in a loop until every byte arrives or the read fails. Both fds are
 * closed before returning, including on failure. On success, received()
 * equals the body, bytes_moved() grows by body.size(), and err is clear.
 * A failed transfer leaves received() and bytes_moved() unchanged.
 * engine() is "local".
 *
 * Remote for "nixl", "mooncake", or "rdma" returns false with
 * ENGINE_ABSENT. It does not create a socket, does not change received(),
 * and does not increase bytes_moved(). Any other engine name is ENGINE
 * and also moves nothing.
 *
 * launched(), gpu(), broadcast(), and connected() stay false.
 * automatic_spend() returns "0". There is no method that sets those true.
 */
class SwarmKvWire {
public:
    bool Transfer(const std::vector<unsigned char>& body, std::string& err);
    bool Remote(const std::string& engine, std::string& err);

    const std::vector<unsigned char>& received() const;
    std::int64_t bytes_moved() const;
    std::string engine() const;
    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    bool connected() const;
    std::string automatic_spend() const;

private:
    std::vector<unsigned char> m_received;
    std::int64_t m_bytes_moved{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVWIRE_H
