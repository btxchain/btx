// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NATPUB_RECORD_H
#define BITCOIN_MODELNET_SWARM_NATPUB_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One claimed endpoint.
 * The record holds the endpoint only. published stays false.
 * bytes_moved stays 0. connected stays false. launched stays false.
 * Make is the only writer of those fields. There is no setter
 * and no publish method.
 */
class SwarmNatPubRecord {
public:
    static SwarmNatPubRecord Make(const std::string& endpoint);

    const std::string& endpoint() const { return m_endpoint; }
    bool published() const { return m_published; }
    int64_t bytes_moved() const { return m_bytes_moved; }
    bool connected() const { return m_connected; }
    bool launched() const { return m_launched; }

private:
    std::string m_endpoint;
    bool m_published{false};
    int64_t m_bytes_moved{0};
    bool m_connected{false};
    bool m_launched{false};
};

/**
 * The endpoint is non-empty, the claim is unpublished, no bytes moved,
 * nothing connected, and nothing was launched.
 */
bool SwarmNatPubRecordUsable(const SwarmNatPubRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NATPUB_RECORD_H
