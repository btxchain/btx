// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NATPUB_H
#define BITCOIN_MODELNET_SWARM_NATPUB_H

#include <modelnet/swarm_natpub/book.h>
#include <modelnet/swarm_natpub/link.h>
#include <modelnet/swarm_natpub/quiet.h>
#include <modelnet/swarm_natpub/seeds.h>
#include <modelnet/swarm_natpub/shelf.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * NAT-publish plane.
 * A claimed endpoint is not published.
 *
 * Claim stores a non-empty endpoint and returns false with err HELD.
 * published() stays false. An empty endpoint is ENDPOINT and stores
 * nothing. A second Claim of the same endpoint is REPLAY and keeps
 * the first. published() stays false.
 *
 * connected() stays false. launched() stays false.
 * bytes_moved() stays 0. dns_seeds() stays empty.
 */
class SwarmNatPublish {
public:
    /**
     * Claim one endpoint.
     * An empty endpoint is ENDPOINT and stores nothing.
     * A non-empty endpoint is stored and the call returns false with err HELD.
     * A second Claim of the same endpoint is REPLAY and keeps the first.
     * published() stays false. ENDPOINT is decided before REPLAY.
     */
    bool Claim(const std::string& endpoint, std::string& err);

    /** True when Claim kept this endpoint. */
    bool claimed(const std::string& endpoint) const;

    /** The kept endpoint, or empty when it was not stored. */
    std::string stored_endpoint(const std::string& endpoint) const;

    /** Number of kept endpoints. */
    std::size_t claim_count() const;

    /** Stays false. A claimed endpoint is not published. */
    bool published() const;

    /** Stays false for every endpoint, including one that was claimed. */
    bool published(const std::string& endpoint) const;

    /** Stays empty. Claim does not record a seed. */
    const std::vector<std::string>& dns_seeds() const;

    /** Stays false. A claimed endpoint does not connect. */
    bool connected() const;

    /** Stays false for every endpoint, including one that was claimed. */
    bool connected(const std::string& endpoint) const;

    /** Stays 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays false. Nothing is launched. */
    bool launched() const;

private:
    SwarmNatPubBook m_book;
    SwarmNatPubShelf m_shelf;
    SwarmNatPubLink m_link;
    SwarmNatPubSeeds m_seeds;
    SwarmNatPubQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NATPUB_H
