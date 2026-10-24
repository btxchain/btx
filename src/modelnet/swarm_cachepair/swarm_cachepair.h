// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_H

#include <modelnet/swarm_cachepair/book.h>
#include <modelnet/swarm_cachepair/quiet.h>
#include <modelnet/swarm_cachepair/roster.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Cache-pair plane.
 * A page with one member cannot be shared. A recorded pair still
 * moves no bytes and starts no process.
 *
 * Place stores a member on a page. An empty page is PAGE and stores
 * nothing. An empty member is MEMBER and stores nothing. PAGE is
 * decided before MEMBER. The same page and member again is REPLAY
 * and keeps the first placement. A different member on that page is
 * a new placement. A successful Place returns true and clears err.
 *
 * Share of an unknown page, including a page that was never stored
 * and an empty page, is PAGE and records nothing. Share of a page
 * with fewer than two distinct members is ALONE, records nothing,
 * and leaves bytes_moved() at 0. Share of a page with two or more
 * distinct members records that share once and returns true. A
 * second Share of that page is REPLAY and does not add another
 * record. A successful Share clears err.
 *
 * bytes_moved() stays 0. cuda_buffer() stays false. launched() stays
 * false.
 */
class SwarmCachePair {
public:
    bool Place(const std::string& page, const std::string& member, std::string& err);
    bool Share(const std::string& page, std::string& err);

    bool placed(const std::string& page, const std::string& member) const;
    std::size_t member_count(const std::string& page) const;
    std::size_t page_count() const;
    /** Distinct members on page, in sorted order. Empty when unknown. */
    std::vector<std::string> members(const std::string& page) const;

    bool shared(const std::string& page) const;
    std::size_t share_count() const;
    /**
     * Members captured by the Share that recorded page, in sorted
     * order. Empty when that page has no recorded share.
     */
    std::vector<std::string> shared_members(const std::string& page) const;

    int64_t bytes_moved() const;
    bool cuda_buffer() const;
    bool launched() const;

private:
    SwarmCachePairRoster m_roster;
    SwarmCachePairBook m_book;
    SwarmCachePairQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_H
