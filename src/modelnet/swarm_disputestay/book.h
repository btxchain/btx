// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISPUTESTAY_BOOK_H
#define BITCOIN_MODELNET_SWARM_DISPUTESTAY_BOOK_H

#include <modelnet/swarm_disputestay/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Disputes opened by Open, keyed by dispute id.
 * store refuses an empty id and an id already present.
 * A refused store leaves the first dispute in place.
 * There is no method that settles a record, adds atoms, moves bytes,
 * broadcasts, or mines.
 */
class SwarmDisputeStayBook {
public:
    bool contains(const std::string& dispute) const;
    std::string dispute_of(const std::string& dispute) const;
    std::size_t size() const;

    /** Atoms on one kept dispute, or 0 when the id is absent. */
    int64_t atoms_of(const std::string& dispute) const;

    /** True when any kept dispute is marked settled. None are. */
    bool settled() const;

    /** Sum of atoms on every kept dispute. Each dispute is built with 0. */
    int64_t atoms_moved() const;

    /** Sum of bytes on every kept dispute. Each dispute is built with 0. */
    int64_t bytes_moved() const;

    /** True when any kept dispute marks a broadcast. None do. */
    bool broadcast() const;

    /** True when any kept dispute is marked mined. None are. */
    bool mined() const;

    /**
     * Record dispute.
     * Refuses an empty id and an id already present. On refusal the
     * book is unchanged.
     */
    bool store(const std::string& dispute);

private:
    std::map<std::string, SwarmDisputeStayRecord> m_disputes;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISPUTESTAY_BOOK_H
