// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOSEMARGIN_BOOK_H
#define BITCOIN_MODELNET_SWARM_CLOSEMARGIN_BOOK_H

#include <modelnet/swarm_closemargin/record.h>

#include <cstddef>
#include <cstdint>
#include <map>

namespace modelnet {

/**
 * Shrink requests recorded by Shrink, keyed by block count.
 * store refuses a count other than 160 and a count already present.
 * A refused store leaves the first request in place.
 * There is no method that shrinks a record, moves bytes,
 * marks the gpu busy, marks the request launched, or marks it mined.
 */
class SwarmCloseMarginHoldBook {
public:
    bool contains(int64_t blocks) const;
    int64_t blocks_of(int64_t blocks) const;
    std::size_t size() const;

    /** True when any kept request is shrunk. None are. */
    bool shrunk() const;

    /** Sum of bytes on every kept request. Each request is built with 0. */
    int64_t bytes_moved() const;

    /** True when any kept request marks the gpu. None do. */
    bool gpu() const;

    /** True when any kept request is marked launched. None are. */
    bool launched() const;

    /** True when any kept request is marked mined. None are. */
    bool mined() const;

    /**
     * Record blocks.
     * Refuses a count other than 160 and a count already present. On
     * refusal the book is unchanged.
     */
    bool store(int64_t blocks);

private:
    std::map<int64_t, SwarmCloseMarginHoldRecord> m_requests;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOSEMARGIN_BOOK_H
