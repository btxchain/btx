// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MINEHOLD_BOOK_H
#define BITCOIN_MODELNET_SWARM_MINEHOLD_BOOK_H

#include <modelnet/swarm_minehold/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Mine requests recorded by Request, keyed by name.
 * store refuses an empty name and a name already present.
 * A refused store leaves the first request in place.
 * There is no method that mines a record, moves bytes,
 * broadcasts, or marks the gpu busy.
 */
class SwarmMineHoldBook {
public:
    bool contains(const std::string& name) const;
    std::string name_of(const std::string& name) const;
    std::size_t size() const;

    /** True when any kept request is marked mined. None are. */
    bool mined() const;

    /** Sum of blocks on every kept request. Each request is built with 0. */
    int64_t blocks() const;

    /** Sum of bytes on every kept request. Each request is built with 0. */
    int64_t bytes_moved() const;

    /** True when any kept request is marked broadcast. None are. */
    bool broadcast() const;

    /** True when any kept request marks the gpu. None do. */
    bool gpu() const;

    /**
     * Record name.
     * Refuses an empty name and a name already present. On refusal the
     * book is unchanged.
     */
    bool store(const std::string& name);

private:
    std::map<std::string, SwarmMineHoldRecord> m_requests;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MINEHOLD_BOOK_H
