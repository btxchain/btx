// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GRADHOLD_BOOK_H
#define BITCOIN_MODELNET_SWARM_GRADHOLD_BOOK_H

#include <modelnet/swarm_gradhold/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Gradient updates recorded by Offer, keyed by update id.
 * store refuses an empty id and an id already present.
 * A refused store leaves the first update in place.
 * There is no method that exports a record, moves bytes, marks the
 * gpu busy, or marks the update launched.
 */
class SwarmGradHoldBook {
public:
    bool contains(const std::string& update_id) const;
    std::string update_id_of(const std::string& update_id) const;
    std::size_t size() const;

    /** True when any kept update is marked exported. None are. */
    bool exported() const;

    /** Sum of bytes on every kept update. Each update is built with 0. */
    int64_t bytes_moved() const;

    /** True when any kept update marks the gpu. None do. */
    bool gpu() const;

    /** True when any kept update is marked launched. None are. */
    bool launched() const;

    /**
     * Record update_id.
     * Refuses an empty id and an id already present. On refusal the
     * book is unchanged.
     */
    bool store(const std::string& update_id);

private:
    std::map<std::string, SwarmGradHoldRecord> m_updates;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GRADHOLD_BOOK_H
