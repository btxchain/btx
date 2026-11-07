// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FSDPHOLD_BOOK_H
#define BITCOIN_MODELNET_SWARM_FSDPHOLD_BOOK_H

#include <modelnet/swarm_fsdphold/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * FSDP run requests recorded by Request, keyed by name.
 * store refuses an empty name and a name already present.
 * A refused store leaves the first request in place.
 * There is no method that runs a record, moves bytes,
 * marks the gpu busy, or marks the request launched.
 */
class SwarmFsdpHoldBook {
public:
    bool contains(const std::string& name) const;
    std::string name_of(const std::string& name) const;
    std::size_t size() const;

    /** True when any kept request is marked running. None are. */
    bool running() const;

    /** Sum of bytes on every kept request. Each request is built with 0. */
    int64_t bytes_moved() const;

    /** True when any kept request marks the gpu. None do. */
    bool gpu() const;

    /** True when any kept request is marked launched. None are. */
    bool launched() const;

    /**
     * Record name.
     * Refuses an empty name and a name already present. On refusal the
     * book is unchanged.
     */
    bool store(const std::string& name);

private:
    std::map<std::string, SwarmFsdpHoldRecord> m_requests;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FSDPHOLD_BOOK_H
