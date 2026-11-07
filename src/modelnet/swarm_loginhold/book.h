// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LOGINHOLD_BOOK_H
#define BITCOIN_MODELNET_SWARM_LOGINHOLD_BOOK_H

#include <modelnet/swarm_loginhold/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Login requests recorded by Request, keyed by name.
 * store refuses an empty name and a name already present.
 * A refused store leaves the first request in place.
 * There is no method that logs a record in, moves bytes,
 * marks the gpu busy, or marks the request launched.
 */
class SwarmLoginHoldBook {
public:
    bool contains(const std::string& name) const;
    std::string name_of(const std::string& name) const;
    std::size_t size() const;

    /** True when any kept request is logged in. None are. */
    bool logged_in() const;

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
    std::map<std::string, SwarmLoginHoldRecord> m_requests;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LOGINHOLD_BOOK_H
