// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GUESTHOLD_BOOK_H
#define BITCOIN_MODELNET_SWARM_GUESTHOLD_BOOK_H

#include <modelnet/swarm_guesthold/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Guest-agent checks recorded by Check, keyed by name.
 * store refuses an empty name and a name already present.
 * A refused store leaves the first check in place.
 * There is no method that passes a record, logs an agent in,
 * moves bytes, marks the gpu busy, or marks the check launched.
 */
class SwarmGuestHoldBook {
public:
    bool contains(const std::string& name) const;
    std::string name_of(const std::string& name) const;
    std::size_t size() const;

    /** True when any kept check is marked passed. None are. */
    bool passed() const;

    /** True when any kept check is marked logged in. None are. */
    bool logged_in() const;

    /** Sum of bytes on every kept check. Each check is built with 0. */
    int64_t bytes_moved() const;

    /** True when any kept check marks the gpu. None do. */
    bool gpu() const;

    /** True when any kept check is marked launched. None are. */
    bool launched() const;

    /**
     * Record name.
     * Refuses an empty name and a name already present. On refusal the
     * book is unchanged.
     */
    bool store(const std::string& name);

private:
    std::map<std::string, SwarmGuestHoldRecord> m_checks;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GUESTHOLD_BOOK_H
