// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LAUNCHPROF_BOOK_H
#define BITCOIN_MODELNET_SWARM_LAUNCHPROF_BOOK_H

#include <modelnet/swarm_launchprof/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Names recorded by Rename, keyed by name.
 * store refuses an empty name and a name already present.
 * A refused store leaves the first name in place.
 * There is no method that renames the profile, moves bytes,
 * marks the gpu busy, or marks the rename launched.
 */
class SwarmLaunchProfileBook {
public:
    bool contains(const std::string& name) const;
    std::string name_of(const std::string& name) const;
    std::size_t size() const;

    /** True when any kept name renamed the profile. None do. */
    bool renamed() const;

    /** Sum of bytes on every kept name. Each record is built with 0. */
    int64_t bytes_moved() const;

    /** True when any kept name marks the gpu. None do. */
    bool gpu() const;

    /** True when any kept name is marked launched. None are. */
    bool launched() const;

    /**
     * Record name.
     * Refuses an empty name and a name already present. On refusal the
     * book is unchanged.
     */
    bool store(const std::string& name);

private:
    std::map<std::string, SwarmLaunchProfileRecord> m_names;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LAUNCHPROF_BOOK_H
