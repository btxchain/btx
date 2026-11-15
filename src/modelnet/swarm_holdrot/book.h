// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HOLDROT_BOOK_H
#define BITCOIN_MODELNET_SWARM_HOLDROT_BOOK_H

#include <modelnet/swarm_holdrot/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Holdouts recorded by Rotate, keyed by label.
 * store refuses an empty holdout and a holdout already present.
 * A refused store leaves the first holdout in place.
 * There is no method that marks a record rotating, moves bytes,
 * marks the gpu busy, or marks the holdout launched.
 */
class SwarmHoldoutRotateBook {
public:
    bool contains(const std::string& holdout) const;
    std::string holdout_of(const std::string& holdout) const;
    std::size_t size() const;

    /** True when any kept holdout is rotating. None are. */
    bool rotated() const;

    /** Sum of bytes on every kept holdout. Each holdout is built with 0. */
    int64_t bytes_moved() const;

    /** True when any kept holdout marks the gpu. None do. */
    bool gpu() const;

    /** True when any kept holdout is marked launched. None are. */
    bool launched() const;

    /**
     * Record holdout.
     * Refuses an empty holdout and a holdout already present. On refusal the
     * book is unchanged.
     */
    bool store(const std::string& holdout);

private:
    std::map<std::string, SwarmHoldoutRotateRecord> m_holdouts;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HOLDROT_BOOK_H
