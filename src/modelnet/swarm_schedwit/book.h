// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCHEDWITNESS_BOOK_H
#define BITCOIN_MODELNET_SWARM_SCHEDWITNESS_BOOK_H

#include <modelnet/swarm_schedwit/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Witnesses recorded by Sign, keyed by witness.
 * store refuses an empty witness and a witness already present.
 * A refused store leaves the first witness in place.
 * There is no method that marks a record signed, arms a spend,
 * attaches a key, broadcasts, or moves atoms.
 */
class SwarmSchedWitnessBook {
public:
    bool contains(const std::string& witness) const;
    std::string witness_of(const std::string& witness) const;
    std::size_t size() const;

    /** True when any kept witness is signed. None are. */
    bool signed_ok() const;

    /** Sum of atoms on every kept witness. Each witness is built with 0. */
    int64_t atoms_moved() const;

    /** automatic_spend of a kept witness when one differs, otherwise "0". */
    std::string automatic_spend() const;

    /** True when any kept witness marks broadcast. None do. */
    bool broadcast() const;

    /** Sum of bytes on every kept witness. Each witness is built with 0. */
    int64_t bytes_moved() const;

    /** True when any kept witness marks the gpu. None do. */
    bool gpu() const;

    /**
     * Record witness.
     * Refuses an empty witness and a witness already present. On refusal the
     * book is unchanged.
     */
    bool store(const std::string& witness);

private:
    std::map<std::string, SwarmSchedWitnessRecord> m_witnesses;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCHEDWITNESS_BOOK_H
