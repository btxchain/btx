// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FLAGSHIP_CATALOG_H
#define BITCOIN_MODELNET_SWARM_FLAGSHIP_CATALOG_H

#include <cstddef>
#include <optional>
#include <string>

namespace modelnet {

/**
 * The thirteen flagship stage names, in order.
 * The spelling is fixed: acquire, join, coordinate, accelerate,
 * experience, train, evolve, evaluate, graduate, adopt, pay,
 * recover, repeat. Any other string is not a stage.
 */
class SwarmFlagshipCatalog {
public:
    static constexpr std::size_t count = 13;

    /** True when stage is one of the thirteen names, spelled exactly. */
    static bool known(const std::string& stage);

    /** Index of stage, or empty when the name is not listed. */
    static std::optional<std::size_t> index(const std::string& stage);

    /** Name at index, or nullptr when index is outside the thirteen. */
    static const char* name(std::size_t index);
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FLAGSHIP_CATALOG_H
