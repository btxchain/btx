// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FOURSCALE_NAMES_H
#define BITCOIN_MODELNET_SWARM_FOURSCALE_NAMES_H

#include <string>

namespace modelnet {

/** Improvement scale that Open plants at step 0. */
inline constexpr char kSwarmFourScaleOnline[] = "online";

/** Improvement scale that Open plants at step 0. */
inline constexpr char kSwarmFourScaleDaily[] = "daily";

/** Improvement scale that Open plants at step 0. */
inline constexpr char kSwarmFourScaleWeekly[] = "weekly";

/** Improvement scale that Open plants at step 0. */
inline constexpr char kSwarmFourScaleGenerational[] = "generational";

/**
 * Index of a planted scale name.
 * An empty scale and any other text return -1. The match is exact.
 */
int SwarmFourScaleIndex(const std::string& scale);

/**
 * Name planted at index, in the order online, daily, weekly, generational.
 * An index outside that range returns an empty string.
 */
const char* SwarmFourScaleNameAt(int index);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FOURSCALE_NAMES_H
