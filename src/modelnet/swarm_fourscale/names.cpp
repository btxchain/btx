// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/names.h>

#include <modelnet/swarm_fourscale/limits.h>

#include <cstddef>

namespace modelnet {
namespace {

const char* const kSwarmFourScaleNames[] = {
    kSwarmFourScaleOnline,
    kSwarmFourScaleDaily,
    kSwarmFourScaleWeekly,
    kSwarmFourScaleGenerational,
};

static_assert(sizeof(kSwarmFourScaleNames) / sizeof(kSwarmFourScaleNames[0]) ==
                  static_cast<std::size_t>(kSwarmFourScaleCount),
              "the name table is the four scales");

} // namespace

int SwarmFourScaleIndex(const std::string& scale)
{
    if (scale.empty()) return -1;
    for (int i = 0; i < kSwarmFourScaleCount; ++i) {
        if (scale == kSwarmFourScaleNames[i]) return i;
    }
    return -1;
}

const char* SwarmFourScaleNameAt(int index)
{
    if (index < 0 || index >= kSwarmFourScaleCount) return "";
    return kSwarmFourScaleNames[index];
}

} // namespace modelnet
