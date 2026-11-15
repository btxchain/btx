// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_MEMORYCAP_H
#define BTX_MODELNET_SWARM_MEMORYCAP_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note of a memory request for one node. node_id names the note.
 * requested_mib is the MiB the note was asked to use. no_device marks that
 * no device file is present. want_raise asks this note to raise memory.
 *
 * raised stays false on every path. Nothing is allocated or moved.
 * Without a device file VRAM stays zero. A request above 16384 MiB stays
 * capped and nothing is allocated.
 */
struct SwarmMemoryCap {
    std::string node_id;
    int64_t requested_mib{0};
    bool no_device{false};
    bool want_raise{false};
};

/**
 * Outcome of noting a memory request. raised stays false: this note does
 * not raise memory. Nothing is allocated or moved. The cap is 16384 MiB.
 * Without a device file VRAM stays zero. A request above 16384 MiB stays
 * capped and nothing is allocated.
 */
struct SwarmMemoryCapResult {
    std::string code;
    bool raised{false};
    int64_t memory_mib{0};
};

/**
 * Note a memory request without allocating or moving bytes.
 * Order, first match wins: an empty node_id is NODE with memory_mib 0.
 * no_device is VRAM_ZERO with memory_mib 0, even when want_raise is false.
 * requested_mib below 0 or above 16384 is CAPPED. memory_mib is 16384 when
 * requested_mib is above 16384, and 0 when requested_mib is below 0.
 * want_raise with requested_mib in 0..16384 is HELD and memory_mib is
 * copied. Otherwise the note is NOTED, err is cleared, and memory_mib is
 * copied. raised stays false on every path.
 * Without a device file VRAM stays zero. A request above 16384 MiB stays
 * capped and nothing is allocated.
 */
SwarmMemoryCapResult SwarmCapMemory(const SwarmMemoryCap& cap, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_MEMORYCAP_H
