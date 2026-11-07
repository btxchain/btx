// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTRESOURCE_H
#define BTX_MODELNET_SWARM_NOTRESOURCE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one node. want_publish asks this note to publish a
 * measured resource sample.
 *
 * This note does not publish a measurement. published stays false, and
 * cpu_ms and bytes stay 0, on every path.
 */
struct SwarmNotResource {
    std::string node_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a resource sample. published stays false, and cpu_ms
 * and bytes stay 0, on every path.
 */
struct SwarmNotResourceResult {
    std::string code;
    bool published{false};
    int64_t cpu_ms{0};
    int64_t bytes{0};
};

/**
 * Note a resource sample without publishing a measurement.
 * Order, first match wins: an empty node_id is NODE.
 * want_publish is UNMEASURED.
 * Otherwise the note is NOTED and err is clear.
 * published stays false, and cpu_ms and bytes stay 0, on every path.
 */
SwarmNotResourceResult SwarmNoteNotResource(const SwarmNotResource& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTRESOURCE_H
