// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTBENCHMARK_H
#define BTX_MODELNET_SWARM_NOTBENCHMARK_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one node. tokens_per_sec is a caller-supplied figure.
 * want_publish asks this note to publish that figure as a benchmark.
 *
 * A caller-supplied tokens_per_sec is not a hardware benchmark.
 * published stays false on every path. measured stays false on every path.
 */
struct SwarmNotBenchmark {
    std::string node_id;
    int64_t tokens_per_sec{0};
    bool want_publish{false};
};

/**
 * Outcome of noting a benchmark request. published and measured stay false
 * on every path: a caller-supplied tokens_per_sec is not a hardware benchmark.
 */
struct SwarmNotBenchmarkResult {
    std::string code;
    bool published{false};
    bool measured{false};
};

/**
 * Note a benchmark request without measuring or publishing.
 * Order, first match wins: an empty node_id or tokens_per_sec < 0 is RATE.
 * want_publish is UNMEASURED, even when tokens_per_sec is greater than 0.
 * Otherwise the note is NOTED and err is clear.
 * published and measured stay false on every path.
 */
SwarmNotBenchmarkResult SwarmNoteNotBenchmark(const SwarmNotBenchmark& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTBENCHMARK_H
