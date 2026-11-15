// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTFRAMEWORK_H
#define BTX_MODELNET_SWARM_NOTFRAMEWORK_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one framework comparison. run_id names the run.
 * want_publish asks this note to publish a comparison against an unmodified
 * framework.
 *
 * A comparison against an unmodified framework has not been measured.
 * published stays false, and delta stays 0, on every path.
 */
struct SwarmNotFramework {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a framework comparison. published stays false, and delta
 * stays 0, on every path: a comparison against an unmodified framework has
 * not been measured.
 */
struct SwarmNotFrameworkResult {
    std::string code;
    bool published{false};
    int64_t delta{0};
};

/**
 * Note a framework comparison without measuring it.
 * Order, first match wins: an empty run_id is RUN.
 * want_publish is UNMEASURED.
 * Otherwise the note is NOTED and err is clear.
 * published stays false, and delta stays 0, on every path.
 * A comparison against an unmodified framework has not been measured.
 */
SwarmNotFrameworkResult SwarmNoteNotFramework(const SwarmNotFramework& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTFRAMEWORK_H
