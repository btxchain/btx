// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTTFT_H
#define BTX_MODELNET_SWARM_NOTNOTTFT_H

#include <string>

namespace modelnet {

/**
 * A local note about time to first token for one run. want_publish asks
 * this note to publish a time-to-first-token measurement.
 *
 * No time-to-first-token measurement is published by this note.
 * published stays false and milliseconds stays 0 on every path.
 */
struct SwarmNotNoTtft {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting time to first token. published stays false and
 * milliseconds stays 0 on every path.
 */
struct SwarmNotNoTtftResult {
    std::string code;
    bool published{false};
    int milliseconds{0};
};

/**
 * Note a run without publishing a time-to-first-token measurement.
 * Order, first match wins: an empty run_id is RUN. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published stays false and milliseconds stays 0 on every path.
 * No time-to-first-token measurement is published by this note.
 */
SwarmNotNoTtftResult SwarmNoteNotNoTtft(const SwarmNotNoTtft& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTTFT_H
