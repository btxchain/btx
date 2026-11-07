// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTVRAM_H
#define BITCOIN_MODELNET_SWARM_NOTVRAM_H

#include <cstdint>
#include <string>

namespace modelnet {

/** A swarm note. This type carries no GPU or VRAM measurement. */
struct SwarmNotVram {
    std::string job_id;
    bool want_publish{false};
};

/** Outcome of recording a note. published stays false; vram_bytes stays 0. */
struct SwarmNotVramResult {
    std::string code;
    bool published{false};
    int64_t vram_bytes{0};
};

/**
 * Record a swarm note without measuring GPU memory.
 * Empty job_id yields JOB. want_publish yields UNMEASURED.
 * Otherwise the note is NOTED and err is cleared.
 * Never publishes and never reports a measured VRAM size.
 */
SwarmNotVramResult SwarmNoteNotVram(const SwarmNotVram& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTVRAM_H
