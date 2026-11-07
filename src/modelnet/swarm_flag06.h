// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FLAG06_H
#define BTX_MODELNET_SWARM_FLAG06_H

#include <string>

namespace modelnet {

/**
 * Flagship stage 6 train: a local note about two workers.
 * worker_a and worker_b name the workers. checkpoint_saved asks this
 * note to treat a checkpoint as saved. want_pair asks this note to
 * pair the workers. want_pass asks this note to treat the note as
 * passed.
 *
 * This note does not pair, distribute, publish, or pass. paired,
 * distributed, published, passed, and bytes_moved stay false on every
 * path.
 */
struct SwarmFlag06 {
    std::string worker_a;
    std::string worker_b;
    bool checkpoint_saved{false};
    bool want_pair{false};
    bool want_pass{false};
};

/**
 * Outcome of flagship stage 6 train. paired, distributed, published,
 * passed, and bytes_moved stay false on every path.
 */
struct SwarmFlag06Result {
    std::string code;
    bool paired{false};
    bool distributed{false};
    bool published{false};
    bool passed{false};
    bool bytes_moved{false};
};

/**
 * Note flagship stage 6 train. Two named workers are still only a note.
 * Order, first match wins: an empty worker_a or worker_b is WORKER.
 * Equal worker_a and worker_b is SAME_WORKER. want_pair is
 * OUT_OF_SCOPE. checkpoint_saved false is NO_CHECKPOINT. want_pass is
 * UNQUALIFIED. Otherwise the note is NOTED and err is cleared.
 * paired, distributed, published, passed, and bytes_moved stay false
 * on every path.
 */
SwarmFlag06Result SwarmStageTrain(const SwarmFlag06& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FLAG06_H
