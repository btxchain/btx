// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTSAVE_PLANE_H
#define BITCOIN_MODELNET_SWARM_CKPTSAVE_PLANE_H

#include <modelnet/swarm_ckptsave/book.h>
#include <modelnet/swarm_ckptsave/quiet.h>
#include <modelnet/swarm_ckptsave/stay.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Checkpoint-save hold plane.
 * A checkpoint save request is recorded and does not save bytes.
 *
 * Request stores a non-empty name and returns false. err is HELD.
 * saved() stays false.
 * An empty name is CHECKPOINT and stores nothing.
 * A second Request of the same name is REPLAY and keeps the first.
 * CHECKPOINT is decided before REPLAY. REPLAY is decided before HELD.
 *
 * bytes_moved() stays 0. gpu() stays false. launched() stays false.
 */
class SwarmCheckpointSave {
public:
    /**
     * Record one checkpoint save request.
     * An empty name is CHECKPOINT and stores nothing.
     * A non-empty name is stored and the call returns false. err is HELD.
     * A second Request of the same name is REPLAY and keeps the first.
     * saved() stays false.
     */
    bool Request(const std::string& name, std::string& err);

    /** True when Request kept this name. */
    bool requested(const std::string& name) const;

    /** The kept name, or empty when it was not stored. */
    std::string stored_name(const std::string& name) const;

    /** Number of kept names. */
    std::size_t request_count() const;

    /** Stays false. A recorded request is not saved. */
    bool saved() const;

    /** Stays 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays false. The gpu is not used. */
    bool gpu() const;

    /** Stays false. Nothing is launched. */
    bool launched() const;

private:
    SwarmCkptSaveBook m_book;
    SwarmCkptSaveQuiet m_quiet;
    SwarmCkptSaveStay m_stay;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTSAVE_PLANE_H
