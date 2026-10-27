// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_CKPT_H
#define BITCOIN_MODELNET_DT_CKPT_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_piecepipe/digest.h>
#include <modelnet/swarm_piecepipe/swarm_piecepipe.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Training checkpoint closure.
 *
 * Save stores one closure: weight bytes, Adam m, Adam v, the step counter,
 * the rng counter, the data cursor, the recipe id, the topology id, and the
 * cohort epoch. The serialized body is split through SwarmPiecePipe::Split.
 * The artifact id is SwarmPiecePipeDigest of that body. Piece bytes stay in
 * the pipe. This class does not keep a second artifact store.
 *
 * Empty weights are WEIGHTS and store nothing. A body that contains the
 * ASCII marker PYTHON_PICKLE stores nothing. A body that contains an
 * executable marker (ELF, PE, shebang, Mach-O, or wasm) is CODE and stores
 * nothing. The frame is not a pickle.
 *
 * A weights-only save, with both moment vectors absent, is stored as a
 * partial export. exact_resume() stays false. Promote of that partial
 * returns false with PARTIAL and does not set promoted().
 *
 * Promote calls Resume on the artifact. Resume of an unknown artifact, or
 * after a required slice is dropped, returns false with MANIFEST.
 * usable() stays false on that path and promoted() is not set. The pipe
 * does not delete a slice a manifest still requires; this engine still
 * refuses Resume and Restore after that drop. Restore copies the saved
 * weights, moments, step, rng, and cursor back only after a successful
 * Promote of an exact closure. A refused Restore leaves the live state.
 *
 * A second Save of the same body is allowed. launched(), gpu(), and
 * broadcast() stay false. automatic_spend() is "0". bytes_moved() stays 0
 * because the pipe does not transfer.
 */
class DtCkpt {
public:
    struct State {
        std::vector<unsigned char> weights;
        std::vector<unsigned char> adam_m;
        std::vector<unsigned char> adam_v;
        std::uint64_t step{0};
        std::uint64_t rng{0};
        std::uint64_t cursor{0};
        std::string recipe_id;
        std::string topology_id;
        std::uint64_t cohort_epoch{0};

        bool operator==(const State& other) const
        {
            return weights == other.weights && adam_m == other.adam_m && adam_v == other.adam_v &&
                   step == other.step && rng == other.rng && cursor == other.cursor &&
                   recipe_id == other.recipe_id && topology_id == other.topology_id &&
                   cohort_epoch == other.cohort_epoch;
        }
    };

    /** Store one closure. Empty weights, a pickle marker, and an executable marker store nothing. */
    bool Save(const State& state, std::string& err);

    /**
     * Resume the saved artifact.
     * A missing required slice or an unknown artifact is MANIFEST.
     */
    bool Resume(std::string& err);

    /**
     * Promote a resumed exact closure.
     * usable() false is MANIFEST and does not set promoted().
     * A partial export is PARTIAL and does not set promoted().
     */
    bool Promote(std::string& err);

    /**
     * Copy the saved closure onto the live state after a successful Promote.
     * A failed resume leaves the live state in place.
     */
    bool Restore(std::string& err);

    /**
     * Drop one slice id through the pipe.
     * A required slice is MANIFEST, stays stored in the pipe, and later Resume fails.
     */
    bool Drop(const std::string& id, std::string& err);

    State& live() { return m_live; }
    const State& live() const { return m_live; }

    const std::string& artifact() const { return m_artifact; }
    std::vector<std::string> slice_ids() const;
    bool has_piece(const std::string& id) const;
    std::size_t piece_count() const;

    bool usable(const std::string& artifact) const;
    bool promoted() const { return m_promoted; }
    bool exact_resume() const { return m_exact; }

    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    std::string automatic_spend() const;
    std::int64_t bytes_moved() const;

private:
    bool required_slice(const std::string& id) const;

    SwarmPiecePipe m_pipe;
    State m_live;
    State m_saved;
    std::string m_artifact;
    bool m_have{false};
    bool m_exact{false};
    bool m_promoted{false};
    bool m_hole{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_CKPT_H
