// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_PIECEOUT_H
#define BITCOIN_MODELNET_DT_PIECEOUT_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_piecepipe/swarm_piecepipe.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Claim is a producer claim. compute_proof() stays false. */
inline constexpr char DT_PIECEOUT_CLAIM[] = "CLAIM";

/**
 * Checkpoint piece output.
 *
 * Requirement DT-CKP-002. Put calls SwarmPiecePipe::Split. Piece bytes stay
 * in the pipe. This class records the artifact id. It keeps no second copy
 * of the body and no whole-artifact transfer buffer.
 *
 * The artifact id is SwarmPiecePipeDigest of the body, the same public
 * function the piece-pipe tests use. SliceIds lists piece ids. Those piece
 * ids are stored by the pipe under the manifest. The remembered id is the
 * digest of the whole body.
 *
 * An empty body fails with the pipe's PIECE error. A body larger than
 * 33554432 bytes fails with the pipe's PIECE_LIMIT error. Both leave this
 * class's artifact id unchanged and store nothing for that call.
 *
 * After a successful Split, when ManifestCount increased and the artifact
 * id is non-empty, Put calls Resume on that id.
 *
 * Resume forwards to the pipe. An unknown artifact is the pipe's MANIFEST.
 *
 * DropRequired calls Drop. The required-slice rule is the pipe's rule: a
 * slice a manifest still requires returns MANIFEST and stays stored. This
 * class returns false with MANIFEST on that path.
 *
 * Claim returns false with CLAIM and leaves compute_proof() false.
 * bytes_moved() is the pipe's bytes_moved(), which stays 0. launched(),
 * gpu(), broadcast(), and qualified() stay false. automatic_spend() is
 * NIFDT_AUTOMATIC_SPEND. hosts() stays 1.
 */
class DtPieceOut {
public:
    bool Put(const std::vector<unsigned char>& body, std::string& err);
    bool Resume(const std::string& artifact, std::string& err);
    bool DropRequired(const std::string& id, std::string& err);
    bool Claim(std::string& err);

    const std::string& artifact() const { return m_artifact; }
    std::vector<std::string> slice_ids() const;
    bool has_piece(const std::string& id) const;
    bool usable(const std::string& artifact) const;
    std::size_t piece_count() const;
    std::size_t manifest_count() const;

    bool compute_proof() const { return false; }
    std::int64_t bytes_moved() const;
    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    bool qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    std::int64_t hosts() const { return static_cast<std::int64_t>(1); }

private:
    SwarmPiecePipe m_pipe;
    std::string m_artifact;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_PIECEOUT_H
