// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PIECEPIPE_H
#define BITCOIN_MODELNET_SWARM_PIECEPIPE_H

#include <modelnet/swarm_piecepipe/manifest.h>
#include <modelnet/swarm_piecepipe/store.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-process content-addressed piece pipeline.
 *
 * Piece bytes live in memory. This plane checks them. It does not decrypt,
 * transfer, write a file, open a socket, or broadcast. bytes_moved() stays
 * 0. decrypted(), broadcast(), launched(), and gpu() stay false.
 *
 * A piece is at most 4194304 bytes. A body is at most 33554432 bytes.
 * A piece id and an artifact id are the lowercase hex of SHA-384 (48 bytes).
 *
 * Refusal paths return false and set err to the code. Accepted paths return
 * true and clear err.
 *
 * Accept stores a body under id when the digest matches.
 * An empty body is PIECE. A body over 33554432 bytes is PIECE_LIMIT.
 * Those two checks run before the stored-id check.
 * A digest mismatch on a new id is PIECE_DIGEST.
 * The same id and the same body again is REPLAY and keeps the first.
 * The same id and a different body is CONFLICT and keeps the first.
 *
 * Split stores slices of at most 4194304 bytes under each slice digest.
 * The artifact id is the SHA-384 of the whole body, not a hash of the slice
 * ids, and is stored as the manifest root. Splitting the same body again
 * keeps the stored slices and the manifest and returns true. The manifest
 * is not usable until Resume sees every slice still present.
 *
 * Resume of an unknown artifact is MANIFEST. A missing slice is MANIFEST
 * and leaves usable() false. When every slice is present, usable() becomes
 * true. Resume does not write, decrypt, or broadcast.
 *
 * Drop of an unknown id is PIECE. Drop of a slice a manifest still requires
 * is MANIFEST and does not delete it. Drop of a stored piece that no
 * manifest requires erases it and returns true.
 *
 * AcceptSealed refuses is_private with PRIVATE_DATA and ciphertext with
 * REALM_SEALED, storing nothing. decrypted() stays false either way.
 * A public plaintext piece follows Accept.
 */
class SwarmPiecePipe {
public:
    bool Accept(const std::string& id, const std::vector<unsigned char>& body, std::string& err);
    bool Split(const std::vector<unsigned char>& body, std::string& err);
    bool Resume(const std::string& artifact, std::string& err);
    bool Drop(const std::string& id, std::string& err);
    bool AcceptSealed(const std::string& id, const std::vector<unsigned char>& body, bool ciphertext, bool is_private, std::string& err);

    std::size_t PieceCount() const;
    std::size_t ManifestCount() const;
    bool usable(const std::string& artifact) const;
    std::vector<std::string> SliceIds(const std::string& artifact) const;
    bool HasPiece(const std::string& id) const;

    std::int64_t bytes_moved() const;
    bool decrypted() const;
    bool broadcast() const;
    bool launched() const;
    bool gpu() const;

private:
    SwarmPiecePipeStore m_store;
    SwarmPiecePipeManifestBook m_manifests;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PIECEPIPE_H
