// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_VERIFIED_MANIFEST_H
#define BITCOIN_MODELNET_VERIFIED_MANIFEST_H

#include <modelnet/cores.h>
#include <univalue.h>
#include <util/fs.h>

#include <string>
#include <vector>

namespace modelnet {

/** Canonical identities rederived from file commitments. Claimed IDs must match. */
struct VerifiedManifest {
    ModelCore core;
    ArtifactCore artifact;
    Digest48 model_id;
    Digest48 artifact_id;
};

/** Parse + EncodeModelCore/EncodeArtifactCore. Fail ID_MISMATCH before any catalog write. */
bool VerifyManifestAgainstRequest(const UniValue& manifest, VerifiedManifest& out, std::string& err);

/**
 * Same rederive as the 3-arg form, then bind the result to the identity the
 * caller asked for: `requested` must name either the model or the artifact.
 * Anything else fails closed with ID_MISMATCH and leaves `out` cleared.
 */
bool VerifyManifestAgainstRequest(const UniValue& manifest, const Digest48& requested,
                                  VerifiedManifest& out, std::string& err);

/** Local SHA-384 + BTX pieces_root. Registry revision is never authority for these. */
bool HashFileSha384AndPiecesRoot(const fs::path& path, Digest48& sha384, Digest48& pieces_root, uint64_t& size,
                                 std::string& err);

/**
 * Recompute identities from staged bytes. Claimed model_id / artifact_id / file
 * sha384 / pieces_root must match. Empty core.files fails closed.
 */
bool BindVerifiedManifestToStaged(const VerifiedManifest& claimed, const fs::path& stage_dir, std::string& err);

/** Build a well-formed VerifiedManifest from staged relative paths (WEIGHTS). */
bool MakeVerifiedManifestFromStaged(const fs::path& stage_dir, const std::vector<std::string>& rel_paths,
                                    VerifiedManifest& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_VERIFIED_MANIFEST_H
