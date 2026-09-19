// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_VERIFIED_MANIFEST_H
#define BITCOIN_MODELNET_VERIFIED_MANIFEST_H

#include <modelnet/cores.h>
#include <univalue.h>

#include <string>

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

} // namespace modelnet

#endif // BITCOIN_MODELNET_VERIFIED_MANIFEST_H
