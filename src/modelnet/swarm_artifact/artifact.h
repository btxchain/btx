// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ARTIFACT_ARTIFACT_H
#define BITCOIN_MODELNET_SWARM_ARTIFACT_ARTIFACT_H

#include <modelnet/swarm_artifact/capture.h>
#include <modelnet/swarm_artifact/join.h>
#include <modelnet/swarm_artifact/limits.h>
#include <modelnet/swarm_artifact/offer.h>
#include <modelnet/swarm_artifact/split.h>
#include <modelnet/training_integer.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Integer-artifact assembly plane.
 * Capture runs one IntegerTrainer::Step, requires ReplayMatches on that
 * state, then EncodeModelArtifact. A second Capture is REPLAY and keeps
 * the first bytes. Split calls SplitModelPieces. Offer records local piece
 * bytes by index. Join calls JoinModelPieces and keeps the string only when
 * it reproduces the capture. bytes_moved() is 0. gpu() is false. The joined
 * string is local reassembly: no bytes cross a network, and no GPU runs.
 * No ninth integer pair is added.
 */
class SwarmArtifact {
public:
    bool Capture(std::string& err);
    bool Split(std::string& err);
    bool Offer(int64_t index, const std::string& bytes, std::string& err);
    bool Join(std::string& err);

    bool has_capture() const { return m_capture.held(); }
    const std::string& captured() const { return m_capture.bytes(); }

    bool has_split() const { return m_split.ready(); }
    const std::vector<std::string>& pieces() const { return m_split.pieces(); }

    const std::string* offered(int64_t index) const { return m_offers.Find(index); }
    std::size_t offer_count() const { return m_offers.count(); }

    bool joined() const { return m_join.joined(); }
    const std::string& reassembly() const { return m_join.reassembly(); }

    uint64_t bytes_moved() const { return kSwarmArtifactBytesMoved; }
    bool gpu() const { return kSwarmArtifactGpu; }

private:
    ArtifactCapture m_capture;
    ArtifactSplit m_split;
    ArtifactOffers m_offers;
    ArtifactJoin m_join;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ARTIFACT_ARTIFACT_H
