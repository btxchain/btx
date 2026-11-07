// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ARTIFACT_CAPTURE_H
#define BITCOIN_MODELNET_SWARM_ARTIFACT_CAPTURE_H

#include <modelnet/training_integer.h>

#include <string>

namespace modelnet {

/**
 * One committed integer-model artifact.
 * Capture steps once from the zero state, requires ReplayMatches, then
 * EncodeModelArtifact. A second Capture is REPLAY and keeps the first bytes.
 * If Step, ReplayMatches, or encode fails, nothing is stored and that error
 * is returned. The trainer still uses the eight frozen pairs.
 */
class ArtifactCapture {
public:
    bool Capture(std::string& err);

    bool held() const { return m_held; }
    const std::string& bytes() const { return m_bytes; }

private:
    IntegerTrainer m_trainer;
    std::string m_bytes;
    bool m_held{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ARTIFACT_CAPTURE_H
