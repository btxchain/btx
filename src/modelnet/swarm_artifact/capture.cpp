// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_artifact/capture.h>

#include <modelnet/swarm_artifact/error.h>
#include <modelnet/training_integer.h>

#include <string>
#include <utility>

namespace modelnet {

bool ArtifactCapture::Capture(std::string& err)
{
    if (m_held) {
        err = kSwarmArtifactReplay;
        return false;
    }

    IntegerTrainer advanced = m_trainer;
    if (!advanced.IntegerTrainer::Step(err)) return false;

    const IntegerState published = advanced.State();
    if (!advanced.IntegerTrainer::ReplayMatches(published, err)) return false;

    std::string bytes;
    if (!EncodeModelArtifact(published, bytes, err)) return false;
    if (bytes.empty()) {
        err = kSwarmArtifactArtifact;
        return false;
    }

    m_trainer = std::move(advanced);
    m_bytes = std::move(bytes);
    m_held = true;
    err.clear();
    return true;
}

} // namespace modelnet
