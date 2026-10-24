// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_INFER_ENGINE_BIND_H
#define BTX_MODELNET_SWARM_INFER_ENGINE_BIND_H

#include <util/fs.h>

#include <string>

namespace modelnet {

/**
 * Result of probing a named binary and qualifying it.
 * stored is false when the probe is ENGINE: the caller must keep its
 * previous session fields unchanged.
 * An installed regular file stays unqualified and unadvertised.
 * This binding does not spawn a process.
 */
struct SwarmInferBinding {
    bool stored{false};
    std::string name;
    fs::path binary;
    bool present{false};
    bool qualified{false};
    bool advertised{false};
    std::string status;
    std::string code;
};

/**
 * Probe name and binary with SwarmProbeEngine, then qualify an installed
 * file with SwarmQualifyEngine.
 * Empty name or path is ENGINE and stored is false.
 * A missing path, or a path that is not a regular file, is ENGINE_ABSENT
 * and present is false.
 * A regular file is status INSTALLED. qualified and advertised stay false
 * and code stays UNQUALIFIED.
 * measurement is not supplied. No process is spawned. vLLM, SGLang, and
 * CUDA are not started.
 */
SwarmInferBinding SwarmInferProbeAndQualify(const std::string& name, const fs::path& binary, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_INFER_ENGINE_BIND_H
