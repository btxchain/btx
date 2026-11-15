// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ENGINE_H
#define BTX_MODELNET_SWARM_ENGINE_H

#include <util/fs.h>

#include <string>

namespace modelnet {

/**
 * Runtime advertisement. A missing binary is ENGINE_ABSENT and is not
 * advertised. An executable file is INSTALLED. A caller-supplied token rate
 * is not a measurement, so the engine stays unadvertised. This function does
 * not start the engine and does not move tensors.
 */
struct SwarmEngineStatus {
    std::string name;
    bool present{false};
    bool advertised{false};
    bool qualified{false};
    std::string code;
};

SwarmEngineStatus SwarmProbeEngine(const std::string& name, const fs::path& binary, std::string& err);
bool SwarmQualifyEngine(SwarmEngineStatus& status, bool measurement_supplied, double tokens_per_sec, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ENGINE_H
