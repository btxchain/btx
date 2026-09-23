// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GENERATE_H
#define BITCOIN_MODELNET_GENERATE_H

#include <univalue.h>
#include <util/fs.h>

#include <cstdint>
#include <string>

namespace modelnet {

enum class GenerateFormat : uint8_t {
    None = 0,
    SafeTensors = 1,
    Gguf = 2,
    Unsafe = 3,
};

struct HostGenerateProfile {
    bool llama_cli{false};
    bool generate_adapter{false};
    bool cuda_loader{false};
    std::string llama_cli_path;
    std::string generate_adapter_path;
    std::string cuda_loader_path;
};

struct ArtifactGenerateView {
    GenerateFormat format{GenerateFormat::None};
    std::string architecture;
    std::string config_path;
    std::string weights_path;
    bool pickle_or_executable{false};
};

/** Operator env only. Does not probe the network or pip. */
HostGenerateProfile ProbeHostGenerateProfile();

UniValue HostGenerateProfileJson(const HostGenerateProfile& p);

bool SafeTensorsArchitectureIsHostCompatible(const std::string& architecture);

ArtifactGenerateView InspectCheckoutForGenerate(const fs::path& checkout);

/** Compatible means this host profile can attempt a local generate. Runtime
 *  may still NOT_RUN (missing torch). Unknown arch / pickle fail closed. */
bool ArtifactCompatibleWithHost(const ArtifactGenerateView& art,
                                const HostGenerateProfile& host,
                                std::string& reason);

std::string PickGenerateAdapter(const ArtifactGenerateView& art, const HostGenerateProfile& host);

} // namespace modelnet

#endif // BITCOIN_MODELNET_GENERATE_H
