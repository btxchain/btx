// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_runtimepick.h>

namespace {

bool IsKnownRuntime(const std::string& name)
{
    return name == "vllm" || name == "sglang" || name == "lmcache" || name == "mooncake" ||
           name == "nixl" || name == "rdma" || name == "torch";
}

} // namespace

namespace modelnet {

SwarmRuntimePickResult SwarmSelectRuntime(const SwarmRuntimePickRequest& request, std::string& err)
{
    SwarmRuntimePickResult result;
    result.selected = false;
    result.advertised = false;
    result.qualified = false;
    if (request.name.empty() || !IsKnownRuntime(request.name)) {
        result.code = "RUNTIME";
        err = "RUNTIME";
        return result;
    }
    if (!request.installed) {
        result.code = "ENGINE_ABSENT";
        err = "ENGINE_ABSENT";
        return result;
    }
    if (!request.measurement_taken) {
        result.selected = true;
        result.advertised = false;
        result.qualified = false;
        result.code = "INSTALLED";
        err.clear();
        return result;
    }
    result.selected = true;
    result.advertised = false;
    result.qualified = false;
    result.code = "SELECTED";
    err.clear();
    return result;
}

} // namespace modelnet
