// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_lora.h>

namespace modelnet {

SwarmKvReuseResult SwarmAdmitKvReuse(const SwarmKvReuseRequest& request, std::string& err)
{
    SwarmKvReuseResult result;
    result.admitted = false;
    result.exact = false;
    if (request.approximate_requested) {
        result.code = "APPROXIMATE";
        err = "APPROXIMATE";
        return result;
    }
    if (!request.same_weights || !request.same_tokenizer || !request.same_quantization || !request.same_adapter) {
        result.code = "INCOMPATIBLE";
        err = "INCOMPATIBLE";
        return result;
    }
    result.admitted = true;
    result.exact = true;
    result.code = "EXACT";
    err.clear();
    return result;
}

} // namespace modelnet
