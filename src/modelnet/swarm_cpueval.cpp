// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cpueval.h>

namespace modelnet {

SwarmCpuEvalResult SwarmNoteCpuEval(const SwarmCpuEval& eval, std::string& err)
{
    SwarmCpuEvalResult result;
    result.published = false;
    result.gpu_claimed = false;
    if (eval.node_id.empty()) {
        result.published = false;
        result.gpu_claimed = false;
        result.code = "EVAL";
        err = "EVAL";
        return result;
    }
    // A CPU evaluator does not claim a GPU. This wins even when
    // cpu_available and want_publish_rate are true.
    if (eval.want_gpu_claim) {
        result.published = false;
        result.gpu_claimed = false;
        result.code = "NO_GPU";
        err = "NO_GPU";
        return result;
    }
    if (!eval.cpu_available) {
        result.published = false;
        result.gpu_claimed = false;
        result.code = "ABSENT";
        err = "ABSENT";
        return result;
    }
    // A CPU role is not a published tokens-per-second figure.
    // Nothing is benchmarked.
    if (eval.want_publish_rate) {
        result.published = false;
        result.gpu_claimed = false;
        result.code = "UNMEASURED";
        err = "UNMEASURED";
        return result;
    }
    result.published = false;
    result.gpu_claimed = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
