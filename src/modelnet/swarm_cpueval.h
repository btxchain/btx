// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CPUEVAL_H
#define BTX_MODELNET_SWARM_CPUEVAL_H

#include <string>

namespace modelnet {

/**
 * A local note of a CPU evaluator for one node. node_id names the note.
 * cpu_available marks that a CPU role is present. want_publish_rate asks
 * this note for a published tokens-per-second figure. want_gpu_claim asks
 * this note to claim a GPU.
 *
 * published and gpu_claimed stay false on every path. Nothing is
 * benchmarked. No hostnames or IPs are used.
 */
struct SwarmCpuEval {
    std::string node_id;
    bool cpu_available{false};
    bool want_publish_rate{false};
    bool want_gpu_claim{false};
};

/**
 * Outcome of noting a CPU evaluator. published and gpu_claimed stay
 * false: this note does not publish a rate and does not claim a GPU.
 * Nothing is benchmarked.
 */
struct SwarmCpuEvalResult {
    bool published{false};
    bool gpu_claimed{false};
    std::string code;
};

/**
 * Note a CPU evaluator without benchmarking. Order, first match wins:
 * an empty node_id is EVAL. published and gpu_claimed stay false and
 * err is EVAL.
 * want_gpu_claim is NO_GPU. published and gpu_claimed stay false and
 * err is NO_GPU. This wins even when cpu_available and want_publish_rate
 * are true. A CPU evaluator does not claim a GPU.
 * !cpu_available is ABSENT. published and gpu_claimed stay false and
 * err is ABSENT.
 * want_publish_rate is UNMEASURED. published and gpu_claimed stay false
 * and err is UNMEASURED. A CPU role is not a published tokens-per-second
 * figure.
 * Otherwise the note is NOTED. published and gpu_claimed stay false and
 * err is cleared. Nothing is benchmarked. No hostnames or IPs are used.
 */
SwarmCpuEvalResult SwarmNoteCpuEval(const SwarmCpuEval& eval, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CPUEVAL_H
