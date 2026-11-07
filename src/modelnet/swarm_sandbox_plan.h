// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SANDBOX_PLAN_H
#define BTX_MODELNET_SWARM_SANDBOX_PLAN_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A request to plan one sandbox. sandbox_id names the plan.
 * requested_threads and requested_mib are the resources asked for.
 * host_interpreter asks to run a host interpreter. network asks for a
 * network. want_launch asks this plan to start the sandbox.
 *
 * A sandbox plan caps threads at 64 and memory at 16384 MiB, refuses a
 * host interpreter, and launches nothing.
 */
struct SwarmSandboxRequest {
    std::string sandbox_id;
    int64_t requested_threads{0};
    int64_t requested_mib{0};
    bool host_interpreter{false};
    bool network{false};
    bool want_launch{false};
};

/**
 * Outcome of planning a sandbox. launched and network_allowed stay
 * false on every path. Nothing is started, and no bytes are moved.
 */
struct SwarmSandboxPlan {
    std::string code;
    bool admitted{false};
    bool launched{false};
    int64_t threads{0};
    int64_t memory_mib{0};
    bool network_allowed{false};
};

/**
 * Plan a sandbox without launching it.
 * A sandbox plan caps threads at 64 and memory at 16384 MiB, refuses a
 * host interpreter, and launches nothing.
 * Order, first match wins:
 * An empty sandbox_id is SANDBOX. admitted is false, threads and
 * memory_mib are 0, and err is SANDBOX.
 * host_interpreter is HOST, even when want_launch is false. admitted
 * is false, threads and memory_mib are 0, and err is HOST.
 * requested_threads above 64 or below 0, or requested_mib above 16384
 * or below 0, is CAPPED. admitted is false. threads is clamped into
 * [0, 64] and memory_mib is clamped into [0, 16384]. err is CAPPED.
 * want_launch is HELD. admitted is true. threads and memory_mib are
 * clamped the same way. err is HELD.
 * Otherwise the plan is NOTED. admitted is true, err is cleared, and
 * threads and memory_mib are clamped the same way.
 * launched and network_allowed stay false on every path.
 */
SwarmSandboxPlan SwarmPlanSandbox(const SwarmSandboxRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SANDBOX_PLAN_H
