// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandbox_plan.h>

#include <cstdint>

namespace modelnet {

static constexpr int64_t kSwarmSandboxThreadCap = 64;
static constexpr int64_t kSwarmSandboxMemoryCapMib = 16384;

static int64_t ClampSandbox(int64_t value, int64_t cap)
{
    if (value < 0) {
        return 0;
    }
    if (value > cap) {
        return cap;
    }
    return value;
}

// A sandbox plan caps threads at 64 and memory at 16384 MiB, refuses a
// host interpreter, and launches nothing.
SwarmSandboxPlan SwarmPlanSandbox(const SwarmSandboxRequest& request, std::string& err)
{
    SwarmSandboxPlan plan;
    plan.launched = false;
    plan.network_allowed = false;

    if (request.sandbox_id.empty()) {
        plan.code = "SANDBOX";
        plan.admitted = false;
        plan.launched = false;
        plan.threads = 0;
        plan.memory_mib = 0;
        plan.network_allowed = false;
        err = "SANDBOX";
        return plan;
    }
    // A host interpreter is refused even when want_launch is false.
    if (request.host_interpreter) {
        plan.code = "HOST";
        plan.admitted = false;
        plan.launched = false;
        plan.threads = 0;
        plan.memory_mib = 0;
        plan.network_allowed = false;
        err = "HOST";
        return plan;
    }
    if (request.requested_threads > kSwarmSandboxThreadCap ||
        request.requested_mib > kSwarmSandboxMemoryCapMib ||
        request.requested_threads < 0 || request.requested_mib < 0) {
        plan.code = "CAPPED";
        plan.admitted = false;
        plan.launched = false;
        plan.threads = ClampSandbox(request.requested_threads, kSwarmSandboxThreadCap);
        plan.memory_mib = ClampSandbox(request.requested_mib, kSwarmSandboxMemoryCapMib);
        plan.network_allowed = false;
        err = "CAPPED";
        return plan;
    }
    // This plan does not launch the sandbox.
    if (request.want_launch) {
        plan.code = "HELD";
        plan.admitted = true;
        plan.launched = false;
        plan.threads = ClampSandbox(request.requested_threads, kSwarmSandboxThreadCap);
        plan.memory_mib = ClampSandbox(request.requested_mib, kSwarmSandboxMemoryCapMib);
        plan.network_allowed = false;
        err = "HELD";
        return plan;
    }
    plan.code = "NOTED";
    plan.admitted = true;
    plan.launched = false;
    plan.threads = ClampSandbox(request.requested_threads, kSwarmSandboxThreadCap);
    plan.memory_mib = ClampSandbox(request.requested_mib, kSwarmSandboxMemoryCapMib);
    plan.network_allowed = false;
    err.clear();
    return plan;
}

} // namespace modelnet
