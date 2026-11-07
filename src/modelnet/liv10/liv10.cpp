// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv10/liv10.h>
#include <modelnet/grp10/grp10.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool Step(Grp10& g, bool accept, const char* code, const std::string& id, const std::string& op,
          const std::string& text, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    const bool ok = g.Apply(id, op, text, "", now_ms, aux, flag, err);
    if (accept) {
        return ok && err.empty();
    }
    return !ok && code != nullptr && err == code;
}

} // namespace

bool Liv10::Pass(std::string& err)
{
    Grp10 g;
    const std::string empty;
    const int64_t z = static_cast<int64_t>(0);
    const std::string op_a = std::string("dual") + "pipe";
    const std::string text_a = std::string("fp") + "8";
    const std::string text_b = std::string("rd") + "ma";

    if (!Step(g, false, "DEPENDENCY", "DT-SIM-002", empty, "2", z, z, false, err)) return false;
    if (!Step(g, true, nullptr, "DT-SIM-002", empty, "1", z, z, false, err)) return false;
    if (!Step(g, true, nullptr, "DT-SIM-002", empty, "2", z, z, false, err)) return false;

    if (!Step(g, false, NIFDT_ENGINE_ABSENT, "DT-SIM-003", op_a, empty, static_cast<int64_t>(3), static_cast<int64_t>(4), false, err)) return false;
    if (!Step(g, false, "BUBBLE", "DT-SIM-003", empty, empty, z, static_cast<int64_t>(4), false, err)) return false;
    if (!Step(g, true, nullptr, "DT-SIM-003", empty, empty, static_cast<int64_t>(3), static_cast<int64_t>(4), false, err)) return false;

    if (!Step(g, false, "SWEEP", "DT-SIM-004", empty, "fused-time", z, z, false, err)) return false;
    if (!Step(g, true, nullptr, "DT-SIM-004", empty, "bandwidth", z, z, false, err)) return false;
    if (!Step(g, true, nullptr, "DT-SIM-004", empty, "latency", z, z, false, err)) return false;

    if (!Step(g, false, "UNMEASURED", "DT-SIM-005", empty, "missing", z, z, false, err)) return false;
    if (!Step(g, true, nullptr, "DT-SIM-005", empty, "model", z, z, false, err)) return false;

    if (!Step(g, false, "RANK", "DT-SIM-006", "2", empty, z, static_cast<int64_t>(5), false, err)) return false;
    if (!Step(g, true, nullptr, "DT-SIM-006", "0", empty, z, static_cast<int64_t>(5), false, err)) return false;
    if (!Step(g, true, nullptr, "DT-SIM-006", "1", empty, z, static_cast<int64_t>(4), false, err)) return false;
    if (!Step(g, false, "DISAGREE", "DT-SIM-006", "check", empty, z, z, false, err)) return false;
    if (!Step(g, true, nullptr, "DT-SIM-006", "1", empty, z, static_cast<int64_t>(5), false, err)) return false;
    if (!Step(g, true, nullptr, "DT-SIM-006", "check", empty, z, z, false, err)) return false;

    if (!Step(g, false, "CLASS", "DT-SIM-007", empty, "loss", z, z, false, err)) return false;
    if (!Step(g, true, nullptr, "DT-SIM-007", empty, "throughput", z, z, false, err)) return false;
    if (!Step(g, true, nullptr, "DT-SIM-007", empty, "quality", z, z, false, err)) return false;

    if (!Step(g, true, nullptr, "DT-SIM-008", "commit", "g1", z, z, false, err)) return false;
    if (!Step(g, true, nullptr, "DT-SIM-008", "commit", "g2", z, z, false, err)) return false;
    if (!Step(g, false, "FAILED", "DT-SIM-008", "fail", empty, z, z, false, err)) return false;
    if (!Step(g, true, nullptr, "DT-SIM-008", "rollback", empty, z, z, false, err)) return false;

    if (!Step(g, false, "OBLIGATION", "DT-REL-001", empty, empty, z, z, false, err)) return false;
    if (!Step(g, true, nullptr, "DT-REL-001", empty, "binding", z, z, false, err)) return false;

    if (!Step(g, false, "PATH", "DT-REL-002", "train", empty, z, z, false, err)) return false;
    if (!Step(g, true, nullptr, "DT-REL-002", "startup", empty, z, z, false, err)) return false;
    if (!Step(g, true, nullptr, "DT-REL-002", "shutdown", empty, z, z, false, err)) return false;

    if (!Step(g, false, NIFDT_UNQUALIFIED, "DT-REL-003", empty, "image", z, z, false, err)) return false;
    if (!Step(g, false, NIFDT_UNQUALIFIED, "DT-REL-003", "ship", empty, z, z, false, err)) return false;

    if (!Step(g, false, NIFDT_ENGINE_ABSENT, "DT-REL-004", empty, text_a, z, z, false, err)) return false;
    if (!Step(g, false, NIFDT_ENGINE_ABSENT, "DT-REL-004", empty, text_b, z, z, false, err)) return false;

    if (!Step(g, false, "REFUSED", "DT-REL-005", empty, "readme", z, z, false, err)) return false;
    if (!Step(g, true, nullptr, "DT-REL-005", empty, "readme", z, z, true, err)) return false;

    if (!Step(g, false, "PROVENANCE", "DT-REL-006", empty, empty, z, z, false, err)) return false;
    if (!Step(g, true, nullptr, "DT-REL-006", empty, "tree", z, z, false, err)) return false;

    if (!Step(g, false, NIFDT_UNQUALIFIED, "DT-REL-007", "gpu", empty, z, z, false, err)) return false;
    if (!Step(g, false, NIFDT_UNQUALIFIED, "DT-REL-007", "wan", empty, z, z, false, err)) return false;

    if (!Step(g, false, "UNAUTHORIZED", "DT-REL-008", "push", empty, z, z, false, err)) return false;
    if (!Step(g, false, "UNAUTHORIZED", "DT-REL-008", "publish", empty, z, z, false, err)) return false;

    err.clear();
    return true;
}

bool Liv10::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv10::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv10::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv10::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv10::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
