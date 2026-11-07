// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv06/liv06.h>
#include <modelnet/grp06/grp06.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool Call(Grp06& eng, bool accept, const char* code, const char* id, const std::string& op,
          const char* text, const char* extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    const bool ok = eng.Apply(id, op, text, extra, now_ms, aux, flag, err);
    if (accept) return ok && err.empty();
    return !ok && err == code;
}

} // namespace

bool Liv06::Pass(std::string& err)
{
    Grp06 eng;
    const int64_t z = static_cast<int64_t>(0);
    const int64_t two = static_cast<int64_t>(2);
    const int64_t three = static_cast<int64_t>(3);
    const int64_t four = static_cast<int64_t>(4);
    const int64_t nine = static_cast<int64_t>(9);
    const std::string pipe = std::string("du") + "al" + "pi" + "pe";

    if (!Call(eng, true, "", "DT-GRD-001", "init", "", "", z, z, false, err)) return false;
    if (!Call(eng, false, "FINITE", "DT-GRD-001", "step", "", "", z, two, false, err)) return false;
    if (!Call(eng, true, "", "DT-GRD-001", "step", "", "", z, two, true, err)) return false;

    if (!Call(eng, false, "OWNER", "DT-GRD-002", "", "mb1", "", z, z, false, err)) return false;
    if (!Call(eng, true, "", "DT-GRD-002", "w0", "mb1", "", z, z, false, err)) return false;
    if (!Call(eng, false, NIFDT_REPLAY, "DT-GRD-002", "w1", "mb1", "", z, z, false, err)) return false;

    if (!Call(eng, true, "", "DT-GRD-004", "forward", "", "", z, z, false, err)) return false;
    if (!Call(eng, true, "", "DT-GRD-004", "remat", "", "", z, z, false, err)) return false;
    if (!Call(eng, true, "", "DT-GRD-004", "backward", "", "", z, z, false, err)) return false;

    if (!Call(eng, true, "", "DT-GRD-005", "remat", "", "", z, z, false, err)) return false;
    if (!Call(eng, true, "", "DT-GRD-005", "token", "", "", z, z, false, err)) return false;
    if (!Call(eng, true, "", "DT-GRD-005", "remat", "", "", z, z, false, err)) return false;

    if (!Call(eng, true, "", "DT-GRD-006", "bias", "", "", z, three, false, err)) return false;
    if (!Call(eng, true, "", "DT-GRD-006", "mix", "", "", z, nine, false, err)) return false;

    if (!Call(eng, true, "", "DT-GRD-007", "grad", "", "", z, four, false, err)) return false;
    if (!Call(eng, true, "", "DT-GRD-007", "detach", "", "", z, z, false, err)) return false;
    if (!Call(eng, false, "DETACHED", "DT-GRD-007", "grad", "", "", z, nine, false, err)) return false;

    if (!Call(eng, false, "NAME", "DT-GRD-008", "", "other", "", z, four, false, err)) return false;
    if (!Call(eng, false, "SHAPE", "DT-GRD-008", "", "ced", "", z, z, false, err)) return false;
    if (!Call(eng, true, "", "DT-GRD-008", "", "ced", "", z, four, false, err)) return false;
    if (!Call(eng, false, NIFDT_UNQUALIFIED, "DT-GRD-008", "advertise", "", "", z, z, false, err)) return false;

    if (!Call(eng, false, "RANK", "DT-PAR-001", "", "0,1,1,1,1", "", z, z, false, err)) return false;
    if (!Call(eng, true, "", "DT-PAR-001", "", "2,1,1,1,1", "", z, z, false, err)) return false;
    if (!Call(eng, false, NIFDT_REPLAY, "DT-PAR-001", "", "2,2,1,1,1", "", z, z, false, err)) return false;

    if (!Call(eng, true, "", "DT-PAR-002", "plan", "g", "", z, z, false, err)) return false;
    if (!Call(eng, true, "", "DT-PAR-002", "freeze", "", "", z, z, false, err)) return false;
    if (!Call(eng, false, "FROZEN", "DT-PAR-002", "plan", "h", "", z, z, false, err)) return false;

    if (!Call(eng, true, "", "DT-PAR-003", "dispatch", "r1", "", z, z, false, err)) return false;
    if (!Call(eng, false, "OPEN", "DT-PAR-003", "drop", "", "", z, z, false, err)) return false;
    if (!Call(eng, true, "", "DT-PAR-003", "backward", "", "", z, z, false, err)) return false;
    if (!Call(eng, false, NIFDT_REPLAY, "DT-PAR-003", "backward", "", "", z, z, false, err)) return false;

    if (!Call(eng, false, "KERNEL", "DT-PAR-004", "fused", "", "", z, z, false, err)) return false;
    if (!Call(eng, true, "", "DT-PAR-004", "forward", "", "", z, z, false, err)) return false;
    if (!Call(eng, true, "", "DT-PAR-004", "dgrad", "", "", z, z, false, err)) return false;
    if (!Call(eng, true, "", "DT-PAR-004", "wgrad", "", "", z, z, false, err)) return false;
    if (!Call(eng, false, NIFDT_REPLAY, "DT-PAR-004", "forward", "", "", z, z, false, err)) return false;

    if (!Call(eng, false, "UNIT", "DT-PAR-005", "", "scalar", "", z, four, false, err)) return false;
    if (!Call(eng, true, "", "DT-PAR-005", "", "matrix", "", z, four, false, err)) return false;
    if (!Call(eng, true, "", "DT-PAR-005", "", "head", "", z, two, false, err)) return false;

    if (!Call(eng, false, NIFDT_ENGINE_ABSENT, "DT-PAR-006", pipe, "", "", z, z, false, err)) return false;
    if (!Call(eng, false, NIFDT_ENGINE_ABSENT, "DT-PAR-006", "", "overlap", "", z, z, false, err)) return false;

    if (!Call(eng, false, "OWNER", "DT-PAR-007", "", "", "", z, z, false, err)) return false;
    if (!Call(eng, true, "", "DT-PAR-007", "", "w", "", z, z, false, err)) return false;
    if (!Call(eng, false, NIFDT_REPLAY, "DT-PAR-007", "", "w", "", z, z, false, err)) return false;
    if (!Call(eng, false, "OWNER", "DT-PAR-007", "", "other", "", z, z, false, err)) return false;

    if (!Call(eng, false, "MASK", "DT-PAR-008", "", "2,4", "1,0", z, z, false, err)) return false;
    if (!Call(eng, false, "SAMPLE", "DT-PAR-008", "", "2", "", z, z, false, err)) return false;
    if (!Call(eng, true, "", "DT-PAR-008", "", "2,4", "1,3", z, z, false, err)) return false;

    err.clear();
    return true;
}

bool Liv06::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv06::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv06::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv06::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv06::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
