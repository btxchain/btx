// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn17/jrn17.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/dtat06/dtat06.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

const char* const kIds[] = {
    "DT-AT-SIM-001",
    "DT-AT-SIM-002",
    "DT-AT-SIM-003",
    "DT-AT-SIM-004",
    "DT-AT-SIM-005",
    "DT-AT-SIM-006",
    "DT-AT-SIM-007",
    "DT-AT-SIM-008",
    "DT-AT-REL-001",
    "DT-AT-REL-002",
    "DT-AT-REL-003",
    "DT-AT-REL-004",
    "DT-AT-REL-005",
    "DT-AT-REL-006",
    "DT-AT-REL-007",
    "DT-AT-REL-008",
};

const char* const kEngines[] = {
    "vllm",
    "sglang",
    "lmcache",
    "nixl",
    "mooncake",
    "rdma",
    "deepinfer",
    "dualpipe",
    "fp8",
    "fp4",
};

bool UnqualifiedId(const char* id)
{
    return std::string(id) == "DT-AT-REL-003" || std::string(id) == "DT-AT-REL-007";
}

bool SpendId(const char* id)
{
    return std::string(id) == "DT-AT-REL-008";
}

bool SimulationId(const char* id)
{
    return std::string(id).compare(0, 9, "DT-AT-SIM") == 0;
}

bool SameFalse(Dtat06& eng, const char* id, const char* text, int64_t aux, bool flag, const char* want, std::string& err)
{
    if (eng.Apply(id, text, aux, flag, err)) return false;
    return err == want;
}

bool SameTrue(Dtat06& eng, const char* id, const char* text, int64_t aux, bool flag, std::string& err)
{
    if (!eng.Apply(id, text, aux, flag, err)) return false;
    return err.empty();
}

bool StaySimulation(const Dtat06& eng, bool saw, std::string& err)
{
    if (!saw) return true;
    if (eng.classification() == "SIMULATION_NOT_HARDWARE_MEASUREMENT") return true;
    err = eng.classification();
    return false;
}

bool Refusals(Dtat06& eng, std::string& err)
{
    if (!SameFalse(eng, "DT-AT-SIM-001", "", static_cast<int64_t>(-1), false, "FIELD", err)) return false;
    if (eng.stored("DT-AT-SIM-001")) return false;
    if (!SameFalse(eng, "DT-AT-SIM-001", "s1", static_cast<int64_t>(-1), false, "BOUND", err)) return false;
    if (eng.stored("DT-AT-SIM-001")) return false;
    if (!SameFalse(eng, "DT-AT-SIM-001", "s1", static_cast<int64_t>(101), false, "CAP", err)) return false;
    if (eng.stored("DT-AT-SIM-001")) return false;
    if (!SameFalse(eng, "DT-AT-SIM-001", "fp8", static_cast<int64_t>(0), false, "ABSENT", err)) return false;
    if (eng.stored("DT-AT-SIM-001")) return false;

    for (const char* name : kEngines) {
        if (!SameFalse(eng, "DT-AT-REL-002", name, static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT, err)) return false;
        if (eng.stored("DT-AT-REL-002") || !eng.text("DT-AT-REL-002").empty()) {
            err = NIFDT_ENGINE_ABSENT;
            return false;
        }
        if (eng.bytes_moved() != static_cast<int64_t>(0) || eng.gpu()) {
            err = NIFDT_ENGINE_ABSENT;
            return false;
        }
    }

    if (!SameFalse(eng, "DT-AT-SIM-003", "private", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA, err)) return false;
    if (eng.stored("DT-AT-SIM-003")) return false;
    if (!SameFalse(eng, "DT-AT-SIM-003", "s1 private", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA, err)) return false;
    if (!eng.text("DT-AT-SIM-003").empty()) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }

    if (!SameFalse(eng, "DT-AT-REL-003", "", static_cast<int64_t>(1), true, "FIELD", err)) return false;
    if (!SameFalse(eng, "DT-AT-REL-003", "s1", static_cast<int64_t>(-1), true, "BOUND", err)) return false;
    if (!SameFalse(eng, "DT-AT-REL-003", "s1", static_cast<int64_t>(101), true, "CAP", err)) return false;
    if (!SameFalse(eng, "DT-AT-REL-003", "s1", static_cast<int64_t>(1), false, "ABSENT", err)) return false;
    if (!SameFalse(eng, "DT-AT-REL-003", "vllm", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT, err)) return false;
    if (!SameFalse(eng, "DT-AT-REL-007", "private", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA, err)) return false;
    if (eng.stored("DT-AT-REL-003") || eng.stored("DT-AT-REL-007")) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }

    if (!SameFalse(eng, "DT-AT-REL-003", "s1", static_cast<int64_t>(1), true, NIFDT_UNQUALIFIED, err)) return false;
    if (eng.stored("DT-AT-REL-003") || !eng.text("DT-AT-REL-003").empty()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (!SameFalse(eng, "DT-AT-REL-003", "s1", static_cast<int64_t>(1), true, NIFDT_UNQUALIFIED, err)) return false;
    if (eng.stored("DT-AT-REL-003")) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (!SameFalse(eng, "DT-AT-REL-007", "s2", static_cast<int64_t>(100), true, NIFDT_UNQUALIFIED, err)) return false;
    if (eng.stored("DT-AT-REL-007") || !eng.text("DT-AT-REL-007").empty()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }

    if (!SameFalse(eng, "DT-AT-REL-008", "", static_cast<int64_t>(1), true, "FIELD", err)) return false;
    if (!SameFalse(eng, "DT-AT-REL-008", "s1", static_cast<int64_t>(-1), true, "BOUND", err)) return false;
    if (!SameFalse(eng, "DT-AT-REL-008", "s1", static_cast<int64_t>(101), true, "CAP", err)) return false;
    if (!SameFalse(eng, "DT-AT-REL-008", "s1", static_cast<int64_t>(1), false, "ABSENT", err)) return false;
    if (!SameFalse(eng, "DT-AT-REL-008", "fp4", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT, err)) return false;
    if (!SameFalse(eng, "DT-AT-REL-008", "s1 private", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA, err)) return false;
    if (!SameFalse(eng, "DT-AT-REL-008", "s1", static_cast<int64_t>(1), true, NIFDT_AUTOMATIC_SPEND, err)) return false;
    if (eng.stored("DT-AT-REL-008") || eng.broadcast()) {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }
    if (!SameFalse(eng, "DT-AT-REL-008", "s1", static_cast<int64_t>(1), true, NIFDT_AUTOMATIC_SPEND, err)) return false;
    if (eng.stored("DT-AT-REL-008") || !eng.text("DT-AT-REL-008").empty()) {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }
    if (eng.bytes_moved() != static_cast<int64_t>(0)) {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }

    if (!SameFalse(eng, "DT-AT-REL-004", "fp8", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT, err)) return false;
    if (eng.stored("DT-AT-REL-004")) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }

    for (const char* id : kIds) {
        if (eng.stored(id)) {
            err = "UNCHANGED";
            return false;
        }
    }
    return true;
}

} // namespace

bool Jrn17::Pass(std::string& err)
{
    Dtat06 eng;
    if (!Refusals(eng, err)) return false;

    bool saw_simulation = false;
    for (const char* id : kIds) {
        if (UnqualifiedId(id)) {
            if (!SameFalse(eng, id, "s1", static_cast<int64_t>(1), true, NIFDT_UNQUALIFIED, err)) return false;
            if (eng.stored(id) || !eng.text(id).empty()) {
                err = NIFDT_UNQUALIFIED;
                return false;
            }
            if (!SameFalse(eng, id, "s2", static_cast<int64_t>(1), true, NIFDT_UNQUALIFIED, err)) return false;
            if (eng.stored(id) || eng.broadcast() || eng.bytes_moved() != static_cast<int64_t>(0)) {
                err = NIFDT_UNQUALIFIED;
                return false;
            }
        } else if (SpendId(id)) {
            if (!SameFalse(eng, id, "s1", static_cast<int64_t>(1), true, NIFDT_AUTOMATIC_SPEND, err)) return false;
            if (eng.stored(id) || !eng.text(id).empty() || eng.broadcast()) {
                err = NIFDT_AUTOMATIC_SPEND;
                return false;
            }
            if (!SameFalse(eng, id, "s2", static_cast<int64_t>(100), true, NIFDT_AUTOMATIC_SPEND, err)) return false;
            if (eng.stored(id) || eng.bytes_moved() != static_cast<int64_t>(0)) {
                err = NIFDT_AUTOMATIC_SPEND;
                return false;
            }
        } else {
            if (!SameTrue(eng, id, "s1", static_cast<int64_t>(1), true, err)) return false;
            if (!eng.stored(id) || eng.text(id) != "s1") {
                err = "UNCHANGED";
                return false;
            }
            if (SimulationId(id)) saw_simulation = true;
            if (!SameFalse(eng, id, "s1", static_cast<int64_t>(0), true, NIFDT_REPLAY, err)) return false;
            if (eng.text(id) != "s1") {
                err = NIFDT_REPLAY;
                return false;
            }
            if (!SameFalse(eng, id, "s2", static_cast<int64_t>(100), true, "UNCHANGED", err)) return false;
            if (eng.text(id) != "s1") {
                err = "UNCHANGED";
                return false;
            }
        }
        if (!StaySimulation(eng, saw_simulation, err)) return false;
    }

    if (!saw_simulation || eng.classification() != "SIMULATION_NOT_HARDWARE_MEASUREMENT") {
        err = eng.classification();
        return false;
    }
    if (eng.stored("DT-AT-REL-003") || eng.stored("DT-AT-REL-007") || eng.stored("DT-AT-REL-008")) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (!eng.stored("DT-AT-SIM-001") || eng.text("DT-AT-REL-001") != "s1") {
        err = "UNCHANGED";
        return false;
    }
    if (!eng.stored("DT-AT-SIM-008") || eng.text("DT-AT-SIM-008") != "s1") {
        err = "UNCHANGED";
        return false;
    }
    if (!eng.stored("DT-AT-REL-006") || eng.text("DT-AT-REL-006") != "s1") {
        err = "UNCHANGED";
        return false;
    }
    if (eng.hosts() != static_cast<int64_t>(1) || eng.physical_hosts() != static_cast<int64_t>(1) ||
        eng.bytes_moved() != static_cast<int64_t>(0) || eng.broadcast() || eng.launched() || eng.gpu() ||
        eng.qualified() || eng.release_qualified() || eng.hardware_qualified()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (eng.Release(err) || err != NIFDT_UNQUALIFIED) return false;
    if (eng.release_qualified() || eng.hardware_qualified() || eng.qualified()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (eng.Spend(err) || err != NIFDT_AUTOMATIC_SPEND) return false;
    if (eng.Vendor(err) || err != NIFDT_ENGINE_ABSENT) return false;
    if (eng.Gpu(err) || err != NIFDT_ENGINE_ABSENT) return false;
    if (eng.Hosts(static_cast<int64_t>(2), err) || err != "HOSTS") return false;
    if (eng.hosts() != static_cast<int64_t>(1) || eng.physical_hosts() != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }

    err.clear();
    return true;
}

bool Jrn17::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn17::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn17::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn17::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn17::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
