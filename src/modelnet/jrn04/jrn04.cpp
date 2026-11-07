// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn04/jrn04.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/acc04/acc04.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

struct KnownRow {
    const char* id;
    const char* refuse;
    const char* code;
};

const KnownRow kKnown[] = {
    {"ADM-003", "kill", "ADVISORY"},
    {"RUN-001", nullptr, nullptr},
    {"RUN-002", "passthrough", "SCOPE"},
    {"RUN-003", "recall", "SENT"},
    {"RUN-004", nullptr, nullptr},
    {"RSI-001", "inherit", "GRANT"},
    {"RSI-002", "skip", "REGRESSION"},
    {"RSI-003", "transfer", "GENERATION"},
    {"REALM-001", nullptr, nullptr},
    {"REALM-002", "bridge", "BRIDGE"},
    {"REALM-003", "transitive", "TRUST"},
    {"MDT-001", "monetary", "STORE"},
    {"MDT-002", "latest", "DISAGREE"},
    {"MDT-003", nullptr, nullptr},
    {"MDT-004", "rewrite", "FOREIGN"},
    {"WAN-001", "older", "ROLLBACK"},
};

const char* const kEngine[] = {
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

bool Fail(Acc04& eng, const char* id, const char* text, int64_t aux, bool flag, const char* want, std::string& err)
{
    if (eng.Apply(id, text, aux, flag, err)) return false;
    return err == want;
}

bool Accept(Acc04& eng, const char* id, const char* text, int64_t aux, bool flag, std::string& err)
{
    if (!eng.Apply(id, text, aux, flag, err)) return false;
    return err.empty();
}

int64_t StoreAux(const char* id)
{
    const std::string name(id);
    if (name == "ADM-003") return static_cast<int64_t>(100);
    if (name == "RUN-004") return static_cast<int64_t>(0);
    return static_cast<int64_t>(1);
}

} // namespace

bool Jrn04::Pass(std::string& err)
{
    Acc04 eng;

    if (!Fail(eng, "ADM-003", "", static_cast<int64_t>(-1), false, "FIELD", err)) return false;
    if (!Fail(eng, "ADM-003", "kill", static_cast<int64_t>(-1), true, "BOUND", err)) return false;
    if (!Fail(eng, "ADM-003", "kill", static_cast<int64_t>(101), false, "CAP", err)) return false;
    if (!Fail(eng, "ADM-003", "kill", static_cast<int64_t>(0), false, "ABSENT", err)) return false;
    if (!Fail(eng, "ADM-003", "kill", static_cast<int64_t>(1), true, "ADVISORY", err)) return false;

    for (const char* name : kEngine) {
        if (!Fail(eng, "RUN-001", name, static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT, err)) return false;
    }
    if (!Fail(eng, "RUN-001", "private trajectory", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA, err)) return false;
    if (!Fail(eng, "ADM-003", "kill private", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA, err)) return false;

    for (const KnownRow& row : kKnown) {
        if (row.refuse == nullptr) continue;
        if (!Fail(eng, row.id, row.refuse, static_cast<int64_t>(1), true, row.code, err)) return false;
        if (!Fail(eng, row.id, row.refuse, static_cast<int64_t>(1), true, row.code, err)) return false;
    }

    for (const KnownRow& row : kKnown) {
        if (row.refuse != nullptr) {
            if (!Fail(eng, row.id, row.refuse, static_cast<int64_t>(1), true, row.code, err)) return false;
        }
        if (!Accept(eng, row.id, "s1", StoreAux(row.id), true, err)) return false;
        if (!Fail(eng, row.id, "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY, err)) return false;
        if (row.refuse != nullptr) {
            if (!Fail(eng, row.id, row.refuse, static_cast<int64_t>(1), true, row.code, err)) return false;
        }
        if (!Fail(eng, row.id, "s2", static_cast<int64_t>(1), true, "UNCHANGED", err)) return false;
    }

    err.clear();
    return true;
}

bool Jrn04::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn04::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn04::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn04::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn04::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
