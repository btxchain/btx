// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn07/jrn07.h>
#include <modelnet/acc07/acc07.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

// Refusal fixtures copied from src/test/acc07_tests.cpp. No other fixture
// table from that test is copied.
struct Refusal {
    const char* id;
    const char* text;
    const char* code;
};

const Refusal kRefusals[] = {
    {"E2E-006", "backup", "ROLLBACK"},
    {"QA-001", "skip", "FAIL"},
    {"QA-002", "native", "PACKAGE"},
    {"QA-003", "growth", "CLAIM"},
    {"REV-001", "1.0.0", "REVISION"},
    {"REV-002", "signed-release", "UNSIGNED"},
    {"REV-004", "cycle", "CYCLE"},
    {"REV-005", "empty-keys", "PENDING"},
    {"REV-008", "early", "BATCH"},
    {"REV-009", "shell", "ACTION"},
    {"REV-010", "default", "PROFILE"},
    {"REV-011", "weaker", "STRICT"},
    {"REV-013", "late", "PLAN"},
    {"REV-014", "shared", "TOKEN"},
    {"REV-015", "score", "BINDING"},
};

const char* const kIds[] = {
    "E2E-006",
    "QA-001",
    "QA-002",
    "QA-003",
    "REV-001",
    "REV-002",
    "REV-003",
    "REV-004",
    "REV-005",
    "REV-006",
    "REV-007",
    "REV-008",
    "REV-009",
    "REV-010",
    "REV-011",
    "REV-012",
    "REV-013",
    "REV-014",
    "REV-015",
    "REV-016",
};

bool ContinueSameErr(Acc07& acc, const std::string& id, const std::string& text, int64_t aux, bool flag, const std::string& code, std::string& err)
{
    if (acc.Apply(id, text, aux, flag, err)) return false;
    return err == code;
}

} // namespace

bool Jrn07::Pass(std::string& err)
{
    Acc07 acc;
    for (const Refusal& row : kRefusals) {
        if (!ContinueSameErr(acc, row.id, row.text, static_cast<int64_t>(1), true, row.code, err)) {
            return false;
        }
    }
    for (const char* id : kIds) {
        if (std::string(id) == "REV-016") {
            if (!ContinueSameErr(acc, id, "s1", static_cast<int64_t>(1), true, NIFDT_UNQUALIFIED, err)) {
                return false;
            }
            if (acc.stored(id) || !acc.text(id).empty()) return false;
            if (acc.qualified() || acc.release_qualified() || acc.hardware_qualified()) return false;
            continue;
        }
        if (!acc.Apply(id, "s1", static_cast<int64_t>(1), true, err)) return false;
        if (!acc.stored(id) || acc.text(id) != "s1") return false;
    }
    err.clear();
    return true;
}

bool Jrn07::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn07::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn07::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn07::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn07::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
