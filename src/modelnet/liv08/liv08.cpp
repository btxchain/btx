// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv08/liv08.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp08/grp08.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

struct Call {
    const char* id;
    const char* op;
    const char* text;
    const char* extra;
    int64_t now_ms;
    int64_t aux;
    bool flag;
    bool accept;
    const char* want;
};

const Call kCalls[] = {
    {"DT-DAT-008", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REVISION"},
    {"DT-DAT-008", "", "r1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-DAT-008", "", "r1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DT-RLP-001", "", "p|s|t", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "POLICY"},
    {"DT-RLP-001", "", "p|s|t|g", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-RLP-001", "", "p|s|t|h", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "COMPAT"},
    {"DT-RLP-002", "", "2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "GROUP"},
    {"DT-RLP-002", "", "2,4", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-RLP-003", "", "2,4", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "GROUP"},
    {"DT-RLP-003", "", "2,4", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"DT-RLP-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, "STALE"},
    {"DT-RLP-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, true, ""},
    {"DT-RLP-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), true, true, ""},
    {"DT-RLP-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, true, ""},
    {"DT-RLP-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, true, ""},
    {"DT-RLP-005", "need", "", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, "SHORT"},
    {"DT-RLP-005", "need", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, true, ""},
    {"DT-RLP-008", "t", "t", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SELF"},
    {"DT-RLP-008", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "RIGHTS"},
    {"DT-RLP-008", "teacher", "student", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-CKP-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "MANIFEST"},
    {"DT-CKP-001", "", "m1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-CKP-001", "", "m2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DT-CKP-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(128), true, false, "BUFFER"},
    {"DT-CKP-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4194305), false, false, "PIECE"},
    {"DT-CKP-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4096), false, true, ""},
    {"DT-CKP-003", "", "PYTHON_PICKLE", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CODE"},
    {"DT-CKP-003", "", "elf", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CODE"},
    {"DT-CKP-003", "", "weights", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-CKP-005", "", "g1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "JOURNAL"},
    {"DT-CKP-005", "", "g1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"DT-CKP-005", "", "g2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "JOURNAL"},
    {"DT-CKP-005", "", "g2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"DT-CKP-006", "snap", "s1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-CKP-006", "mutate", "s2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "IMMUTABLE"},
    {"DT-CKP-007", "", "PYTHON_PICKLE", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CODE"},
    {"DT-CKP-007", "export", "weights", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-CKP-008", "promote", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED"},
    {"DT-CKP-008", "valid", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-CKP-008", "activate", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED"},
    {"DT-WAN-001", "perlayer", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "NO_ROUTE"},
    {"DT-WAN-001", "coarse", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
};

} // namespace

bool Liv08::Pass(std::string& err)
{
    Grp08 group;
    for (const Call& call : kCalls) {
        const bool ok = group.Apply(call.id, call.op, call.text, call.extra, call.now_ms, call.aux, call.flag, err);
        if (!call.accept) {
            if (ok) {
                err = "STEP";
                return false;
            }
            if (err != call.want) return false;
            continue;
        }
        if (!ok || !err.empty()) return false;
    }
    err.clear();
    return true;
}

bool Liv08::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv08::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv08::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv08::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv08::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
