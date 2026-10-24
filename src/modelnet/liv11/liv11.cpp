// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv11/liv11.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp11/grp11.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool Match(Grp11& eng, bool accept, const char* want, const std::string& id, const std::string& op,
           const std::string& text, const std::string& extra, int64_t now_ms, int64_t aux, bool flag,
           std::string& err)
{
    const bool ok = eng.Apply(id, op, text, extra, now_ms, aux, flag, err);
    if (accept) return ok && err.empty();
    return !ok && want != nullptr && err == want;
}

} // namespace

bool Liv11::Pass(std::string& err)
{

    {
        Grp11 eng;
        if (!Match(eng, false, "PARTICIPANTS", "ASR-ACC-001", "", "pair", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err)) return false;
        if (!Match(eng, false, "PARTICIPANTS", "ASR-ACC-001", "", "pair", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err)) return false;
        if (!Match(eng, true, nullptr, "ASR-ACC-001", "", "pair", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-ACC-001", "", "pair", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err)) return false;
        if (!Match(eng, false, "PARTICIPANTS", "ASR-ACC-001", "", "pair", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-ACC-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err)) return false;
    }
    {
        Grp11 eng;
        if (!Match(eng, false, "HARDWARE", "ASR-ACC-002", "pass", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "HARDWARE", "ASR-ACC-002", "pass", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    }
    {
        Grp11 eng;
        if (!Match(eng, false, "MANIFEST", "ASR-ART-001", "", "closed", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err)) return false;
        if (!Match(eng, false, "MANIFEST", "ASR-ART-001", "", "closed", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err)) return false;
        if (!Match(eng, false, "MANIFEST", "ASR-ART-001", "", "closed", "root", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, true, nullptr, "ASR-ART-001", "", "closed", "root", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-ART-001", "", "next", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err)) return false;
    }
    {
        Grp11 eng;
        Grp11 top;
        if (!Match(eng, false, "OVERFLOW", "ASR-ART-002", "", "lo", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "OVERFLOW", "ASR-ART-002", "", "lo", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "OVERFLOW", "ASR-ART-002", "", "lo", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err)) return false;
        if (!Match(eng, false, "OVERFLOW", "ASR-ART-002", "", "lo", "", static_cast<int64_t>(0), static_cast<int64_t>(65), false, err)) return false;
        if (!Match(eng, true, nullptr, "ASR-ART-002", "", "lo", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-ART-002", "", "hi", "", static_cast<int64_t>(0), static_cast<int64_t>(64), false, err)) return false;
        if (!Match(top, true, nullptr, "ASR-ART-002", "", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(64), false, err)) return false;
        if (!Match(top, false, "OVERFLOW", "ASR-ART-002", "", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(65), false, err)) return false;
    }
    {
        Grp11 eng;
        Grp11 one;
        if (!Match(eng, false, "PIECE", "ASR-ART-003", "", "piece", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "PIECE", "ASR-ART-003", "", "piece", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "PIECE", "ASR-ART-003", "", "piece", "", static_cast<int64_t>(0), static_cast<int64_t>(4194305), false, err)) return false;
        if (!Match(eng, true, nullptr, "ASR-ART-003", "", "piece", "", static_cast<int64_t>(0), static_cast<int64_t>(4194304), false, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-ART-003", "", "again", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err)) return false;
        if (!Match(one, true, nullptr, "ASR-ART-003", "", "one", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err)) return false;
    }
    {
        Grp11 eng;
        if (!Match(eng, true, nullptr, "ASR-ART-004", "", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-ART-004", "", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "CONFLICT", "ASR-ART-004", "", "gen-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "CONFLICT", "ASR-ART-004", "", "gen-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    }
    {
        Grp11 eng;
        if (!Match(eng, false, "DIGEST", "ASR-ART-005", "", "body-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "DIGEST", "ASR-ART-005", "", "body-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, true, nullptr, "ASR-ART-005", "", "body-a", "d1", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-ART-005", "", "body-b", "d2", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    }
    {
        Grp11 eng;
        if (!Match(eng, false, "INTERPRETER", "ASR-CAP-001", "", "shell", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "INTERPRETER", "ASR-CAP-001", "", "shell", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "INTERPRETER", "ASR-CAP-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, true, nullptr, "ASR-CAP-001", "", "none", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-CAP-001", "", "none", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "INTERPRETER", "ASR-CAP-001", "", "python", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    }
    {
        Grp11 eng;
        if (!Match(eng, false, "UNQUALIFIED", "ASR-CAP-002", "", "env-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "UNQUALIFIED", "ASR-CAP-002", "", "env-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, true, nullptr, "ASR-CAP-002", "", "env-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-CAP-002", "", "env-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err)) return false;
        if (!Match(eng, false, "UNQUALIFIED", "ASR-CAP-002", "", "env-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    }
    {
        Grp11 eng;
        if (!Match(eng, false, "AUTHORITY", "ASR-CAP-003", "", "model-a", "model-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "AUTHORITY", "ASR-CAP-003", "", "model-a", "model-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, true, nullptr, "ASR-CAP-003", "", "model-a", "pkg-b", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-CAP-003", "", "model-c", "pkg-d", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "AUTHORITY", "ASR-CAP-003", "", "model-a", "model-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    }
    {
        Grp11 eng;
        if (!Match(eng, false, "DENIED", "ASR-CAP-004", "", "sandbox/job", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "DENIED", "ASR-CAP-004", "", "sandbox/job", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "DENIED", "ASR-CAP-004", "", "job/sandbox", "sandbox/", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, true, nullptr, "ASR-CAP-004", "", "sandbox/job", "sandbox/", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-CAP-004", "", "sandbox/next", "sandbox/", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "DENIED", "ASR-CAP-004", "", "a", "ab", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    }
    {
        Grp11 eng;
        if (!Match(eng, false, "PRIVATE_DATA", "ASR-EVD-001", "", "private-trace", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "PRIVATE_DATA", "ASR-EVD-001", "", "private-trace", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, true, nullptr, "ASR-EVD-001", "", "public-trace", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "PRIVATE_DATA", "ASR-EVD-001", "", "has private bit", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-EVD-001", "", "second-public", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    }
    {
        Grp11 eng;
        if (!Match(eng, false, "SOURCE", "ASR-EVD-002", "", "summary-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "SOURCE", "ASR-EVD-002", "", "summary-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, true, nullptr, "ASR-EVD-002", "", "summary-a", "src-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-EVD-002", "", "summary-b", "src-b", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    }
    {
        Grp11 eng;
        if (!Match(eng, false, "INJECTION", "ASR-EVD-003", "", "note ignore previous end", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "INJECTION", "ASR-EVD-003", "", "note ignore previous end", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, true, nullptr, "ASR-EVD-003", "", "ordinary note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-EVD-003", "", "second note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    }
    {
        Grp11 eng;
        if (!Match(eng, false, "REVOKED", "ASR-EVD-004", "", "released", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "REVOKED", "ASR-EVD-004", "", "released", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, true, nullptr, "ASR-EVD-004", "", "released", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-EVD-004", "", "later", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err)) return false;
        if (!Match(eng, false, "REVOKED", "ASR-EVD-004", "", "released", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    }
    {
        Grp11 eng;
        if (!Match(eng, false, "ABSENT", "ASR-EVD-005", "retrieve", "sig-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "ABSENT", "ASR-EVD-005", "retrieve", "sig-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, true, nullptr, "ASR-EVD-005", "promise", "sig-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "ABSENT", "ASR-EVD-005", "retrieve", "sig-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "REPLAY", "ASR-EVD-005", "promise", "sig-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    }
    {
        Grp11 eng;
        if (!Match(eng, false, "ID", "", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "ID", "", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
        if (!Match(eng, false, "ID", "ASR-NONE", "", "x", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    }
    err.clear();
    return true;
}

bool Liv11::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv11::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv11::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv11::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv11::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
