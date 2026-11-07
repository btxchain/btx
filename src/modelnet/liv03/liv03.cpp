// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv03/liv03.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp03/grp03.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool Match(Grp03& eng, bool accept, const char* want, const std::string& id, const std::string& op,
           const std::string& text, const std::string& extra, int64_t now_ms, int64_t aux, bool flag,
           std::string& err)
{
    const bool ok = eng.Apply(id, op, text, extra, now_ms, aux, flag, err);
    if (accept) return ok && err.empty();
    return !ok && want != nullptr && err == want;
}

} // namespace

bool Liv03::Pass(std::string& err)
{
    Grp03 eng;
    // NIF-LAN-005
    if (!Match(eng, true, nullptr, "NIF-LAN-005", "scope", "lan", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-LAN-005", "airgap", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err)) return false;

    // NIF-LAN-006
    if (!Match(eng, false, "IFACE", "NIF-LAN-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-LAN-006", "deny", "eth0", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, false, "DENIED", "NIF-LAN-006", "discover", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;

    // NIF-LAN-007
    if (!Match(eng, false, "WALLET", "NIF-LAN-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-LAN-007", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;

    // NIF-LAN-008
    if (!Match(eng, true, nullptr, "NIF-LAN-008", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-LAN-008", "airgap", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err)) return false;
    if (!Match(eng, false, "POLICY", "NIF-LAN-008", "internet", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;

    // NIF-ISL-001
    if (!Match(eng, false, "TOPOLOGY", "NIF-ISL-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-ISL-001", "", "rtt10", "", static_cast<int64_t>(0), static_cast<int64_t>(10), false, err)) return false;

    // NIF-ISL-002
    if (!Match(eng, false, "NO_ROUTE", "NIF-ISL-002", "collective", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-ISL-002", "collective", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;

    // NIF-ISL-003
    if (!Match(eng, true, nullptr, "NIF-ISL-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, err)) return false;
    if (!Match(eng, false, "BACKPRESSURE", "NIF-ISL-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err)) return false;

    // NIF-ISL-005
    if (!Match(eng, true, nullptr, "NIF-ISL-005", "fail", "hello", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-ISL-005", "restore", "hello", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, false, "MISMATCH", "NIF-ISL-005", "restore", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;

    // NIF-PKG-001
    if (!Match(eng, false, "DIGEST", "NIF-PKG-001", "", "abc", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-PKG-001", "", "ab", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, false, "ENGINE_ABSENT", "NIF-PKG-001", "execute", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;

    // NIF-PKG-002
    if (!Match(eng, false, "DIGEST", "NIF-PKG-002", "", "zz", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-PKG-002", "", "cd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;

    // NIF-PKG-003
    if (!Match(eng, false, "DENIED", "NIF-PKG-003", "egress", "plain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, false, "DOWNLOAD", "NIF-PKG-003", "download", "plain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, false, "CODE", "NIF-PKG-003", "", "PYTHON_PICKLE", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-PKG-003", "", "plain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;

    // NIF-PKG-004
    if (!Match(eng, false, "AUTHORITY", "NIF-PKG-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, false, "AUTHORITY", "NIF-PKG-004", "same", "same", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-PKG-004", "model", "soft", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;

    // NIF-PKG-005
    if (!Match(eng, true, nullptr, "NIF-PKG-005", "bind", "a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-PKG-005", "bind", "b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-PKG-005", "rollback", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, false, "EMPTY", "NIF-PKG-005", "rollback", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;

    // NIF-DATA-001
    if (!Match(eng, false, "ENCODING", "NIF-DATA-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-DATA-001", "utf8", "utf8", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, false, "ENCODING", "NIF-DATA-001", "latin1", "utf8", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;

    // NIF-DATA-002
    if (!Match(eng, false, "LOOKALIKE", "NIF-DATA-002", "", "<eos>", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-DATA-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err)) return false;
    if (!Match(eng, false, "TOKEN", "NIF-DATA-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err)) return false;

    // NIF-DATA-003
    if (!Match(eng, false, "BOUNDARY", "NIF-DATA-003", "", "c3", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, true, nullptr, "NIF-DATA-003", "", "c3a9", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    if (!Match(eng, false, "BOUNDARY", "NIF-DATA-003", "", "c3", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err)) return false;
    err.clear();
    return true;
}

bool Liv03::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv03::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv03::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv03::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv03::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
