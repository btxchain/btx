// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/guard_machine.h>

#include <crypto/sha384.h>

#include <limits>
#include <charconv>
#include <algorithm>
#include <cerrno>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif
#include <sstream>
#include <string>

namespace modelnet {
namespace {

bool Fail(std::string& err, const char* code)
{
    err = code;
    return false;
}

std::string HexLower(const unsigned char* data, size_t n)
{
    static const char* kHex = "0123456789abcdef";
    std::string out(n * 2, '0');
    for (size_t i = 0; i < n; ++i) {
        out[i * 2] = kHex[data[i] >> 4];
        out[i * 2 + 1] = kHex[data[i] & 0x0f];
    }
    return out;
}

bool NamesWallet(const std::string& effect)
{
    std::string lower;
    lower.reserve(effect.size());
    for (unsigned char c : effect) {
        if (c >= 'A' && c <= 'Z') lower.push_back(static_cast<char>(c - 'A' + 'a'));
        else lower.push_back(static_cast<char>(c));
    }
    return lower.find("wallet") != std::string::npos || lower.find("spend") != std::string::npos;
}

} // namespace

std::string GuardCommitment(const std::string& secret)
{
    unsigned char hash[CSHA384::OUTPUT_SIZE];
    CSHA384().Write(reinterpret_cast<const unsigned char*>(secret.data()), secret.size()).Finalize(hash);
    return HexLower(hash, CSHA384::OUTPUT_SIZE);
}

std::string GuardRandomHex()
{
    unsigned char bytes[32];
#ifdef _WIN32
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return {};
#else
    const int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return {};
    size_t used = 0;
    while (used < sizeof(bytes)) {
        const ssize_t count = read(fd, bytes + used, sizeof(bytes) - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(fd); return {}; }
        used += static_cast<size_t>(count);
    }
    close(fd);
#endif
    return HexLower(bytes, sizeof(bytes));
}
bool GuardTable::CheckTime(int64_t now_ms, std::string& err)
{
    if (now_ms < 0 || now_ms > std::numeric_limits<int64_t>::max() - kPermitTtlMs)
        return Fail(err, "BTX035_CLOCK");
    if (m_last_now >= 0 && now_ms < m_last_now) {
        Pause(); return Fail(err, "BTX035_CLOCK");
    }
    m_last_now = now_ms; return true;
}
void GuardTable::Prune(int64_t now_ms)
{
    for (auto it = m_by_secret.begin(); it != m_by_secret.end();) {
        if (it->second.not_after_ms < now_ms) it = m_by_secret.erase(it);
        else ++it;
    }
}
void GuardTable::Pause()
{
    m_paused = true;
    // Resume never resurrects a capability issued before the pause boundary.
    for (auto& [secret, permit] : m_by_secret) { (void)secret; permit.revoked = true; }
}
void GuardTable::Revoke(const std::string& fingerprint)
{
    for (auto& [secret, permit] : m_by_secret) {
        (void)secret;
        if (permit.fingerprint == fingerprint) permit.revoked = true;
    }
}

bool GuardTable::Prepare(const std::string& effect, const std::string& fingerprint, uint64_t generation, int64_t now_ms,
                         GuardPermit& out, std::string& err)
{
    auto token = [](const std::string& value, size_t maximum) {
        return !value.empty() && value.size() <= maximum &&
               std::all_of(value.begin(), value.end(), [](unsigned char c) { return c >= 33 && c <= 126; });
    };
    if (!token(effect, 128) || !token(fingerprint, 256) || generation == 0) return Fail(err, "BTX035_PERMIT");
    if (!CheckTime(now_ms, err)) return false;
    Prune(now_ms);
    if (m_by_secret.size() >= kMaxPermits) return Fail(err, "BTX035_LIMIT");
    if (NamesWallet(effect)) return Fail(err, "BTX035_SCOPE_DENIED");
    if (m_paused) return Fail(err, "BTX035_PAUSED");
    const std::string secret = GuardRandomHex();
    if (secret.size() != 64) return Fail(err, "BTX035_PERMIT");
    if (m_by_secret.count(secret)) return Fail(err, "BTX035_REPLAY");
    GuardPermit permit;
    permit.secret = secret;
    permit.commitment = GuardCommitment(secret);
    permit.effect = effect;
    permit.fingerprint = fingerprint;
    permit.generation = generation;
    permit.not_after_ms = now_ms + kPermitTtlMs;
    out = permit;
    m_by_secret.emplace(secret, permit);
    err.clear();
    return true;
}

bool GuardTable::Execute(const std::string& secret, int64_t now_ms, std::string& receipt_id, std::string& err)
{
    if (!CheckTime(now_ms, err)) return false;
    if (m_paused) return Fail(err, "BTX035_PAUSED");
    const auto it = m_by_secret.find(secret);
    if (it == m_by_secret.end()) return Fail(err, "BTX035_PERMIT");
    GuardPermit& permit = it->second;
    if (permit.consumed) return Fail(err, "BTX035_REPLAY");
    if (permit.revoked) return Fail(err, "BTX035_REVOKED");
    if (now_ms >= permit.not_after_ms) return Fail(err, "BTX035_EXPIRED");
    permit.consumed = true;
    receipt_id = GuardCommitment(permit.commitment + "|" + std::to_string(now_ms));
    err.clear();
    return true;
}

std::string GuardHandleLine(GuardTable& table, const std::string& line, int64_t now_ms)
{
    if (line.empty() || line.size() > GuardTable::kMaxLine ||
        line.find_first_of("\r\n\0", 0, 3) != std::string::npos) return "ERR BTX035_SCHEMA";
    std::istringstream in(line);
    std::string verb, extra;
    in >> verb;
    std::string err;
    if (verb == "PING") return (in >> extra) ? "ERR BTX035_SCHEMA" : "READY BTX_GUARD/1";
    if (verb == "PREPARE") {
        std::string effect, fingerprint, generation_text;
        if (!(in >> effect >> fingerprint >> generation_text) || (in >> extra)) return "ERR BTX035_SCHEMA";
        uint64_t generation = 0;
        const auto parsed = std::from_chars(generation_text.data(), generation_text.data() + generation_text.size(), generation);
        if (parsed.ec != std::errc{} || parsed.ptr != generation_text.data() + generation_text.size() ||
            generation_text.empty() || generation_text[0] == '-') return "ERR BTX035_SCHEMA";
        GuardPermit permit;
        if (!table.Prepare(effect, fingerprint, generation, now_ms, permit, err)) return "ERR " + err;
        return "PERMIT " + permit.secret + " " + permit.commitment + " " + std::to_string(permit.not_after_ms);
    }
    if (verb == "EXECUTE" || verb == "CONSUME") {
        std::string secret;
        if (!(in >> secret) || (in >> extra)) return "ERR BTX035_SCHEMA";
        std::string receipt;
        if (!table.Execute(secret, now_ms, receipt, err)) return "ERR " + err;
        return "RECEIPT " + receipt + " PERMIT_CONSUMED NOT_DISPATCHED";
    }
    if (verb == "REVOKE") {
        std::string fingerprint;
        if (!(in >> fingerprint) || (in >> extra) || fingerprint.size() > 256) return "ERR BTX035_SCHEMA";
        table.Revoke(fingerprint); return "OK";
    }
    if (verb == "PAUSE" || verb == "RESUME") {
        if (in >> extra) return "ERR BTX035_SCHEMA";
        if (verb == "PAUSE") table.Pause(); else table.Resume();
        return "OK";
    }
    return "ERR BTX035_SCHEMA";
}

} // namespace modelnet
