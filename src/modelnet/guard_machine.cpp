// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/guard_machine.h>

#include <crypto/sha384.h>

#include <random>
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
    std::random_device device;
    unsigned char bytes[32];
    for (size_t i = 0; i < sizeof(bytes); i += 4) {
        const uint32_t word = device();
        bytes[i] = static_cast<unsigned char>(word);
        bytes[i + 1] = static_cast<unsigned char>(word >> 8);
        bytes[i + 2] = static_cast<unsigned char>(word >> 16);
        bytes[i + 3] = static_cast<unsigned char>(word >> 24);
    }
    return HexLower(bytes, sizeof(bytes));
}

bool GuardTable::Prepare(const std::string& effect, const std::string& fingerprint, uint64_t generation, int64_t now_ms,
                         GuardPermit& out, std::string& err)
{
    if (effect.empty() || fingerprint.empty() || generation == 0) return Fail(err, "BTX035_PERMIT");
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
    if (permit.not_after_ms - now_ms != kPermitTtlMs) return Fail(err, "BTX035_PERMIT");
    out = permit;
    m_by_secret.emplace(secret, permit);
    err.clear();
    return true;
}

bool GuardTable::Execute(const std::string& secret, int64_t now_ms, std::string& receipt_id, std::string& err)
{
    if (m_paused) return Fail(err, "BTX035_PAUSED");
    const auto it = m_by_secret.find(secret);
    if (it == m_by_secret.end()) return Fail(err, "BTX035_PERMIT");
    GuardPermit& permit = it->second;
    if (permit.consumed) return Fail(err, "BTX035_REPLAY");
    if (now_ms > permit.not_after_ms) return Fail(err, "BTX035_EXPIRED");
    permit.consumed = true;
    receipt_id = GuardCommitment(permit.commitment + "|" + std::to_string(now_ms));
    err.clear();
    return true;
}

std::string GuardHandleLine(GuardTable& table, const std::string& line, int64_t now_ms)
{
    std::istringstream in(line);
    std::string verb;
    in >> verb;
    std::string err;
    if (verb == "PREPARE") {
        std::string effect, fingerprint;
        uint64_t generation = 0;
        in >> effect >> fingerprint >> generation;
        GuardPermit permit;
        if (!table.Prepare(effect, fingerprint, generation, now_ms, permit, err)) return "ERR " + err;
        return "PERMIT " + permit.secret + " " + permit.commitment + " " + std::to_string(permit.not_after_ms);
    }
    if (verb == "EXECUTE") {
        std::string secret;
        in >> secret;
        std::string receipt;
        if (!table.Execute(secret, now_ms, receipt, err)) return "ERR " + err;
        return "RECEIPT " + receipt + " EXECUTED STOPPED_QUIESCENT";
    }
    if (verb == "PAUSE") {
        table.Pause();
        return "OK";
    }
    if (verb == "RESUME") {
        table.Resume();
        return "OK";
    }
    return "ERR BTX035_SCHEMA";
}

} // namespace modelnet
