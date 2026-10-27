// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp13/grp13.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

bool Grp13::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp13::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp13::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp13::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp13::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp13::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp13::classification(const std::string& id) const
{
    (void)id;
    return "COMPONENT";
}

bool Grp13::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp13::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp13::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp13::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp13::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t /*now_ms*/, int64_t aux, bool flag, std::string& err)
{
    if (id.empty()) {
        err = "ID";
        return false;
    }
    if (id == "ASR-HND-001") {
        if (extra.empty()) { err = "GRANT"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), extra);
        err.clear();
        return true;
    }
    if (id == "ASR-HND-002") {
        if (!flag) { err = "FENCE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-HND-003") {
        if (text.find("cross") != std::string::npos) { err = "AMBIGUOUS"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-HND-004") {
        if (!flag) { err = "USEFUL"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-KVC-001") {
        int commas = 0;
        for (char c : text) {
            if (c == ',') ++commas;
        }
        if (commas != 3) { err = "INCOMPATIBLE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-KVC-002") {
        if (extra.empty()) { err = "SUFFIX"; return false; }
        if (!Has(id)) {
            Put(id, aux, text);
            err.clear();
            return true;
        }
        if (text != text_of(id)) {
            const std::string prefix = text_of(id);
            Put(id, static_cast<int64_t>(0), prefix);
            SetBit(id, true);
            err = "STALE";
            return false;
        }
        err = NIFDT_REPLAY;
        return false;
    }
    if (id == "ASR-KVC-003") {
        if (text == "nixl" || text == "mooncake" || text == "rdma") {
            err = NIFDT_ENGINE_ABSENT;
            return false;
        }
        if (text == "local" && aux > static_cast<int64_t>(0)) {
            if (Has(id)) { err = NIFDT_REPLAY; return false; }
            Put(id, aux, text);
            err.clear();
            return true;
        }
        err = "BOUND";
        return false;
    }
    if (id == "ASR-KVC-004") {
        if (!flag) { err = "HASH"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-KVC-005") {
        if (aux > static_cast<int64_t>(8) || aux < static_cast<int64_t>(1)) { err = "BOUND"; return false; }
        if (op == "prefetch" && text_of(id) == "revoke") { err = NIFDT_REVOKED; return false; }
        if (op == "revoke") {
            if (text_of(id) == "revoke") { err = NIFDT_REPLAY; return false; }
            Put(id, aux, "revoke");
            err.clear();
            return true;
        }
        if (op != "prefetch") { err = "ORDER"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, "prefetch");
        err.clear();
        return true;
    }
    if (id == "ASR-KVC-006") {
        if (extra.empty()) { err = "UNMEASURED"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-MIG-001") {
        if (flag) { err = "ASSURANCE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-MIG-002") {
        if (!flag) { err = "JOURNAL"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-NAT-001") {
        if (text != "btxd") { err = "OWNER"; return false; }
        if (aux != static_cast<int64_t>(0)) { err = "SPAWN"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), "btxd");
        err.clear();
        return true;
    }
    if (id == "ASR-NAT-002") {
        const std::string mark = id + "#n";
        if (op == "fail") {
            if (bit_of(id)) { err = NIFDT_REPLAY; return false; }
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (Has(mark)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, text);
        Put(mark, static_cast<int64_t>(1), "1");
        err.clear();
        return true;
    }
    if (id == "ASR-NAT-003") {
        if (aux < static_cast<int64_t>(0)) { err = "BOUND"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        // Return on this call. Do not loop.
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "ASR-NAT-004") {
        if (text == "wallet") { err = "WALLET"; return false; }
        if (text != "cpu" && text != "memory") { err = "RESOURCE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    err = "ID";
    return false;
}

} // namespace modelnet
