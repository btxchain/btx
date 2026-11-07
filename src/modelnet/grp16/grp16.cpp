// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp16/grp16.h>
#include <modelnet/nifdt_contract/contract.h>


#include <cstdint>
#include <limits>
#include <map>
#include <string>

namespace modelnet {
namespace {

bool AddOk(int64_t a, int64_t b, int64_t& out)
{
    const __int128 s = static_cast<__int128>(a) + static_cast<__int128>(b);
    if (s > static_cast<__int128>(INT64_MAX) || s < static_cast<__int128>(INT64_MIN)) return false;
    out = static_cast<int64_t>(s);
    return true;
}

} // namespace

bool Grp16::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp16::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

int64_t Grp16::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp16::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp16::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp16::classification(const std::string& id) const
{
    (void)id;
    return "COMPONENT";
}

bool Grp16::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp16::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp16::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp16::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp16::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    (void)now_ms;
    if (id.empty()) {
        err = "REQUEST";
        return false;
    }
    if (id == "ASR-RES-001") {
        if (aux < 1) { err = "BYTES"; return false; }
        const std::string key = id + "#" + text;
        if (Has(key)) { err = NIFDT_REPLAY; return false; }
        int64_t sum = aux;
        if (Has(id) && !AddOk(stored(id), aux, sum)) { err = "CAPACITY"; return false; }
        if (sum > 100) { err = "CAPACITY"; return false; }
        Put(key, aux, text);
        Put(id, sum, text);
        err.clear();
        return true;
    }
    if (id == "ASR-RES-002") {
        if (aux > 4 || aux < 1) { err = "BACKPRESSURE"; return false; }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "ASR-SEC-001") {
        if (!text.empty() && text == extra) { err = "DOMAIN"; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "ASR-SEC-002") {
        if (!flag) { err = NIFDT_PRIVATE_DATA; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "ASR-TRN-001") {
        if (extra.empty() || extra == text) { err = "CONTRIBUTOR"; return false; }
        Put(id, 1, text + "," + extra);
        err.clear();
        return true;
    }
    if (id == "ASR-TRN-002") {
        if (!flag) { err = "PARTIAL"; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "ASR-TRN-003") {
        if (text == "wan") { err = NIFDT_NO_ROUTE; return false; }
        if (aux > 100) { err = "INFLUENCE"; return false; }
        if (aux > 0) Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "ASR-TRN-004") {
        if (text != "public_trajectory" && text != "synthetic_trajectory") { err = NIFDT_PRIVATE_DATA; return false; }
        if (extra.empty()) { err = "POLICY"; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "ASR-TRN-005") {
        if (!flag) { err = "NOT_MERGED"; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "ASR-VAL-001") {
        if (op == "score") {
            if (!Has(id + "#commit")) { err = "ORDER"; return false; }
            Put(id, 1, text);
            err.clear();
            return true;
        }
        if (op == "commit") {
            Put(id + "#commit", 1, "commit");
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "ASR-VAL-002") {
        if (flag) { err = "SAMPLE"; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "ASR-VAL-003") {
        if (!text.empty() && text == extra) { err = "SELF"; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "ASR-VAL-004") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "ASR-VAL-005") {
        if (aux < 2) { err = "SHORT"; return false; }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "DS-ACT-001") {
        if (text != "D0" && text != "D1" && text != "D2" && text != "D3" && text != "D4") {
            err = "EFFECT";
            return false;
        }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    err = "ID";
    return false;
}

} // namespace modelnet
