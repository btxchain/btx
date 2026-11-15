// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp24/grp24.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {
namespace {

bool Contains(const std::string& s, const std::string& part)
{
    return s.find(part) != std::string::npos;
}

bool CompleteCore(const std::string& text)
{
    return Contains(text, "discovery") && Contains(text, "coordination") &&
           Contains(text, "inference") && Contains(text, "defense");
}

} // namespace

bool Grp24::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp24::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp24::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp24::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp24::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp24::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp24::classification(const std::string& id) const
{
    if (id.rfind("P2P-", 0) == 0) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    return "COMPONENT";
}

bool Grp24::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp24::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp24::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp24::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp24::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    (void)now_ms;
    if (id.empty()) {
        err = "ID";
        return false;
    }
    if (id == "P2P-SCN-K") {
        if (op == "activate") {
            err = NIFDT_UNQUALIFIED;
            return false;
        }
        if (op == "rollback") {
            const std::string prior_key = id + "#prior";
            if (text.empty() || !Has(prior_key) || text != text_of(prior_key)) {
                err = "ORDER";
                return false;
            }
            if (Has(id) && text_of(id) == text) {
                err = NIFDT_REPLAY;
                return false;
            }
            const int64_t n = stored(prior_key);
            Put(id, n == static_cast<int64_t>(0) ? static_cast<int64_t>(1) : n, text);
            err.clear();
            return true;
        }
        if (op != "stage") {
            err = "ORDER";
            return false;
        }
        if (text.empty()) {
            err = "ORDER";
            return false;
        }
        if (Has(id) && text_of(id) == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        if (!Has(id)) {
            Put(id, static_cast<int64_t>(1), text);
            Put(id + "#prior", static_cast<int64_t>(1), text);
            err.clear();
            return true;
        }
        if (!Has(id + "#prior")) {
            const int64_t kept = stored(id);
            Put(id + "#prior", kept == static_cast<int64_t>(0) ? static_cast<int64_t>(1) : kept, text_of(id));
        }
        Put(id, stored(id) + static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "P2P-SCN-L") {
        if (Contains(text, "hosted")) {
            err = "SERVICE";
            return false;
        }
        if (text.empty()) {
            err = "ORDER";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "P2P-SCN-M") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "P2P-SCN-N") {
        if (op == "exit") {
            err = "KEPT";
            return false;
        }
        if (text.empty()) {
            err = "ORDER";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "P2P-SCN-O") {
        if (!extra.empty() || text != "default") {
            err = "FLAG";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), "default");
        err.clear();
        return true;
    }
    if (id == "P2P-SCN-P") {
        if (op == "gpu") {
            err = NIFDT_ENGINE_ABSENT;
            return false;
        }
        if (op != "observe") {
            err = "ORDER";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), "observer");
        err.clear();
        return true;
    }
    if (id == "P2P-SCN-Q") {
        if (op == "remove") {
            err = "KEPT";
            return false;
        }
        if (!CompleteCore(text)) {
            err = "CORE";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "P2P-SCN-R") {
        if (!flag) {
            err = "ABSENT";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "NIF-ISL-004") {
        if (aux < static_cast<int64_t>(0)) {
            err = "BOUND";
            return false;
        }
        if (!flag) {
            err = "HARDWARE";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "NIF-LAN-001") {
        if (text.empty()) {
            err = "HINT";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), "local");
        err.clear();
        return true;
    }
    if (id == "NIF-LAN-002") {
        if (text != "local") {
            err = "HINT";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), "local");
        err.clear();
        return true;
    }
    if (id == "NIF-QA-007") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "DT-CKP-004") {
        if (text.empty()) {
            err = "PARAM";
            return false;
        }
        if (extra != text) {
            err = "MAP";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DT-REL-003") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "DT-REL-007") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    err = "ID";
    return false;
}

} // namespace modelnet
