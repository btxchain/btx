// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp20/grp20.h>
#include <modelnet/nifdt_contract/contract.h>


#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

bool Grp20::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.kept;
}

void Grp20::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.kept = true;
    row.n = n;
    row.s = s;
}

void Grp20::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp20::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end() || !it->second.on || it->second.n == static_cast<int64_t>(0)) {
        return static_cast<int64_t>(0);
    }
    return it->second.n;
}

std::string Grp20::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp20::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp20::classification(const std::string& id) const
{
    (void)id;
    return "COMPONENT";
}

bool Grp20::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp20::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp20::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp20::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp20::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    (void)now_ms;
    if (id.empty() || (
            id != "DS-MODEL-005" && id != "DS-MODEL-006" &&
            id != "DS-NAT-001" && id != "DS-NAT-002" && id != "DS-NAT-003" &&
            id != "DS-NAT-004" && id != "DS-NAT-005" && id != "DS-NAT-006" &&
            id != "DS-OPS-001" && id != "DS-OPS-002" && id != "DS-OPS-003" &&
            id != "DS-OPS-004" && id != "DS-OPS-005" && id != "DS-OPS-006" &&
            id != "DS-PAY-001")) {
        err = "ID";
        return false;
    }
    if (id == "DS-MODEL-005") {
        if (op == "place" && !bit_of(id)) {
            err = "ORDER";
            return false;
        }
        if (text.empty()) {
            err = "LOCATION";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        if (op == "restrict") {
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (op == "place") {
            Put(id, static_cast<int64_t>(1), text);
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "DS-MODEL-006") {
        if (op == "poison") {
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (op == "use") {
            if (bit_of(id)) {
                err = NIFDT_REVOKED;
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
        err = "ORDER";
        return false;
    }
    if (id == "DS-NAT-001") {
        if (text != "btxd") {
            err = "OWNER";
            return false;
        }
        if (aux != static_cast<int64_t>(0)) {
            err = "SPAWN";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), "btxd");
        err.clear();
        return true;
    }
    if (id == "DS-NAT-002") {
        if (op == "drop") {
            err = "PRESERVE";
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
    if (id == "DS-NAT-003") {
        if (!flag) {
            err = "SPEND";
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
    if (id == "DS-NAT-004") {
        if (op == "fail") {
            if (!Has(id)) {
                Put(id, aux, std::string());
            }
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, aux, std::string());
        err.clear();
        return true;
    }
    if (id == "DS-NAT-005") {
        if (!flag) {
            err = "JOURNAL";
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
    if (id == "DS-NAT-006") {
        if (!flag) {
            err = "OPTOUT";
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
    if (id == "DS-OPS-001") {
        if (!flag) {
            err = "READINESS";
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
    if (id == "DS-OPS-002") {
        if (text.find("live-target") != std::string::npos) {
            err = "BENIGN";
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
    if (id == "DS-OPS-003") {
        if (aux > static_cast<int64_t>(1)) {
            err = "FIXTURE";
            return false;
        }
        if (aux < static_cast<int64_t>(1)) {
            err = "FIXTURE";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), std::string());
        err.clear();
        return true;
    }
    if (id == "DS-OPS-004") {
        if (!flag) {
            err = "EMBARGO";
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
    if (id == "DS-OPS-005") {
        if (text.find("private") != std::string::npos) {
            err = NIFDT_PRIVATE_DATA;
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
    if (id == "DS-OPS-006") {
        if (extra.empty()) {
            err = "LOCAL";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), extra);
        err.clear();
        return true;
    }
    if (id == "DS-PAY-001") {
        if (text.empty()) {
            err = "MODE";
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
    err = "ID";
    return false;
}

} // namespace modelnet
