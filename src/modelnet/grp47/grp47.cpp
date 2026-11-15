// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp47/grp47.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool Known(const std::string& id)
{
    static const char* kIds[] = {
        "DT-NAT-006", "DT-NAT-007", "DT-NAT-008",
        "DT-GRD-001", "DT-GRD-002", "DT-GRD-003", "DT-GRD-004", "DT-GRD-005", "DT-GRD-006", "DT-GRD-007",
        "DT-PAR-001", "DT-PAR-002", "DT-PAR-003", "DT-PAR-004", "DT-PAR-005", "DT-PAR-006", "DT-PAR-007", "DT-PAR-008",
        "DT-OPT-001",
    };
    for (const char* s : kIds) {
        if (id == s) return true;
    }
    return false;
}

bool EngineName(const std::string& text)
{
    if (text == "dualpipe" || text == "fp8") return true;
    return !NifDtEngineLinked(text);
}

} // namespace

int64_t Grp47::stored(const std::string& id) const
{
    return m_rows.find(id) == m_rows.end() ? static_cast<int64_t>(0) : static_cast<int64_t>(1);
}

std::string Grp47::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() ? std::string() : it->second;
}

std::string Grp47::classification(const std::string&) const
{
    return "COMPONENT";
}

bool Grp47::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Grp47::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp47::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp47::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp47::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp47::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
{
    if (!Known(id)) {
        err = "ID";
        return false;
    }
    if (text.empty()) {
        err = "FIELD";
        return false;
    }
    if (aux < static_cast<int64_t>(0)) {
        err = "BOUND";
        return false;
    }
    if (aux > static_cast<int64_t>(100)) {
        err = "CAP";
        return false;
    }
    if (!flag) {
        err = "ABSENT";
        return false;
    }
    if (EngineName(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (id == "DT-PAR-006") {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (id == "DT-NAT-006") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    const auto it = m_rows.find(id);
    if (it != m_rows.end()) {
        if (it->second == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = "UNCHANGED";
        return false;
    }
    m_rows.emplace(id, text);
    err.clear();
    return true;
}

} // namespace modelnet
