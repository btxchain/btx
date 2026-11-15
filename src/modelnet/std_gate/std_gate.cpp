// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/std_gate/std_gate.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool KnownName(const std::string& name)
{
    return name == "stix" || name == "taxii" || name == "ocsf" || name == "sigma" ||
           name == "eve" || name == "cacao";
}

} // namespace

bool StdGate::noted(const std::string& name) const
{
    for (const std::string& row : m_noted) {
        if (row == name) return true;
    }
    return false;
}

bool StdGate::stored(const std::string& name) const
{
    for (const Held& row : m_held) {
        if (row.name == name) return true;
    }
    return false;
}

std::string StdGate::body_of(const std::string& name) const
{
    for (const Held& row : m_held) {
        if (row.name == name) return row.body;
    }
    return std::string();
}

bool StdGate::Note(const std::string& name, std::string& err)
{
    if (name.empty() || !KnownName(name)) {
        err = "NAME";
        return false;
    }
    if (noted(name)) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_noted.push_back(name);
    err.clear();
    return true;
}

bool StdGate::Import(const std::string& name, const std::string& body, std::string& err)
{
    if (body.empty()) {
        err = "BODY";
        return false;
    }
    if (name.empty() || !KnownName(name)) {
        err = "NAME";
        return false;
    }
    if (name == "taxii") {
        err = "BOUNDED";
        return false;
    }
    if (name == "sigma") {
        err = "BACKEND";
        return false;
    }
    if (name == "stix" && body.find("version") == std::string::npos) {
        err = "VERSION";
        return false;
    }
    if (name == "ocsf" && body.find("lineage") == std::string::npos) {
        err = "LINEAGE";
        return false;
    }
    if (name == "eve" && body.size() > 64) {
        err = "OVERSIZE";
        return false;
    }
    if (name == "cacao" && body.find("typed") == std::string::npos) {
        err = "SUBSET";
        return false;
    }
    for (Held& row : m_held) {
        if (row.name == name) {
            row.body = body;
            err.clear();
            return true;
        }
    }
    m_held.push_back(Held{name, body});
    err.clear();
    return true;
}

bool StdGate::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool StdGate::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool StdGate::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool StdGate::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
