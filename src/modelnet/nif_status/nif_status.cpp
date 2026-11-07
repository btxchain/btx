// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_status/nif_status.h>

#include <modelnet/nifdt_contract/contract.h>

#include <string>
#include <vector>

namespace {

bool Holds(const std::vector<std::string>& rows, const std::string& name)
{
    for (const std::string& row : rows) {
        if (row == name) return true;
    }
    return false;
}

} // namespace

namespace modelnet {

std::vector<std::string>* NifStatus::Find(const std::string& kind)
{
    if (kind == "component") return &m_component;
    if (kind == "native") return &m_native;
    if (kind == "hardware") return &m_hardware;
    if (kind == "release") return &m_release;
    return nullptr;
}

bool NifStatus::component_stored(const std::string& name) const
{
    return Holds(m_component, name);
}

bool NifStatus::native_stored(const std::string& name) const
{
    return Holds(m_native, name);
}

bool NifStatus::hardware_stored(const std::string& name) const
{
    return Holds(m_hardware, name);
}

bool NifStatus::release_stored(const std::string& name) const
{
    return Holds(m_release, name);
}

bool NifStatus::Record(const std::string& kind, const std::string& name, std::string& err)
{
    std::vector<std::string>* rows = Find(kind);
    if (rows == nullptr) {
        err = NIF_STATUS_CLASS;
        return false;
    }
    if (name.empty()) {
        err = NIF_STATUS_NAME;
        return false;
    }
    if (Holds(*rows, name)) {
        err = NIFDT_REPLAY;
        return false;
    }
    rows->push_back(name);
    err.clear();
    return true;
}

bool NifStatus::Release(const std::string& name, std::string& err)
{
    // Qualification is refused. The name is not added to the release class.
    static_cast<void>(name);
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool NifStatus::Promote(const std::string& name, std::string& err)
{
    // A component name stays in the component class. Release stays unqualified.
    static_cast<void>(name);
    err = NIFDT_UNQUALIFIED;
    return false;
}

} // namespace modelnet
