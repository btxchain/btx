// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_numprof/dt_numprof.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool DtNumProf::Known(const std::string& name)
{
    return name == DT_NUMPROF_CED || name == DT_NUMPROF_CSA2 ||
           name == DT_NUMPROF_ENGRAM || name == DT_NUMPROF_MHC;
}

const DtNumProf::Shape* DtNumProf::Find(const std::string& name) const
{
    const auto it = m_shapes.find(name);
    if (it == m_shapes.end()) return nullptr;
    return &it->second;
}

bool DtNumProf::Define(const std::string& name, std::int64_t hidden, std::int64_t layers, std::int64_t heads, std::string& err)
{
    if (!Known(name)) {
        err = DT_NUMPROF_NAME;
        return false;
    }
    if (hidden < static_cast<std::int64_t>(1) || layers < static_cast<std::int64_t>(1) ||
        heads < static_cast<std::int64_t>(1)) {
        err = DT_NUMPROF_SHAPE;
        return false;
    }
    if (m_shapes.count(name) != 0) {
        err = NIFDT_REPLAY;
        return false;
    }
    Shape row;
    row.hidden = hidden;
    row.layers = layers;
    row.heads = heads;
    m_shapes.emplace(name, row);
    err.clear();
    return true;
}

bool DtNumProf::Advertise(const std::string& name, std::string& err)
{
    if (!Known(name)) {
        err = DT_NUMPROF_NAME;
        return false;
    }
    if (m_shapes.count(name) == 0) {
        err = DT_NUMPROF_INCOMPLETE;
        return false;
    }
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool DtNumProf::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool DtNumProf::defined(const std::string& name) const
{
    return Find(name) != nullptr;
}

std::int64_t DtNumProf::hidden(const std::string& name) const
{
    const Shape* row = Find(name);
    if (row == nullptr) return static_cast<std::int64_t>(0);
    return row->hidden;
}

std::int64_t DtNumProf::layers(const std::string& name) const
{
    const Shape* row = Find(name);
    if (row == nullptr) return static_cast<std::int64_t>(0);
    return row->layers;
}

std::int64_t DtNumProf::heads(const std::string& name) const
{
    const Shape* row = Find(name);
    if (row == nullptr) return static_cast<std::int64_t>(0);
    return row->heads;
}

} // namespace modelnet
