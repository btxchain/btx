// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_fork/nif_fork.h>

namespace modelnet {

NifFork::Reservation* NifFork::Find(const std::string& id)
{
    for (Reservation& row : m_rows) {
        if (row.id == id) return &row;
    }
    return nullptr;
}

const NifFork::Reservation* NifFork::Find(const std::string& id) const
{
    for (const Reservation& row : m_rows) {
        if (row.id == id) return &row;
    }
    return nullptr;
}

void NifFork::Erase(const std::string& id)
{
    for (auto it = m_rows.begin(); it != m_rows.end(); ++it) {
        if (it->id == id) {
            m_rows.erase(it);
            return;
        }
    }
}

int64_t NifFork::used() const
{
    int64_t total = static_cast<int64_t>(0);
    for (const Reservation& row : m_rows) {
        total += row.bytes;
    }
    return total;
}

bool NifFork::Reserve(const std::string& id, int64_t bytes, int64_t now_ms, int64_t until_ms, std::string& err)
{
    if (id.empty()) {
        err = "REQUEST";
        return false;
    }
    if (bytes < static_cast<int64_t>(1)) {
        err = "BYTES";
        return false;
    }
    if (now_ms >= until_ms) {
        err = "EXPIRED";
        return false;
    }
    if (Find(id) != nullptr) {
        err = NIFDT_REPLAY;
        return false;
    }
    const int64_t held = used();
    if (bytes > kCapacity - held) {
        err = "CAPACITY";
        return false;
    }
    Reservation row;
    row.id = id;
    row.bytes = bytes;
    m_rows.push_back(std::move(row));
    err.clear();
    return true;
}

bool NifFork::Pin(const std::string& id, int64_t fence, std::string& err)
{
    Reservation* row = Find(id);
    if (id.empty() || row == nullptr) {
        err = "REQUEST";
        return false;
    }
    if (row->fence_open) {
        err = "PINNED";
        return false;
    }
    row->fence_open = true;
    row->fence = fence;
    err.clear();
    return true;
}

bool NifFork::Complete(const std::string& id, int64_t fence, std::string& err)
{
    Reservation* row = Find(id);
    if (id.empty() || row == nullptr) {
        err = "REQUEST";
        return false;
    }
    if (!row->fence_open || row->fence != fence) {
        err = "FENCE";
        return false;
    }
    row->fence_open = false;
    err.clear();
    return true;
}

bool NifFork::Release(const std::string& id, std::string& err)
{
    const Reservation* row = Find(id);
    if (id.empty() || row == nullptr) {
        err = "REQUEST";
        return false;
    }
    if (row->fence_open) {
        err = "PINNED";
        return false;
    }
    Erase(id);
    err.clear();
    return true;
}

bool NifFork::Eligible(int64_t devices, int64_t minimum_devices, int64_t qualified_until_ms, int64_t now_ms, std::string& err)
{
    if (devices != static_cast<int64_t>(1)) {
        err = "HARDWARE";
        return false;
    }
    if (minimum_devices > devices) {
        err = "HARDWARE";
        return false;
    }
    if (now_ms >= qualified_until_ms) {
        err = "EXPIRED";
        return false;
    }
    err.clear();
    return true;
}

bool NifFork::ExecuteVendor(std::string& err)
{
    if (!NifDtEngineLinked("deepinfer")) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
