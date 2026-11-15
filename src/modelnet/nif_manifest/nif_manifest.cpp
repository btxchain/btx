// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_manifest/nif_manifest.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstddef>

namespace modelnet {

NifManifest::Row* NifManifest::Find(const std::string& id)
{
    for (Row& row : m_rows) {
        if (row.id == id) return &row;
    }
    return nullptr;
}

const NifManifest::Row* NifManifest::Find(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return &row;
    }
    return nullptr;
}

bool NifManifest::stored(const std::string& id) const
{
    return Find(id) != nullptr;
}

int64_t NifManifest::pieces(const std::string& id) const
{
    const Row* row = Find(id);
    if (row == nullptr) return static_cast<int64_t>(0);
    return row->pieces;
}

int64_t NifManifest::accepted(const std::string& id) const
{
    const Row* row = Find(id);
    if (row == nullptr) return static_cast<int64_t>(0);
    return static_cast<int64_t>(row->digests.size());
}

std::string NifManifest::digest(const std::string& id, int64_t index) const
{
    const Row* row = Find(id);
    if (row == nullptr) return {};
    if (index < static_cast<int64_t>(0) || index >= static_cast<int64_t>(row->digests.size())) return {};
    return row->digests[static_cast<std::size_t>(index)];
}

bool NifManifest::sealed(const std::string& id) const
{
    const Row* row = Find(id);
    if (row == nullptr) return false;
    return row->sealed;
}

bool NifManifest::sealed() const
{
    if (m_rows.empty()) return false;
    for (const Row& row : m_rows) {
        if (!row.sealed) return false;
    }
    return true;
}

bool NifManifest::Open(const std::string& id, int64_t pieces, int64_t now_ms, int64_t until_ms, std::string& err)
{
    if (id.empty()) {
        err = NIF_MANIFEST_MANIFEST;
        return false;
    }
    if (pieces < static_cast<int64_t>(1)) {
        err = NIF_MANIFEST_PIECE;
        return false;
    }
    if (now_ms >= until_ms) {
        err = NIF_MANIFEST_EXPIRED;
        return false;
    }
    if (Find(id) != nullptr) {
        err = NIFDT_REPLAY;
        return false;
    }
    Row row;
    row.id = id;
    row.pieces = pieces;
    m_rows.push_back(std::move(row));
    err.clear();
    return true;
}

bool NifManifest::Accept(const std::string& id, int64_t index, const std::string& digest, std::string& err)
{
    Row* row = Find(id);
    if (id.empty() || row == nullptr) {
        err = NIF_MANIFEST_MANIFEST;
        return false;
    }
    if (index < static_cast<int64_t>(0) || index >= row->pieces) {
        err = NIF_MANIFEST_PIECE;
        return false;
    }
    const int64_t filled = static_cast<int64_t>(row->digests.size());
    if (index < filled) {
        if (row->digests[static_cast<std::size_t>(index)] != digest) {
            err = NIF_MANIFEST_ALTERED;
            return false;
        }
        err = NIFDT_REPLAY;
        return false;
    }
    if (index != filled) {
        err = NIF_MANIFEST_ORDER;
        return false;
    }
    row->digests.push_back(digest);
    err.clear();
    return true;
}

bool NifManifest::Seal(const std::string& id, std::string& err)
{
    Row* row = Find(id);
    if (id.empty() || row == nullptr) {
        err = NIF_MANIFEST_MANIFEST;
        return false;
    }
    if (static_cast<int64_t>(row->digests.size()) != row->pieces) {
        err = NIF_MANIFEST_INCOMPLETE;
        return false;
    }
    row->sealed = true;
    err.clear();
    return true;
}

bool NifManifest::Claim(const std::string& id, std::string& err)
{
    return Claim(id, true, err);
}

bool NifManifest::Claim(const std::string& id, bool producer_claim, std::string& err)
{
    if (id.empty() || Find(id) == nullptr) {
        err = NIF_MANIFEST_MANIFEST;
        return false;
    }
    if (producer_claim) {
        err = NIF_MANIFEST_CLAIM;
        return false;
    }
    err.clear();
    return true;
}

bool NifManifest::Remote(const std::string& engine, std::string& err)
{
    if (!NifDtEngineLinked(engine)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    err = "ENGINE";
    return false;
}

} // namespace modelnet
