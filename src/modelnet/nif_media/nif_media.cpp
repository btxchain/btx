// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_media/nif_media.h>

#include <modelnet/nifdt_contract/contract.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace {

constexpr unsigned char kPickle[] = {
    'P', 'Y', 'T', 'H', 'O', 'N', '_', 'P', 'I', 'C', 'K', 'L', 'E',
};

bool BeginsWithElf(const std::vector<unsigned char>& body)
{
    return body.size() >= 4 &&
           body[0] == 0x7f &&
           body[1] == static_cast<unsigned char>('E') &&
           body[2] == static_cast<unsigned char>('L') &&
           body[3] == static_cast<unsigned char>('F');
}

bool ContainsPickle(const std::vector<unsigned char>& body)
{
    if (body.size() < sizeof(kPickle)) return false;
    return std::search(body.begin(), body.end(), std::begin(kPickle), std::end(kPickle)) != body.end();
}

} // namespace

namespace modelnet {

const NifMedia::MediaItem* NifMedia::Find(const std::string& id) const
{
    for (const MediaItem& row : m_items) {
        if (row.id == id) return &row;
    }
    return nullptr;
}

bool NifMedia::stored(const std::string& id) const
{
    return Find(id) != nullptr;
}

const std::vector<unsigned char>& NifMedia::body(const std::string& id) const
{
    const MediaItem* row = Find(id);
    if (row == nullptr) {
        static const std::vector<unsigned char> empty;
        return empty;
    }
    return row->body;
}

int64_t NifMedia::stored_bytes() const
{
    int64_t total = static_cast<int64_t>(0);
    for (const MediaItem& row : m_items) {
        total += static_cast<int64_t>(row.body.size());
    }
    return total;
}

bool NifMedia::Bind(const std::string& purpose, std::string& err)
{
    if (purpose != "inference" && purpose != "training") {
        err = NIF_MEDIA_PURPOSE;
        return false;
    }
    m_purpose = purpose;
    err.clear();
    return true;
}

bool NifMedia::Acquire(const std::string& id, const std::vector<unsigned char>& body, bool authorized, bool local_file, std::string& err)
{
    if (m_purpose.empty()) {
        err = NIF_MEDIA_PURPOSE;
        return false;
    }
    if (id.empty()) {
        err = NIF_MEDIA_MEDIA;
        return false;
    }
    // Replay is decided before download and code so a second call cannot
    // replace the first body, and a failed first call never reaches here.
    if (stored(id)) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (!local_file) {
        err = NIF_MEDIA_DOWNLOAD;
        return false;
    }
    if (!authorized) {
        err = NIF_MEDIA_DENIED;
        return false;
    }
    if (BeginsWithElf(body)) {
        err = NIF_MEDIA_CODE;
        return false;
    }
    if (ContainsPickle(body)) {
        err = NIF_MEDIA_CODE;
        return false;
    }
    MediaItem row;
    row.id = id;
    row.body = body;
    m_items.push_back(std::move(row));
    err.clear();
    return true;
}

} // namespace modelnet
