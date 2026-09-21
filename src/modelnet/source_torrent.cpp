// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/source_torrent.h>

#include <cstddef>
#include <limits>

namespace modelnet {

std::string ParseTorrentInfohash(const std::string& locator, const std::string& snapshot_token)
{
    if (!snapshot_token.empty()) return snapshot_token;
    const auto xt = locator.find("xt=urn:btih:");
    if (xt != std::string::npos) {
        std::string h = locator.substr(xt + 12);
        const auto amp = h.find('&');
        if (amp != std::string::npos) h.resize(amp);
        return h;
    }
    const auto xt2 = locator.find("xt=urn:btmh:");
    if (xt2 != std::string::npos) {
        std::string h = locator.substr(xt2 + 12);
        const auto amp = h.find('&');
        if (amp != std::string::npos) h.resize(amp);
        return h;
    }
    return locator;
}

bool TorrentFileNameAllowed(const std::string& name, std::string& err)
{
    if (!name.empty() && name.front() == '/') {
        err = "torrent path";
        return false;
    }
    if (name.find("..") != std::string::npos) {
        err = "torrent path";
        return false;
    }
    return true;
}

bool MapTorrentRangeSafe(const std::vector<TorrentFileMap>& files, uint64_t offset, uint64_t length,
                         std::vector<TorrentSlice>& out, std::string& err)
{
    out.clear();
    for (const auto& f : files) {
        if (!TorrentFileNameAllowed(f.name, err)) return false;
    }
    return MapTorrentRange(files, offset, length, out, err);
}

namespace {

void SaturatingAdd(uint64_t& acc, uint64_t n)
{
    if (n > std::numeric_limits<uint64_t>::max() - acc) {
        acc = std::numeric_limits<uint64_t>::max();
    } else {
        acc += n;
    }
}

UniValue ReverseTorrentFlagsJson(bool live, uint64_t bt_to_btx, uint64_t btx_to_torrent)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("reverse_bridge", true);
    o.pushKV("reverse_bridge_live", live);
    o.pushKV("torrentd_process", false);
    o.pushKV("receives_s3_credentials", false);
    o.pushKV("holds_s3_secrets", false);
    o.pushKV("upload_class", TORRENT_REVERSE_UPLOAD_CLASS);
    o.pushKV("provenance_note", TORRENT_PROVENANCE_NOTE);
    o.pushKV("authorship", TORRENT_AUTHORSHIP_NOTE);
    o.pushKV("bt_to_btx_bytes", std::to_string(bt_to_btx));
    o.pushKV("btx_to_torrent_bytes", std::to_string(btx_to_torrent));
    return o;
}

} // namespace

void ReverseTorrentBridge::NoteBtToBtxBytes(uint64_t n)
{
    SaturatingAdd(m_bt_to_btx_bytes, n);
}

void ReverseTorrentBridge::NoteBtxToTorrentBytes(uint64_t n)
{
    SaturatingAdd(m_btx_to_torrent_bytes, n);
}

UniValue ReverseTorrentBridge::Json() const
{
    return ReverseTorrentFlagsJson(/*live=*/true, m_bt_to_btx_bytes, m_btx_to_torrent_bytes);
}

UniValue ReverseTorrentStatusJson(const ReverseTorrentBridge* accounting)
{
    if (!accounting) {
        return ReverseTorrentFlagsJson(/*live=*/false, 0, 0);
    }
    return accounting->Json();
}

TorrentByteSource::TorrentByteSource(std::string locator, std::string infohash,
                                     std::vector<TorrentFileMap> files)
    : m_locator(std::move(locator)), m_infohash(ParseTorrentInfohash(m_locator, std::move(infohash))),
      m_files(std::move(files))
{
}

void TorrentByteSource::InjectFileBytes(const std::string& name, std::vector<unsigned char> bytes)
{
    std::string err;
    if (!TorrentFileNameAllowed(name, err)) return;
    m_payload[name] = std::move(bytes);
    m_pinned = false;
}

std::string TorrentByteSource::Kind() const
{
    return m_locator.starts_with("magnet:") ? "MAGNET" : "TORRENT";
}

bool TorrentByteSource::Pin(std::string& err)
{
    if (m_infohash.empty()) {
        err = "infohash";
        return false;
    }
    bool any = false;
    for (const auto& f : m_files) {
        if (!TorrentFileNameAllowed(f.name, err)) return false;
        if (f.padding) continue;
        any = true;
        const auto it = m_payload.find(f.name);
        if (it == m_payload.end()) {
            err = "missing torrent file";
            return false;
        }
        if (it->second.size() != f.size) {
            err = "torrent file size";
            return false;
        }
    }
    if (!any) {
        err = "no torrent files";
        return false;
    }
    m_pinned = true;
    return true;
}

bool TorrentByteSource::Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
                             std::string& err)
{
    out.clear();
    if (!m_pinned && !Pin(err)) return false;
    if (extent.length > budget_bytes) {
        err = "credit exhausted";
        return false;
    }
    std::vector<TorrentSlice> slices;
    if (!MapTorrentRangeSafe(m_files, extent.offset, extent.length, slices, err)) return false;
    for (const auto& s : slices) {
        if (!TorrentFileNameAllowed(s.name, err)) return false;
        const auto it = m_payload.find(s.name);
        if (it == m_payload.end()) {
            err = "missing torrent file";
            return false;
        }
        if (s.file_offset > it->second.size() || s.length > it->second.size() - s.file_offset) {
            err = "extent";
            return false;
        }
        out.insert(out.end(), it->second.begin() + static_cast<std::ptrdiff_t>(s.file_offset),
                   it->second.begin() + static_cast<std::ptrdiff_t>(s.file_offset + s.length));
    }
    return true;
}

} // namespace modelnet
