// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SOURCE_TORRENT_H
#define BITCOIN_MODELNET_SOURCE_TORRENT_H

#include <modelnet/byte_source.h>
#include <modelnet/erasure_store.h>
#include <univalue.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/** Infohash/piece-tree validates source bytes. It is not a BTX publisher signature. */
inline constexpr const char* TORRENT_PROVENANCE_NOTE =
    "infohash is source integrity, not publisher authorship";

/** Reverse-bridge host class. Accounting only — not a second scheduler. */
inline constexpr const char* TORRENT_REVERSE_UPLOAD_CLASS = "TORRENT_REVERSE";

inline constexpr const char* TORRENT_AUTHORSHIP_NOTE = "not implied by source integrity";

/**
 * Map torrent-global extents through MapTorrentRange. Padding is excluded from
 * returned model bytes. Packaged btx-torrentd / libtorrent is not linked here.
 */
class TorrentByteSource : public ByteSource {
    std::string m_locator;
    std::string m_infohash;
    std::vector<TorrentFileMap> m_files;
    std::map<std::string, std::vector<unsigned char>> m_payload;
    bool m_pinned{false};

public:
    TorrentByteSource(std::string locator, std::string infohash, std::vector<TorrentFileMap> files);
    void InjectFileBytes(const std::string& name, std::vector<unsigned char> bytes);
    bool Pin(std::string& err) override;
    bool Read(const ReadExtent& extent, std::vector<unsigned char>& out, uint64_t budget_bytes,
              std::string& err) override;
    std::string Kind() const override;
    std::string Locator() const override { return m_locator; }
    std::string SourceIntegrity() const override { return m_infohash; }
    std::string ProvenanceNote() const { return TORRENT_PROVENANCE_NOTE; }
};

std::string ParseTorrentInfohash(const std::string& locator, const std::string& snapshot_token);

/** Reject names containing ".." or a leading '/'. Empty names are allowed (padding). */
bool TorrentFileNameAllowed(const std::string& name, std::string& err);

/**
 * MapTorrentRange after TorrentFileNameAllowed on every file name.
 * helper_network02 / TorrentByteSource should call this, not the raw mapper.
 */
bool MapTorrentRangeSafe(const std::vector<TorrentFileMap>& files, uint64_t offset, uint64_t length,
                         std::vector<TorrentSlice>& out, std::string& err);

/**
 * In-process reverse-torrent byte accounting. Does not link libtorrent, spawn
 * btx-torrentd, or hold S3 credentials. UploadClass remains TORRENT_REVERSE.
 *
 * helper_network02 should call ReverseTorrentStatusJson(ptr) and, when a bridge
 * object exists, NoteBtToBtxBytes / NoteBtxToTorrentBytes on it.
 * reverse_bridge_live is true only when that accounting object is non-null.
 */
class ReverseTorrentBridge {
    uint64_t m_bt_to_btx_bytes{0};
    uint64_t m_btx_to_torrent_bytes{0};

public:
    void NoteBtToBtxBytes(uint64_t n);
    void NoteBtxToTorrentBytes(uint64_t n);
    uint64_t BtToBtxBytes() const { return m_bt_to_btx_bytes; }
    uint64_t BtxToTorrentBytes() const { return m_btx_to_torrent_bytes; }

    bool TorrentdProcess() const { return false; }
    bool ReceivesS3Credentials() const { return false; }
    bool HoldsS3Secrets() const { return false; }
    const char* UploadClassName() const { return TORRENT_REVERSE_UPLOAD_CLASS; }
    std::string ProvenanceNote() const { return TORRENT_PROVENANCE_NOTE; }

    /** Member Json: this object exists, so reverse_bridge_live is true. */
    UniValue Json() const;
};

/** Status for gettorrentsourcestatus / settorrentsourcepolicy.
 *  accounting == nullptr → reverse_bridge=true, reverse_bridge_live=false.
 *  accounting != nullptr → reverse_bridge_live=true plus byte counters.
 *  torrentd_process and receives_s3_credentials stay false either way.
 */
UniValue ReverseTorrentStatusJson(const ReverseTorrentBridge* accounting);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SOURCE_TORRENT_H
