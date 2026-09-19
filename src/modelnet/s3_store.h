// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_S3_STORE_H
#define BITCOIN_MODELNET_S3_STORE_H

#include <modelnet/cloud_layout.h>
#include <modelnet/piece_store.h>
#include <modelnet/s3_client.h>
#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>
#include <util/fs.h>

#include <cstdint>
#include <istream>
#include <limits>
#include <mutex>
#include <string>
#include <vector>

namespace modelnet {

struct CloudStoreConfig {
    S3ClientConfig s3;
    CloudProvider provider{CloudProvider::AUTO};
    CloudObjectLayout layout{CloudObjectLayout::AUTO};
    CloudReadStrategy read_strategy{CloudReadStrategy::AUTO};
    bool allow_request_heavy_cloud_layout{false};
    uint64_t projected_piece_objects{0};
    uint64_t budget_origin_bytes{std::numeric_limits<uint64_t>::max()};
    uint64_t budget_gets{std::numeric_limits<uint64_t>::max()};
    uint64_t budget_gets_per_day{std::numeric_limits<uint64_t>::max()};
    uint64_t budget_gets_per_month{std::numeric_limits<uint64_t>::max()};
    uint64_t budget_bytes_per_day{std::numeric_limits<uint64_t>::max()};
    uint64_t budget_bytes_per_month{std::numeric_limits<uint64_t>::max()};
    fs::path budget_state_path;
};

/**
 * S3-compatible CloudObjectStore (Lane B interface). SOURCE_FILES Put streams
 * the file in <= 8 MiB chunks. BTX pieces are not the default cloud object unit.
 */
class S3PieceStore final : public CloudObjectStore
{
    CloudStoreConfig m_cfg;
    S3Client m_client;
    CloudObjectLayout m_layout{CloudObjectLayout::SOURCE_FILES};
    CloudReadStrategy m_strategy{CloudReadStrategy::STREAM_FILE};
    std::string m_prefix;
    bool m_ready{false};
    mutable std::mutex m_mu;
    uint64_t m_used_bytes{0};
    uint64_t m_used_gets{0};
    int64_t m_day_utc{-1};
    int64_t m_month_utc{-1};
    uint64_t m_day_gets{0};
    uint64_t m_month_gets{0};
    uint64_t m_day_bytes{0};
    uint64_t m_month_bytes{0};
    int64_t m_now_override_s{0};

    int64_t NowS() const;
    void RollWindowsLocked(int64_t now_s);
    void PersistBudgetLocked() const;
    void LoadBudgetState();
    bool ChargeGet(uint64_t bytes, std::string& err);
    bool WouldExceed(uint64_t bytes) const;

public:
    explicit S3PieceStore(CloudStoreConfig cfg);
    bool Init(std::string& err);
    bool IsReady() const { return m_ready; }

    bool GetObject(const std::string& key, uint64_t offset, uint64_t len,
                   std::vector<unsigned char>& out, std::string& err) override;
    bool PutObject(const std::string& key, std::istream& body, uint64_t content_length,
                   std::string& err) override;
    bool HeadObject(const std::string& key, uint64_t& size, std::string& err) const override;
    bool DeleteObject(const std::string& key, std::string& err) override;
    PieceStoreHealth Health() const override;

    UniValue HealthJson() const;
    UniValue ConfigJson() const;

    std::string SourceFileKey(const Digest48& artifact, uint32_t file_index) const;
    std::string PieceFileKey(const Digest48& artifact, uint32_t file_index, uint32_t piece_index) const;

    bool PutSourceFile(const Digest48& artifact, uint32_t file_index, const fs::path& src,
                       uint64_t expected_bytes, uint64_t logical_piece_count, std::string& err);
    bool PutPieceObjects(const Digest48& artifact, uint32_t file_index, const fs::path& src,
                         uint64_t expected_bytes, std::string& err);
    bool GetSourceFile(const Digest48& artifact, uint32_t file_index, std::vector<unsigned char>& out,
                       std::string& err);
    bool GetPieceObject(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                        std::vector<unsigned char>& out, std::string& err);

    /** PhysicalObjectLayout WHOLE_FILE / LARGE_EXTENTS. FakeS3 loopback only. */
    bool PutWholeFile(const Digest48& artifact, uint32_t file_index, Span<const unsigned char> body,
                      std::string& err);
    bool GetWholeFile(const Digest48& artifact, uint32_t file_index, std::vector<unsigned char>& out,
                      std::string& err);
    bool PutLargeExtent(const Digest48& artifact, uint32_t file_index, uint32_t extent_index,
                        Span<const unsigned char> body, std::string& err);
    bool GetLargeExtent(const Digest48& artifact, uint32_t file_index, uint32_t extent_index,
                        std::vector<unsigned char>& out, std::string& err);
    bool PresignSourceFileGet(const Digest48& artifact, uint32_t file_index, int ttl_seconds, std::string& url,
                              std::string& err);
    bool FetchPresignedGet(const std::string& url, std::vector<unsigned char>& out, std::string& err);
    void SetClockForTests(int64_t unix_seconds);

    CloudObjectLayout Layout() const { return m_layout; }
    CloudReadStrategy ReadStrategy() const { return m_strategy; }
    S3Client& Client() { return m_client; }
    const S3Client& Client() const { return m_client; }
    FakeS3* FakeForTests() { return m_client.Fake(); }
    const FakeS3* FakeForTests() const { return m_client.Fake(); }
    size_t LastPutMaxBufferBytes() const { return m_client.LastPutMaxBufferBytes(); }
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_S3_STORE_H
