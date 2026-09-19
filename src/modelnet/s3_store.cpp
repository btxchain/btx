// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/s3_store.h>

#include <algorithm>
#include <ctime>
#include <fstream>
#include <limits>
#include <sstream>
#include <system_error>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

bool CapHit(uint64_t used, uint64_t cap, uint64_t add)
{
    if (cap == std::numeric_limits<uint64_t>::max()) return false;
    if (used >= cap) return true;
    return add > cap - used;
}

uint64_t RemainingOrZero(uint64_t used, uint64_t cap)
{
    if (cap == std::numeric_limits<uint64_t>::max()) return std::numeric_limits<uint64_t>::max();
    return used >= cap ? 0 : (cap - used);
}

std::string PhysicalWholeFileKey(const std::string& prefix, const std::string& artifact_hex, uint32_t file_index)
{
    return prefix + "/physical/wf/" + artifact_hex + "/" + std::to_string(file_index);
}

std::string PhysicalLargeExtentKey(const std::string& prefix, const std::string& artifact_hex, uint32_t file_index,
                                   uint32_t extent_index)
{
    return prefix + "/physical/le/" + artifact_hex + "/" + std::to_string(file_index) + "/" +
           std::to_string(extent_index);
}

bool PutSpanObject(S3PieceStore& store, const std::string& key, Span<const unsigned char> body, std::string& err)
{
    const std::string raw(reinterpret_cast<const char*>(body.data()), body.size());
    std::istringstream in(raw);
    return store.PutObject(key, in, body.size(), err);
}

} // namespace

S3PieceStore::S3PieceStore(CloudStoreConfig cfg) : m_cfg(std::move(cfg)) {}

int64_t S3PieceStore::NowS() const
{
    if (m_now_override_s > 0) return m_now_override_s;
    return static_cast<int64_t>(std::time(nullptr));
}

void S3PieceStore::SetClockForTests(int64_t unix_seconds)
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_now_override_s = unix_seconds;
}

void S3PieceStore::RollWindowsLocked(int64_t now_s)
{
    if (now_s < 0) now_s = 0;
    const int64_t day = now_s / 86400;
    std::tm utc{};
    const time_t t = static_cast<time_t>(now_s);
    gmtime_r(&t, &utc);
    const int64_t month = static_cast<int64_t>(utc.tm_year) * 12 + utc.tm_mon;
    if (day != m_day_utc) {
        m_day_utc = day;
        m_day_gets = 0;
        m_day_bytes = 0;
    }
    if (month != m_month_utc) {
        m_month_utc = month;
        m_month_gets = 0;
        m_month_bytes = 0;
    }
}

void S3PieceStore::PersistBudgetLocked() const
{
    if (m_cfg.budget_state_path.empty()) return;
    UniValue o(UniValue::VOBJ);
    o.pushKV("day_utc", m_day_utc);
    o.pushKV("month_utc", m_month_utc);
    o.pushKV("day_gets", m_day_gets);
    o.pushKV("month_gets", m_month_gets);
    o.pushKV("day_bytes", m_day_bytes);
    o.pushKV("month_bytes", m_month_bytes);
    o.pushKV("used_gets", m_used_gets);
    o.pushKV("used_bytes", m_used_bytes);
    const fs::path parent = m_cfg.budget_state_path.parent_path();
    if (!parent.empty()) fs::create_directories(parent);
    std::ofstream out{m_cfg.budget_state_path};
    if (!out) return;
    out << o.write() << "\n";
}

void S3PieceStore::LoadBudgetState()
{
    if (m_cfg.budget_state_path.empty()) return;
    std::ifstream in{m_cfg.budget_state_path};
    if (!in) return;
    std::ostringstream ss;
    ss << in.rdbuf();
    UniValue o;
    if (!o.read(ss.str()) || !o.isObject()) return;
    auto i64 = [&](const char* k, int64_t& dst) {
        if (o.exists(k) && o[k].isNum()) dst = o[k].getInt<int64_t>();
    };
    auto u64 = [&](const char* k, uint64_t& dst) {
        if (o.exists(k) && o[k].isNum()) dst = o[k].getInt<uint64_t>();
    };
    i64("day_utc", m_day_utc);
    i64("month_utc", m_month_utc);
    u64("day_gets", m_day_gets);
    u64("month_gets", m_month_gets);
    u64("day_bytes", m_day_bytes);
    u64("month_bytes", m_month_bytes);
    u64("used_gets", m_used_gets);
    u64("used_bytes", m_used_bytes);
}

bool S3PieceStore::WouldExceed(uint64_t bytes) const
{
    if (CapHit(m_used_gets, m_cfg.budget_gets, 1)) return true;
    if (CapHit(m_used_bytes, m_cfg.budget_origin_bytes, bytes)) return true;
    if (CapHit(m_day_gets, m_cfg.budget_gets_per_day, 1)) return true;
    if (CapHit(m_month_gets, m_cfg.budget_gets_per_month, 1)) return true;
    if (CapHit(m_day_bytes, m_cfg.budget_bytes_per_day, bytes)) return true;
    if (CapHit(m_month_bytes, m_cfg.budget_bytes_per_month, bytes)) return true;
    return false;
}

bool S3PieceStore::ChargeGet(uint64_t bytes, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    RollWindowsLocked(NowS());
    if (WouldExceed(bytes)) {
        err = "cloud origin budget exhausted";
        return false;
    }
    ++m_used_gets;
    m_used_bytes += bytes;
    ++m_day_gets;
    ++m_month_gets;
    m_day_bytes += bytes;
    m_month_bytes += bytes;
    PersistBudgetLocked();
    return true;
}

bool S3PieceStore::Init(std::string& err)
{
    m_ready = false;
    if (!NormalizeCloudKeyPrefix(m_cfg.s3.prefix, m_prefix, err)) return false;
    m_cfg.s3.prefix = m_prefix;
    if (m_cfg.s3.region.empty() && CloudProviderIsR2(m_cfg.provider, m_cfg.s3.endpoint)) {
        m_cfg.s3.region = "auto";
    }
    std::string reject;
    if (!ResolveCloudLayout(m_cfg.provider, m_cfg.s3.endpoint, m_cfg.layout,
                            m_cfg.allow_request_heavy_cloud_layout, m_cfg.projected_piece_objects, m_layout,
                            m_strategy, reject)) {
        err = reject.empty() ? "cloud layout rejected" : reject;
        return false;
    }
    if (!m_client.Init(m_cfg.s3, err)) return false;
    LoadBudgetState();
    {
        std::lock_guard<std::mutex> lock(m_mu);
        RollWindowsLocked(NowS());
        PersistBudgetLocked();
    }
    m_ready = true;
    return true;
}

bool S3PieceStore::GetObject(const std::string& key, uint64_t offset, uint64_t len,
                             std::vector<unsigned char>& out, std::string& err)
{
    if (!m_ready) {
        err = "s3 store not initialized";
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(m_mu);
        RollWindowsLocked(NowS());
        if (WouldExceed(/*bytes unknown; check GET count first*/ 0)) {
            err = "cloud origin budget exhausted";
            return false;
        }
    }
    bool ok = false;
    if (offset == 0 && len == 0) {
        ok = m_client.Get(key, out, err);
    } else {
        ok = m_client.RangeGet(key, offset, len, out, err);
    }
    if (!ok) return false;
    if (!ChargeGet(out.size(), err)) {
        out.clear();
        return false;
    }
    return true;
}

bool S3PieceStore::PutObject(const std::string& key, std::istream& body, uint64_t content_length, std::string& err)
{
    if (!m_ready) {
        err = "s3 store not initialized";
        return false;
    }
    if (key.empty() || key.find("..") != std::string::npos) {
        err = "invalid object key";
        return false;
    }
    return m_client.PutStream(key, body, content_length, err);
}

bool S3PieceStore::HeadObject(const std::string& key, uint64_t& size, std::string& err) const
{
    if (!m_ready) {
        err = "s3 store not initialized";
        return false;
    }
    return m_client.Head(key, size, err);
}

bool S3PieceStore::DeleteObject(const std::string& key, std::string& err)
{
    if (!m_ready) {
        err = "s3 store not initialized";
        return false;
    }
    return m_client.Delete(key, err);
}

PieceStoreHealth S3PieceStore::Health() const
{
    PieceStoreHealth h;
    h.backend = m_client.UsesFake() ? "fake-s3" : "s3";
    h.local_bytes = 0;
    if (!m_ready) {
        h.ok = false;
        h.error = "not initialized";
        return h;
    }
    if (auto* fake = m_client.Fake()) {
        h.cloud_objects = fake->ObjectCount();
    }
    h.ok = true;
    return h;
}

UniValue S3PieceStore::HealthJson() const
{
    UniValue o = m_client.HealthJson();
    o.pushKV("layout", CloudObjectLayoutName(m_layout));
    o.pushKV("read_strategy", CloudReadStrategyName(m_strategy));
    o.pushKV("provider", CloudProviderName(m_cfg.provider));
    o.pushKV("budget_gets_limited", m_cfg.budget_gets != std::numeric_limits<uint64_t>::max());
    o.pushKV("budget_bytes_limited", m_cfg.budget_origin_bytes != std::numeric_limits<uint64_t>::max());
    o.pushKV("budget_gets_per_day_limited", m_cfg.budget_gets_per_day != std::numeric_limits<uint64_t>::max());
    o.pushKV("budget_gets_per_month_limited", m_cfg.budget_gets_per_month != std::numeric_limits<uint64_t>::max());
    o.pushKV("budget_bytes_per_day_limited", m_cfg.budget_bytes_per_day != std::numeric_limits<uint64_t>::max());
    o.pushKV("budget_bytes_per_month_limited", m_cfg.budget_bytes_per_month != std::numeric_limits<uint64_t>::max());
    {
        std::lock_guard<std::mutex> lock(m_mu);
        o.pushKV("origin_bytes", m_used_bytes);
        o.pushKV("budget_used_gets", m_used_gets);
        o.pushKV("budget_day_utc", m_day_utc);
        o.pushKV("budget_month_utc", m_month_utc);
        o.pushKV("budget_used_gets_day", m_day_gets);
        o.pushKV("budget_used_gets_month", m_month_gets);
        o.pushKV("budget_used_bytes_day", m_day_bytes);
        o.pushKV("budget_used_bytes_month", m_month_bytes);
        auto push_rem = [&](const char* key, uint64_t used, uint64_t cap) {
            if (cap == std::numeric_limits<uint64_t>::max()) {
                o.pushKV(key, UniValue{});
            } else {
                o.pushKV(key, RemainingOrZero(used, cap));
            }
        };
        push_rem("budget_gets_remaining", m_used_gets, m_cfg.budget_gets);
        push_rem("budget_bytes_remaining", m_used_bytes, m_cfg.budget_origin_bytes);
        push_rem("budget_gets_remaining_day", m_day_gets, m_cfg.budget_gets_per_day);
        push_rem("budget_gets_remaining_month", m_month_gets, m_cfg.budget_gets_per_month);
        push_rem("budget_bytes_remaining_day", m_day_bytes, m_cfg.budget_bytes_per_day);
        push_rem("budget_bytes_remaining_month", m_month_bytes, m_cfg.budget_bytes_per_month);
    }
    return o;
}

UniValue S3PieceStore::ConfigJson() const
{
    UniValue o = m_client.ConfigJson();
    o.pushKV("layout", CloudObjectLayoutName(m_layout));
    o.pushKV("read_strategy", CloudReadStrategyName(m_strategy));
    o.pushKV("provider", CloudProviderName(m_cfg.provider));
    o.pushKV("allow_request_heavy_cloud_layout", m_cfg.allow_request_heavy_cloud_layout);
    o.pushKV("projected_piece_objects", m_cfg.projected_piece_objects);
    auto persist_cap = [&](const char* key, uint64_t v) {
        if (v != std::numeric_limits<uint64_t>::max()) o.pushKV(key, v);
    };
    persist_cap("budget_gets", m_cfg.budget_gets);
    persist_cap("budget_origin_bytes", m_cfg.budget_origin_bytes);
    persist_cap("budget_gets_per_day", m_cfg.budget_gets_per_day);
    persist_cap("budget_gets_per_month", m_cfg.budget_gets_per_month);
    persist_cap("budget_bytes_per_day", m_cfg.budget_bytes_per_day);
    persist_cap("budget_bytes_per_month", m_cfg.budget_bytes_per_month);
    return o;
}

std::string S3PieceStore::SourceFileKey(const Digest48& artifact, uint32_t file_index) const
{
    return ObjectKeySourceFile(m_prefix, artifact.Hex(), file_index);
}

std::string S3PieceStore::PieceFileKey(const Digest48& artifact, uint32_t file_index, uint32_t piece_index) const
{
    return ObjectKeyPiece(m_prefix, artifact.Hex(), file_index, piece_index);
}

bool S3PieceStore::PutSourceFile(const Digest48& artifact, uint32_t file_index, const fs::path& src,
                                 uint64_t expected_bytes, uint64_t logical_piece_count, std::string& err)
{
    if (m_layout != CloudObjectLayout::SOURCE_FILES) {
        err = "PutSourceFile requires SOURCE_FILES layout";
        return false;
    }
    std::error_code ec;
    const auto sz = fs::file_size(src, ec);
    if (ec) {
        err = "source file size unavailable";
        return false;
    }
    if (static_cast<uint64_t>(sz) != expected_bytes) {
        err = "object bytes must equal FileEntry size";
        return false;
    }
    std::ifstream in{src, std::ios::binary};
    if (!in) {
        err = "failed to open source file";
        return false;
    }
    const std::string key = ObjectKeySourceFile(m_prefix, artifact.Hex(), file_index);
    if (!PutObject(key, in, expected_bytes, err)) return false;
    if (auto* fake = m_client.Fake()) {
        fake->SetMeta(key, "logical_piece_count", std::to_string(logical_piece_count));
        fake->SetMeta(key, "file_entry_bytes", std::to_string(expected_bytes));
    }
    return true;
}

bool S3PieceStore::PutPieceObjects(const Digest48& artifact, uint32_t file_index, const fs::path& src,
                                  uint64_t expected_bytes, std::string& err)
{
    if (m_layout != CloudObjectLayout::PIECE_OBJECTS) {
        err = "PutPieceObjects requires PIECE_OBJECTS layout";
        return false;
    }
    std::error_code ec;
    const auto sz = fs::file_size(src, ec);
    if (ec) {
        err = "source file size unavailable";
        return false;
    }
    if (static_cast<uint64_t>(sz) != expected_bytes) {
        err = "object bytes must equal FileEntry size";
        return false;
    }
    std::ifstream in{src, std::ios::binary};
    if (!in) {
        err = "failed to open source file";
        return false;
    }
    const uint64_t n = expected_bytes == 0 ? 1 : ((expected_bytes + PIECE_SIZE - 1) / PIECE_SIZE);
    std::vector<char> buf(PIECE_SIZE);
    for (uint64_t p = 0; p < n; ++p) {
        const uint64_t off = p * PIECE_SIZE;
        const uint64_t want = expected_bytes == 0 ? 0 : std::min<uint64_t>(PIECE_SIZE, expected_bytes - off);
        if (want > 0) {
            in.read(buf.data(), static_cast<std::streamsize>(want));
            if (static_cast<uint64_t>(in.gcount()) != want) {
                err = "short read while splitting PIECE_OBJECTS";
                return false;
            }
        }
        const std::string key = ObjectKeyPiece(m_prefix, artifact.Hex(), file_index, static_cast<uint32_t>(p));
        const std::string raw(buf.data(), static_cast<size_t>(want));
        std::istringstream piece_in(raw);
        if (!PutObject(key, piece_in, want, err)) return false;
        if (auto* fake = m_client.Fake()) {
            fake->SetMeta(key, "file_entry_bytes", std::to_string(expected_bytes));
            fake->SetMeta(key, "piece_index", std::to_string(p));
            fake->SetMeta(key, "logical_piece_count", std::to_string(n));
        }
    }
    return true;
}

bool S3PieceStore::GetSourceFile(const Digest48& artifact, uint32_t file_index, std::vector<unsigned char>& out,
                                 std::string& err)
{
    const std::string key = ObjectKeySourceFile(m_prefix, artifact.Hex(), file_index);
    return GetObject(key, 0, 0, out, err);
}

bool S3PieceStore::GetPieceObject(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                  std::vector<unsigned char>& out, std::string& err)
{
    const std::string key = ObjectKeyPiece(m_prefix, artifact.Hex(), file_index, piece_index);
    return GetObject(key, 0, 0, out, err);
}

bool S3PieceStore::PresignSourceFileGet(const Digest48& artifact, uint32_t file_index, int ttl_seconds,
                                        std::string& url, std::string& err)
{
    if (m_layout != CloudObjectLayout::SOURCE_FILES) {
        err = "direct seed presign of a source file requires SOURCE_FILES layout";
        return false;
    }
    const std::string key = ObjectKeySourceFile(m_prefix, artifact.Hex(), file_index);
    return m_client.PresignGet(key, ttl_seconds, url, err);
}

bool S3PieceStore::PutWholeFile(const Digest48& artifact, uint32_t file_index, Span<const unsigned char> body,
                                std::string& err)
{
    if (!m_cfg.s3.use_fake) {
        err = "WHOLE_FILE store I/O requires FakeS3";
        return false;
    }
    const std::string key = PhysicalWholeFileKey(m_prefix, artifact.Hex(), file_index);
    return PutSpanObject(*this, key, body, err);
}

bool S3PieceStore::GetWholeFile(const Digest48& artifact, uint32_t file_index, std::vector<unsigned char>& out,
                                std::string& err)
{
    if (!m_cfg.s3.use_fake) {
        err = "WHOLE_FILE store I/O requires FakeS3";
        return false;
    }
    const std::string key = PhysicalWholeFileKey(m_prefix, artifact.Hex(), file_index);
    return GetObject(key, 0, 0, out, err);
}

bool S3PieceStore::PutLargeExtent(const Digest48& artifact, uint32_t file_index, uint32_t extent_index,
                                  Span<const unsigned char> body, std::string& err)
{
    if (!m_cfg.s3.use_fake) {
        err = "LARGE_EXTENTS store I/O requires FakeS3";
        return false;
    }
    const std::string key = PhysicalLargeExtentKey(m_prefix, artifact.Hex(), file_index, extent_index);
    return PutSpanObject(*this, key, body, err);
}

bool S3PieceStore::GetLargeExtent(const Digest48& artifact, uint32_t file_index, uint32_t extent_index,
                                  std::vector<unsigned char>& out, std::string& err)
{
    if (!m_cfg.s3.use_fake) {
        err = "LARGE_EXTENTS store I/O requires FakeS3";
        return false;
    }
    const std::string key = PhysicalLargeExtentKey(m_prefix, artifact.Hex(), file_index, extent_index);
    return GetObject(key, 0, 0, out, err);
}

bool S3PieceStore::FetchPresignedGet(const std::string& url, std::vector<unsigned char>& out, std::string& err)
{
    if (!m_ready) {
        err = "s3 store not initialized";
        return false;
    }
    if (!m_client.FetchPresignedGet(url, out, err)) return false;
    if (!ChargeGet(out.size(), err)) {
        out.clear();
        return false;
    }
    return true;
}

} // namespace modelnet
