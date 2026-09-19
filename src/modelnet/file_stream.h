// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_FILE_STREAM_H
#define BITCOIN_MODELNET_FILE_STREAM_H

#include <modelnet/store.h>
#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>
#include <util/fs.h>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace modelnet {

/** Negotiated model-plane capability: sequential source-file bootstrap, not random piece GET. */
inline constexpr const char* FULL_FILE_STREAM_V1 = "FULL_FILE_STREAM_V1";

/**
 * Client shortcut gate (RetrieveFreeFromPeer): files larger than this use piece HTTP.
 * FULL_FILE_STREAM_V1 GET responses are capped at this advertised size, not MAX_RPC_BODY.
 */
inline constexpr uint64_t FULL_FILE_STREAM_MAX_BYTES = 64ull << 20;

/** Must match PQ1_HTTP_HEADER_CAP so SslReadHttp can finish headers before the body. */
inline constexpr size_t FULL_FILE_STREAM_HTTP_HEADER_SLACK = 64 * 1024;

/**
 * Upper bound passed to SslReadHttp for GET /files/{artifact}/{index} before
 * Content-Length is known. SslReadHttp then stops at the advertised length.
 * RPC JSON stays at MAX_RPC_BODY; piece HTTP stays at MAX_PIECE_HTTP.
 */
inline constexpr size_t FULL_FILE_STREAM_HTTP_READ_CAP =
    FULL_FILE_STREAM_HTTP_HEADER_SLACK + static_cast<size_t>(FULL_FILE_STREAM_MAX_BYTES);

/** Native GET /files/{artifact}/{index} (not /pieces/, not RPC). */
bool IsFullFileStreamGet(const std::string& method, const std::string& path);

/**
 * Fail-closed body cap for a FULL_FILE_STREAM_V1 GET response.
 * Missing or > FULL_FILE_STREAM_MAX_BYTES Content-Length is refused (no silent truncate).
 * On success, read_cap is header slack + advertised Content-Length.
 */
bool FullFileStreamHttpBodyCap(bool have_content_length, uint64_t content_length, size_t& read_cap, std::string& err);

/** Parse Content-Length from a response and apply FullFileStreamHttpBodyCap. */
bool FullFileStreamAcceptContentLength(const std::string& raw_http, uint64_t& content_length, std::string& err);

struct FileStreamCaps {
    bool random_piece_access{false};
    bool sequential_file_stream{false};
    bool direct_file_seed{false};
    bool local_piece_complete{false};
    bool origin_file_complete{false};
};

UniValue FileStreamCapsJson(const FileStreamCaps& c);

/** Sequential byte source. Implementations MUST keep a bounded read buffer. */
using FileStreamReadFn = std::function<bool(size_t want, unsigned char* buf, size_t& got, std::string& err)>;

struct FileStreamProgress {
    uint64_t bytes_ingested{0};
    uint32_t pieces_verified{0};
    uint32_t next_piece{0};
    uint64_t resume_offset{0};
    int origin_get_ops{0};
    int origin_range_ops{0};
    bool complete{false};
    bool advertised{false};
    bool quarantined{true};
};

/**
 * Durable hydration cursor. No secrets, no URLs, no credentials.
 * resume_offset MUST be N * PIECE_SIZE and equal next_piece * PIECE_SIZE.
 * JSON lives at modeldir/file_stream_jobs/<artifact_hex>-<file_index>.json
 */
struct FileStreamJobRecord {
    Digest48 artifact;
    uint32_t file_index{0};
    uint64_t expected_size{0};
    uint64_t resume_offset{0};
    uint32_t next_piece{0};
    Digest48 expected_sha384{};
    Digest48 expected_root{};
    bool have_sha{false};
    bool have_root{false};
};

using FileStreamJob = FileStreamJobRecord;

fs::path FileStreamJobDir(const fs::path& modeldir);
fs::path FileStreamJobPath(const fs::path& modeldir, const Digest48& artifact, uint32_t file_index);
bool SaveFileStreamJob(const fs::path& modeldir, const FileStreamJobRecord& rec, std::string& err);
bool LoadFileStreamJob(const fs::path& modeldir, const Digest48& artifact, uint32_t file_index,
                        FileStreamJobRecord& rec, std::string& err);
bool DeleteFileStreamJob(const fs::path& modeldir, const Digest48& artifact, uint32_t file_index,
                         std::string& err);

/**
 * Consume a SOURCE_FILES origin stream, split at canonical PIECE_SIZE, verify
 * ChunkLeaf / pieces_root / file SHA-384, then promote into ModelStore.
 * Unverified bytes are never advertised.
 *
 * Resume offset is always N * PIECE_SIZE (one Range per attempt, not per piece).
 */
class FileStreamHydration {
    Digest48 m_artifact;
    uint32_t m_file_index{0};
    uint64_t m_expected_size{0};
    Digest48 m_expected_sha384;
    Digest48 m_expected_root;
    bool m_have_expected_sha{false};
    bool m_have_expected_root{false};
    ModelStore* m_store{nullptr};
    ModelStore* m_quarantine{nullptr};
    fs::path m_job_dir;
    FileStreamProgress m_st;
    std::vector<Digest48> m_leaves;
    std::vector<unsigned char> m_buf;
    size_t m_buf_fill{0};

    bool FlushPiece(std::string& err);
    bool FinishLocked(std::string& err);
    bool PersistJob(std::string& err);

public:
    FileStreamHydration(Digest48 artifact, uint32_t file_index, uint64_t expected_size,
                        ModelStore& live, ModelStore& quarantine);

    void SetExpectedSha384(const Digest48& d);
    void SetExpectedPiecesRoot(const Digest48& d);
    /** Model directory; job JSON is written under file_stream_jobs/. */
    void SetJobDir(fs::path modeldir) { m_job_dir = std::move(modeldir); }

    FileStreamJobRecord ToRecord() const;
    bool ApplyRecord(const FileStreamJobRecord& rec, std::string& err);
    FileStreamJob CurrentJob() const { return ToRecord(); }
    bool ApplyJob(const FileStreamJob& j, std::string& err) { return ApplyRecord(j, err); }

    const FileStreamProgress& Progress() const { return m_st; }
    uint64_t ResumeOffset() const { return uint64_t{m_st.next_piece} * PIECE_SIZE; }

    /** Pull until EOF or error. Increments origin_get_ops once at start unless resume. */
    bool Ingest(const FileStreamReadFn& read, bool resume, std::string& err);

    /** Append already-read bytes (bounded). Does not increment origin counters. */
    bool Feed(Span<const unsigned char> chunk, std::string& err);

    bool Finish(std::string& err);
    bool IsAdvertisable() const { return m_st.complete && !m_st.quarantined; }
};

/** Dedupe identical local hydration jobs (same artifact+file). */
class HydrationCoalescer {
    mutable std::mutex m_mu;
    std::map<std::string, int> m_inflight;
    int m_max_streams_per_object{1};

public:
    void SetMaxStreamsPerObject(int n) { m_max_streams_per_object = std::max(1, n); }
    bool TryBegin(const Digest48& artifact, uint32_t file_index, std::string& err);
    void End(const Digest48& artifact, uint32_t file_index);
    int InFlight(const Digest48& artifact, uint32_t file_index) const;
};

struct OriginDiversity {
    int p2p_complete_providers{0};
    int p2p_partial_providers{0};
    int independent_netgroups{0};
    int cloud_origins{0};
    bool origin_assisted{false};
    bool reconstructable_without_origin{false};
    bool reconstructable_without_this_node{false};
};

/** N BTX front ends on one bucket_id count as one cloud origin. */
OriginDiversity SummarizeOriginDiversity(int p2p_complete, int p2p_partial, int netgroups,
                                          const std::vector<std::string>& origin_ids,
                                          bool enough_p2p_without_origin);
UniValue OriginDiversityJson(const OriginDiversity& d);

/** Structural amplification (no vendor prices). */
UniValue CloudAmplificationJson(uint64_t n_files, uint64_t n_pieces, bool source_files_layout);

/** R2 AUTO / SOURCE_FILES: never one origin GET per missing piece. */
enum class SourceFilesPiecePlan {
    LOCAL_CACHE = 0,
    P2P,
    JOIN_HYDRATION,
    START_FILE_STREAM,
    DIRECT_FILE_SEED,
    ORIGIN_RANGE_PIECE,
};

SourceFilesPiecePlan PlanSourceFilesPieceRequest(bool local_hit, bool p2p_available, bool hydration_inflight,
                                                 bool allow_range_per_piece, bool direct_file_seed);

/** H-T2: sparse 400GiB-equivalent receipt. stored_object_bytes is real FakeS3 size, not disk. */
UniValue SparseOriginScaleReceiptJson(uint64_t logical_bytes, uint64_t stored_object_bytes, uint64_t origin_gets,
                                        uint32_t n_files);

/** H-T3: per-peer and per-netgroup origin GET caps plus a sticky circuit breaker. */
struct OriginStampedeState {
    int64_t window_ms{60000};
    int max_per_peer{8};
    int max_per_netgroup{16};
    int errors_to_open{8};
    int64_t open_ms{60000};
};

class OriginStampedeGuard {
    OriginStampedeState m_s;
    mutable std::mutex m_mu;
    std::map<std::string, std::vector<int64_t>> m_peer_hits;
    std::map<std::string, std::vector<int64_t>> m_ng_hits;
    std::map<std::string, int> m_errors;
    std::map<std::string, int64_t> m_open_until;

    bool CircuitOpenLocked(const std::string& peer, int64_t now_ms) const;

public:
    OriginStampedeGuard() = default;
    explicit OriginStampedeGuard(OriginStampedeState s) : m_s(s) {}

    bool Allow(const std::string& peer, const std::string& netgroup, int64_t now_ms, std::string& err);
    void NoteSuccess(const std::string& peer);
    void NoteError(const std::string& peer, int64_t now_ms);
    bool CircuitOpen(const std::string& peer, int64_t now_ms) const;
    UniValue Json(int64_t now_ms) const;
    void ResetForTests();
};

OriginStampedeGuard& GlobalOriginStampede();

} // namespace modelnet

#endif // BITCOIN_MODELNET_FILE_STREAM_H
