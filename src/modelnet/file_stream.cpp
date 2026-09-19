// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/file_stream.h>

#include <crypto/sha384.h>
#include <span.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/readwritefile.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <set>
#include <stdexcept>
#include <vector>

namespace modelnet {
namespace {

std::string JobKey(const Digest48& artifact, uint32_t file_index)
{
    return artifact.Hex() + ":" + std::to_string(file_index);
}

bool JobJsonForbidden(const std::string& raw)
{
    return raw.find('?') != std::string::npos || raw.find("SECRET") != std::string::npos ||
           raw.find("://") != std::string::npos;
}

bool ResumeOffsetAligned(uint64_t off)
{
    return off % PIECE_SIZE == 0;
}

/** Fill next_piece from resume_offset when omitted; reject unaligned or mismatched cursors. */
bool NormalizeResumeCursor(FileStreamJobRecord& rec, std::string& err)
{
    if (!ResumeOffsetAligned(rec.resume_offset)) {
        err = "resume_offset must be a multiple of PIECE_SIZE";
        return false;
    }
    const uint64_t n64 = rec.resume_offset / PIECE_SIZE;
    if (n64 > UINT32_MAX) {
        err = "file stream job too many pieces";
        return false;
    }
    const uint32_t n = static_cast<uint32_t>(n64);
    if (rec.next_piece == 0) {
        rec.next_piece = n;
    } else if (rec.next_piece != n) {
        err = "resume_offset must equal next_piece * PIECE_SIZE";
        return false;
    }
    return true;
}

bool CopyPiece(ModelStore& from, ModelStore& to, const Digest48& artifact, uint32_t file_index,
               uint32_t piece_index, const Digest48& leaf, std::string& err)
{
    std::vector<unsigned char> bytes;
    if (!from.GetPiece(artifact, file_index, piece_index, bytes, err)) return false;
    return to.PutVerifiedPiece(artifact, file_index, piece_index, bytes, leaf, err);
}

} // namespace

bool IsFullFileStreamGet(const std::string& method, const std::string& path)
{
    if (method != "GET") return false;
    if (path.find("/files/") == std::string::npos) return false;
    if (path.find("/pieces/") != std::string::npos) return false;
    return true;
}

bool FullFileStreamHttpBodyCap(bool have_content_length, uint64_t content_length, size_t& read_cap, std::string& err)
{
    read_cap = 0;
    if (!have_content_length) {
        err = "file stream missing Content-Length";
        return false;
    }
    if (content_length > FULL_FILE_STREAM_MAX_BYTES) {
        err = "file stream body too large";
        return false;
    }
    read_cap = FULL_FILE_STREAM_HTTP_HEADER_SLACK + static_cast<size_t>(content_length);
    return true;
}

bool FullFileStreamAcceptContentLength(const std::string& raw_http, uint64_t& content_length, std::string& err)
{
    content_length = 0;
    const auto pos = raw_http.find("\r\n\r\n");
    if (pos == std::string::npos) {
        err = "truncated http";
        return false;
    }
    auto cl = raw_http.find("Content-Length:");
    if (cl == std::string::npos) cl = raw_http.find("content-length:");
    if (cl == std::string::npos || cl >= pos) {
        err = "file stream missing Content-Length";
        return false;
    }
    const char* p = raw_http.c_str() + cl + 15;
    const char* const hdr_end = raw_http.c_str() + pos;
    if (p > hdr_end) {
        err = "file stream missing Content-Length";
        return false;
    }
    while (p < hdr_end && (*p == ' ' || *p == '\t')) ++p;
    if (p >= hdr_end || *p < '0' || *p > '9') {
        err = "file stream Content-Length";
        return false;
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long long v = std::strtoull(p, &end, 10);
    if (errno == ERANGE || end == p || end > hdr_end) {
        err = "file stream Content-Length";
        return false;
    }
    while (end < hdr_end && (*end == ' ' || *end == '\t')) ++end;
    if (end < hdr_end && *end != '\r' && *end != '\n') {
        err = "file stream Content-Length";
        return false;
    }
    content_length = static_cast<uint64_t>(v);
    size_t read_cap = 0;
    return FullFileStreamHttpBodyCap(true, content_length, read_cap, err);
}

UniValue FileStreamCapsJson(const FileStreamCaps& c)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("capability", FULL_FILE_STREAM_V1);
    o.pushKV("random_piece_access", c.random_piece_access);
    o.pushKV("sequential_file_stream", c.sequential_file_stream);
    o.pushKV("direct_file_seed", c.direct_file_seed);
    o.pushKV("local_piece_complete", c.local_piece_complete);
    o.pushKV("origin_file_complete", c.origin_file_complete);
    return o;
}

fs::path FileStreamJobDir(const fs::path& modeldir)
{
    return modeldir / fs::PathFromString("file_stream_jobs");
}

fs::path FileStreamJobPath(const fs::path& modeldir, const Digest48& artifact, uint32_t file_index)
{
    return FileStreamJobDir(modeldir) /
           fs::PathFromString(artifact.Hex() + "-" + std::to_string(file_index) + ".json");
}

bool SaveFileStreamJob(const fs::path& modeldir, const FileStreamJobRecord& rec, std::string& err)
{
    if (modeldir.empty()) {
        err = "missing file stream job directory";
        return false;
    }
    FileStreamJobRecord j = rec;
    if (!NormalizeResumeCursor(j, err)) return false;

    const fs::path dir = FileStreamJobDir(modeldir);
    try {
        if (!TryCreateDirectories(dir) && !fs::exists(dir)) {
            err = "cannot create file stream job directory";
            return false;
        }
    } catch (const fs::filesystem_error& e) {
        err = e.what();
        return false;
    }

    UniValue o(UniValue::VOBJ);
    o.pushKV("capability", FULL_FILE_STREAM_V1);
    o.pushKV("artifact", j.artifact.Hex());
    o.pushKV("file_index", static_cast<int64_t>(j.file_index));
    o.pushKV("expected_size", static_cast<int64_t>(j.expected_size));
    o.pushKV("resume_offset", static_cast<int64_t>(j.resume_offset));
    o.pushKV("next_piece", static_cast<int64_t>(j.next_piece));
    o.pushKV("have_sha", j.have_sha);
    o.pushKV("have_root", j.have_root);
    if (j.have_sha) o.pushKV("expected_sha384", j.expected_sha384.Hex());
    if (j.have_root) o.pushKV("expected_root", j.expected_root.Hex());
    o.pushKV("automatic_spend_atoms", 0);

    const std::string raw = o.write() + "\n";
    if (JobJsonForbidden(raw)) {
        err = "file stream job json must not contain secrets or URLs";
        return false;
    }
    if (!WriteBinaryFile(FileStreamJobPath(modeldir, j.artifact, j.file_index), raw)) {
        err = "failed to write file stream job";
        return false;
    }
    return true;
}

bool LoadFileStreamJob(const fs::path& modeldir, const Digest48& artifact, uint32_t file_index,
                        FileStreamJobRecord& rec, std::string& err)
{
    rec = FileStreamJobRecord{};
    const fs::path path = FileStreamJobPath(modeldir, artifact, file_index);
    const auto [ok, raw] = ReadBinaryFile(path, /*maxsize=*/65536);
    if (!ok || raw.empty()) {
        err = "no file stream job";
        return false;
    }
    if (raw.size() > 65536) {
        err = "file stream job too large";
        return false;
    }
    if (JobJsonForbidden(raw)) {
        err = "file stream job json must not contain secrets or URLs";
        return false;
    }
    UniValue obj;
    if (!obj.read(raw) || !obj.isObject()) {
        err = "invalid file stream job";
        return false;
    }
    try {
        if (!obj.exists("artifact") || !obj["artifact"].isStr() ||
            !Digest48::FromHex(obj["artifact"].get_str(), rec.artifact, err)) {
            if (err.empty()) err = "file stream job artifact";
            return false;
        }
        if (rec.artifact != artifact) {
            err = "file stream job artifact mismatch";
            return false;
        }
        if (!obj.exists("file_index")) {
            err = "file stream job file_index";
            return false;
        }
        const int64_t fi = obj["file_index"].getInt<int64_t>();
        if (fi < 0 || fi > static_cast<int64_t>(UINT32_MAX)) {
            err = "file stream job file_index";
            return false;
        }
        rec.file_index = static_cast<uint32_t>(fi);
        if (rec.file_index != file_index) {
            err = "file stream job file_index mismatch";
            return false;
        }
        if (!obj.exists("expected_size")) {
            err = "file stream job expected_size";
            return false;
        }
        rec.expected_size = obj["expected_size"].getInt<uint64_t>();
        if (!obj.exists("resume_offset")) {
            err = "file stream job resume_offset";
            return false;
        }
        rec.resume_offset = obj["resume_offset"].getInt<uint64_t>();
        if (!ResumeOffsetAligned(rec.resume_offset)) {
            err = "resume_offset must be a multiple of PIECE_SIZE";
            return false;
        }
        if (obj.exists("next_piece")) {
            const int64_t np = obj["next_piece"].getInt<int64_t>();
            if (np < 0 || np > static_cast<int64_t>(UINT32_MAX)) {
                err = "file stream job next_piece";
                return false;
            }
            rec.next_piece = static_cast<uint32_t>(np);
        }
        if (!NormalizeResumeCursor(rec, err)) return false;
        if (obj.exists("automatic_spend_atoms") && obj["automatic_spend_atoms"].getInt<int64_t>() != 0) {
            err = "file stream job automatic_spend_atoms must be 0";
            return false;
        }
        rec.have_sha = obj.exists("have_sha") && obj["have_sha"].get_bool();
        rec.have_root = obj.exists("have_root") && obj["have_root"].get_bool();
        if (obj.exists("expected_sha384") && obj["expected_sha384"].isStr() &&
            !obj["expected_sha384"].get_str().empty()) {
            if (!Digest48::FromHex(obj["expected_sha384"].get_str(), rec.expected_sha384, err)) return false;
            rec.have_sha = true;
        } else if (rec.have_sha) {
            err = "file stream job expected_sha384";
            return false;
        }
        if (obj.exists("expected_root") && obj["expected_root"].isStr() &&
            !obj["expected_root"].get_str().empty()) {
            if (!Digest48::FromHex(obj["expected_root"].get_str(), rec.expected_root, err)) return false;
            rec.have_root = true;
        } else if (rec.have_root) {
            err = "file stream job expected_root";
            return false;
        }
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
    return true;
}

bool DeleteFileStreamJob(const fs::path& modeldir, const Digest48& artifact, uint32_t file_index,
                         std::string& err)
{
    const fs::path path = FileStreamJobPath(modeldir, artifact, file_index);
    std::error_code ec;
    fs::remove(path, ec);
    if (fs::exists(path)) {
        err = "failed to delete file stream job";
        return false;
    }
    return true;
}

FileStreamHydration::FileStreamHydration(Digest48 artifact, uint32_t file_index, uint64_t expected_size,
                                           ModelStore& live, ModelStore& quarantine)
    : m_artifact(artifact), m_file_index(file_index), m_expected_size(expected_size),
      m_store(&live), m_quarantine(&quarantine), m_buf(PIECE_SIZE, 0)
{
    m_st.quarantined = true;
}

void FileStreamHydration::SetExpectedSha384(const Digest48& d)
{
    m_expected_sha384 = d;
    m_have_expected_sha = true;
}

void FileStreamHydration::SetExpectedPiecesRoot(const Digest48& d)
{
    m_expected_root = d;
    m_have_expected_root = true;
}

FileStreamJobRecord FileStreamHydration::ToRecord() const
{
    FileStreamJobRecord rec;
    rec.artifact = m_artifact;
    rec.file_index = m_file_index;
    rec.expected_size = m_expected_size;
    rec.resume_offset = ResumeOffset();
    rec.next_piece = m_st.next_piece;
    rec.expected_sha384 = m_expected_sha384;
    rec.expected_root = m_expected_root;
    rec.have_sha = m_have_expected_sha;
    rec.have_root = m_have_expected_root;
    return rec;
}

bool FileStreamHydration::PersistJob(std::string& err)
{
    if (m_job_dir.empty()) return true;
    return SaveFileStreamJob(m_job_dir, ToRecord(), err);
}

bool FileStreamHydration::ApplyRecord(const FileStreamJobRecord& rec, std::string& err)
{
    if (m_st.complete) {
        err = "stream already finished";
        return false;
    }
    if (m_buf_fill != 0 || m_st.next_piece != 0 || !m_leaves.empty()) {
        err = "hydration already started";
        return false;
    }
    if (rec.artifact != m_artifact || rec.file_index != m_file_index) {
        err = "file stream job identity mismatch";
        return false;
    }
    if (rec.expected_size != m_expected_size) {
        err = "file stream job expected_size mismatch";
        return false;
    }
    FileStreamJobRecord norm = rec;
    if (!NormalizeResumeCursor(norm, err)) return false;
    // Cursor only: verified pieces already live in ModelStore. Do not re-ingest.
    m_st.next_piece = norm.next_piece;
    m_st.pieces_verified = norm.next_piece;
    m_st.bytes_ingested = norm.resume_offset;
    m_st.resume_offset = norm.resume_offset;
    if (norm.have_sha) SetExpectedSha384(norm.expected_sha384);
    if (norm.have_root) SetExpectedPiecesRoot(norm.expected_root);
    return true;
}

bool FileStreamHydration::FlushPiece(std::string& err)
{
    if (m_buf_fill == 0) return true;
    if (m_st.complete) {
        err = "stream already finished";
        return false;
    }
    const uint64_t already = m_st.bytes_ingested;
    if (already + m_buf_fill > m_expected_size) {
        err = "stream longer than expected file";
        return false;
    }
    Span<const unsigned char> piece{m_buf.data(), m_buf_fill};
    const Digest48 leaf = ChunkLeaf(m_st.next_piece, piece);
    if (!m_quarantine->PutVerifiedPiece(m_artifact, m_file_index, m_st.next_piece, piece, leaf, err)) {
        return false;
    }
    m_leaves.push_back(leaf);
    m_st.bytes_ingested += m_buf_fill;
    m_st.pieces_verified += 1;
    m_st.next_piece += 1;
    m_st.resume_offset = uint64_t{m_st.next_piece} * PIECE_SIZE;
    m_buf_fill = 0;
    m_st.advertised = false;
    return PersistJob(err);
}

bool FileStreamHydration::Feed(Span<const unsigned char> chunk, std::string& err)
{
    size_t off = 0;
    while (off < chunk.size()) {
        const size_t room = PIECE_SIZE - m_buf_fill;
        const size_t n = std::min(room, chunk.size() - off);
        std::memcpy(m_buf.data() + m_buf_fill, chunk.data() + off, n);
        m_buf_fill += n;
        off += n;
        if (m_buf_fill == PIECE_SIZE) {
            if (!FlushPiece(err)) return false;
        }
    }
    return true;
}

bool FileStreamHydration::Ingest(const FileStreamReadFn& read, bool resume, std::string& err)
{
    if (!read) {
        err = "missing stream reader";
        return false;
    }
    if (resume) {
        m_st.origin_range_ops += 1;
    } else {
        m_st.origin_get_ops += 1;
    }
    std::vector<unsigned char> tmp(1 << 16);
    while (m_st.bytes_ingested + m_buf_fill < m_expected_size) {
        const uint64_t remain = m_expected_size - m_st.bytes_ingested - m_buf_fill;
        const size_t want = static_cast<size_t>(std::min<uint64_t>(tmp.size(), remain));
        size_t got = 0;
        if (!read(want, tmp.data(), got, err)) return false;
        if (got == 0) break;
        if (!Feed(Span<const unsigned char>{tmp.data(), got}, err)) return false;
    }
    return Finish(err);
}

bool FileStreamHydration::Finish(std::string& err)
{
    if (!FinishLocked(err)) return false;
    if (m_job_dir.empty()) return true;
    return DeleteFileStreamJob(m_job_dir, m_artifact, m_file_index, err);
}

bool FileStreamHydration::FinishLocked(std::string& err)
{
    if (m_st.complete) return true;
    if (m_buf_fill > 0) {
        const uint64_t remain = m_expected_size - m_st.bytes_ingested;
        if (m_buf_fill != remain) {
            err = "partial last piece before EOF";
            return false;
        }
        if (!FlushPiece(err)) return false;
    }
    if (m_st.bytes_ingested != m_expected_size) {
        err = "short stream";
        return false;
    }

    CSHA384 hasher;
    m_leaves.clear();
    m_leaves.reserve(m_st.next_piece);
    for (uint32_t i = 0; i < m_st.next_piece; ++i) {
        std::vector<unsigned char> bytes;
        if (!m_quarantine->GetPiece(m_artifact, m_file_index, i, bytes, err)) return false;
        hasher.Write(bytes.data(), bytes.size());
        m_leaves.push_back(ChunkLeaf(i, bytes));
    }
    Digest48 sha;
    hasher.Finalize(sha.data.data());
    if (m_have_expected_sha && sha != m_expected_sha384) {
        err = "file SHA-384 mismatch";
        return false;
    }

    PieceIndex idx;
    idx.file_size = m_expected_size;
    if (m_expected_size == 0) {
        idx.leaves = {EmptyFileRoot()};
        idx.pieces_root = EmptyFileRoot();
    } else {
        const size_t n = m_leaves.size();
        size_t width = 1;
        while (width < n) width <<= 1;
        idx.leaves = m_leaves;
        for (size_t i = n; i < width; ++i) idx.leaves.push_back(ChunkPad(i));
        const auto rows = BuildChunkTreeFromLeaves(idx.leaves);
        if (rows.empty()) {
            err = "chunk tree";
            return false;
        }
        idx.pieces_root = rows.back()[0];
    }
    if (m_have_expected_root && idx.pieces_root != m_expected_root) {
        err = "pieces_root mismatch";
        return false;
    }
    if (!m_quarantine->SavePieceIndex(m_artifact, m_file_index, idx, err)) return false;

    for (uint32_t i = 0; i < m_st.next_piece; ++i) {
        if (!CopyPiece(*m_quarantine, *m_store, m_artifact, m_file_index, i, m_leaves[i], err)) {
            return false;
        }
    }
    if (!m_store->SavePieceIndex(m_artifact, m_file_index, idx, err)) return false;

    m_st.complete = true;
    m_st.quarantined = false;
    m_st.advertised = true;
    return true;
}

bool HydrationCoalescer::TryBegin(const Digest48& artifact, uint32_t file_index, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    const std::string k = JobKey(artifact, file_index);
    if (m_inflight[k] >= m_max_streams_per_object) {
        err = "origin hydration already in flight";
        return false;
    }
    m_inflight[k] += 1;
    return true;
}

void HydrationCoalescer::End(const Digest48& artifact, uint32_t file_index)
{
    std::lock_guard<std::mutex> lock(m_mu);
    const std::string k = JobKey(artifact, file_index);
    auto it = m_inflight.find(k);
    if (it == m_inflight.end()) return;
    if (it->second <= 1) m_inflight.erase(it);
    else it->second -= 1;
}

int HydrationCoalescer::InFlight(const Digest48& artifact, uint32_t file_index) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    const auto it = m_inflight.find(JobKey(artifact, file_index));
    return it == m_inflight.end() ? 0 : it->second;
}

OriginDiversity SummarizeOriginDiversity(int p2p_complete, int p2p_partial, int netgroups,
                                          const std::vector<std::string>& origin_ids,
                                          bool enough_p2p_without_origin)
{
    OriginDiversity d;
    d.p2p_complete_providers = p2p_complete;
    d.p2p_partial_providers = p2p_partial;
    d.independent_netgroups = netgroups;
    std::set<std::string> uniq;
    for (const auto& id : origin_ids) {
        if (!id.empty()) uniq.insert(id);
    }
    d.cloud_origins = static_cast<int>(uniq.size());
    d.origin_assisted = d.cloud_origins > 0;
    d.reconstructable_without_origin = enough_p2p_without_origin;
    d.reconstructable_without_this_node = p2p_complete > 0;
    return d;
}

UniValue OriginDiversityJson(const OriginDiversity& d)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("p2p_complete_providers", d.p2p_complete_providers);
    o.pushKV("p2p_partial_providers", d.p2p_partial_providers);
    o.pushKV("independent_netgroups", d.independent_netgroups);
    o.pushKV("cloud_origins", d.cloud_origins);
    o.pushKV("origin_assisted", d.origin_assisted);
    o.pushKV("reconstructable_without_origin", d.reconstructable_without_origin);
    o.pushKV("reconstructable_without_this_node", d.reconstructable_without_this_node);
    o.pushKV("note", "cloud front-ends sharing one bucket are one origin");
    return o;
}

UniValue CloudAmplificationJson(uint64_t n_files, uint64_t n_pieces, bool source_files_layout)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("logical_btx_pieces", static_cast<int64_t>(n_pieces));
    o.pushKV("cloud_source_objects", static_cast<int64_t>(source_files_layout ? n_files : n_pieces));
    o.pushKV("estimated_cloud_gets_per_cold_full_retrieval",
             static_cast<int64_t>(source_files_layout ? n_files : n_pieces));
    o.pushKV("piece_object_equivalent_gets", static_cast<int64_t>(n_pieces));
    o.pushKV("layout", source_files_layout ? "SOURCE_FILES" : "PIECE_OBJECTS");
    return o;
}

SourceFilesPiecePlan PlanSourceFilesPieceRequest(bool local_hit, bool p2p_available, bool hydration_inflight,
                                                 bool allow_range_per_piece, bool direct_file_seed)
{
    if (local_hit) return SourceFilesPiecePlan::LOCAL_CACHE;
    if (p2p_available) return SourceFilesPiecePlan::P2P;
    if (hydration_inflight) return SourceFilesPiecePlan::JOIN_HYDRATION;
    if (direct_file_seed) return SourceFilesPiecePlan::DIRECT_FILE_SEED;
    if (allow_range_per_piece) return SourceFilesPiecePlan::ORIGIN_RANGE_PIECE;
    return SourceFilesPiecePlan::START_FILE_STREAM;
}

UniValue SparseOriginScaleReceiptJson(uint64_t logical_bytes, uint64_t stored_object_bytes, uint64_t origin_gets,
                                       uint32_t n_files)
{
    const uint64_t pieces = logical_bytes == 0 ? 0 : (logical_bytes + PIECE_SIZE - 1) / PIECE_SIZE;
    UniValue o(UniValue::VOBJ);
    o.pushKV("logical_bytes", static_cast<int64_t>(logical_bytes));
    o.pushKV("stored_object_bytes", static_cast<int64_t>(stored_object_bytes));
    o.pushKV("origin_get_ops", static_cast<int64_t>(origin_gets));
    o.pushKV("files", static_cast<int>(n_files));
    o.pushKV("logical_btx_pieces", static_cast<int64_t>(pieces));
    o.pushKV("piece_object_equivalent_gets", static_cast<int64_t>(pieces));
    o.pushKV("layout", "SOURCE_FILES");
    o.pushKV("sparse", true);
    o.pushKV("note", "400GiB-equivalent receipt; stored_object_bytes is the real object, not 400G on disk");
    o.pushKV("automatic_spend_atoms", 0);
    return o;
}

namespace {

void TrimWindow(std::vector<int64_t>& hits, int64_t now_ms, int64_t window_ms)
{
    auto it = std::remove_if(hits.begin(), hits.end(), [&](int64_t t) { return now_ms - t > window_ms; });
    hits.erase(it, hits.end());
}

} // namespace

bool OriginStampedeGuard::CircuitOpenLocked(const std::string& peer, int64_t now_ms) const
{
    auto it = m_open_until.find(peer);
    return it != m_open_until.end() && it->second > now_ms;
}

bool OriginStampedeGuard::Allow(const std::string& peer, const std::string& netgroup, int64_t now_ms, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (CircuitOpenLocked(peer, now_ms)) {
        err = "origin circuit open";
        return false;
    }
    auto& ph = m_peer_hits[peer];
    TrimWindow(ph, now_ms, m_s.window_ms);
    if (static_cast<int>(ph.size()) >= m_s.max_per_peer) {
        err = "per-peer origin cap";
        return false;
    }
    const std::string ng = netgroup.empty() ? peer : netgroup;
    auto& nh = m_ng_hits[ng];
    TrimWindow(nh, now_ms, m_s.window_ms);
    if (static_cast<int>(nh.size()) >= m_s.max_per_netgroup) {
        err = "per-netgroup origin cap";
        return false;
    }
    ph.push_back(now_ms);
    nh.push_back(now_ms);
    return true;
}

void OriginStampedeGuard::NoteSuccess(const std::string& peer)
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_errors.erase(peer);
}

void OriginStampedeGuard::NoteError(const std::string& peer, int64_t now_ms)
{
    std::lock_guard<std::mutex> lock(m_mu);
    const int n = ++m_errors[peer];
    if (n >= m_s.errors_to_open) {
        m_open_until[peer] = now_ms + m_s.open_ms;
    }
}

bool OriginStampedeGuard::CircuitOpen(const std::string& peer, int64_t now_ms) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return CircuitOpenLocked(peer, now_ms);
}

UniValue OriginStampedeGuard::Json(int64_t now_ms) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    int open = 0;
    for (const auto& kv : m_open_until) {
        if (kv.second > now_ms) ++open;
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("window_ms", m_s.window_ms);
    o.pushKV("max_per_peer", m_s.max_per_peer);
    o.pushKV("max_per_netgroup", m_s.max_per_netgroup);
    o.pushKV("errors_to_open", m_s.errors_to_open);
    o.pushKV("circuit_open_ms", m_s.open_ms);
    o.pushKV("circuits_open", open);
    o.pushKV("tracked_peers", static_cast<int>(m_peer_hits.size()));
    o.pushKV("automatic_spend_atoms", 0);
    return o;
}

void OriginStampedeGuard::ResetForTests()
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_peer_hits.clear();
    m_ng_hits.clear();
    m_errors.clear();
    m_open_until.clear();
}

OriginStampedeGuard& GlobalOriginStampede()
{
    static OriginStampedeGuard g;
    return g;
}

} // namespace modelnet
