// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>

#include <matmul/matmul_v4_rc_alg_hash.h>

#include <cstring>
#include <limits>

namespace matmul::v4::rc {
namespace {

using air_quotient::AirAlgRowPath;

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "airquotient-codec:" + message;
    return false;
}

void PutU32(std::vector<unsigned char>& out, uint32_t v)
{
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<unsigned char>(v >> (8 * i)));
}

void PutU16(std::vector<unsigned char>& out, uint16_t v)
{
    for (int i = 0; i < 2; ++i) out.push_back(static_cast<unsigned char>(v >> (8 * i)));
}

void PutU64(std::vector<unsigned char>& out, uint64_t v)
{
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<unsigned char>(v >> (8 * i)));
}

void PutUint256(std::vector<unsigned char>& out, const uint256& v)
{
    out.insert(out.end(), v.begin(), v.end());
}

/** Fp3 is three Goldilocks coefficients; write each canonically. */
void PutFp3(std::vector<unsigned char>& out, const gkr_field::Fp3& v)
{
    // Canonical() folds the single redundant representative Goldilocks allows,
    // so the same field element always encodes to the same bytes.
    PutU64(out, gkr_field::Canonical(v.c0));
    PutU64(out, gkr_field::Canonical(v.c1));
    PutU64(out, gkr_field::Canonical(v.c2));
}

void PutDigest(std::vector<unsigned char>& out, const Fri3AlgDigest& d)
{
    for (size_t i = 0; i < alg_hash::kAlgHashDigestLen; ++i) {
        PutU64(out, gkr_field::Canonical(d[i]));
    }
}

class Reader
{
public:
    explicit Reader(const std::vector<unsigned char>& bytes) : m_bytes(bytes) {}

    [[nodiscard]] size_t Remaining() const { return m_bytes.size() - m_pos; }

    bool U16(uint16_t& out)
    {
        if (Remaining() < 2) return false;
        out = 0;
        for (int i = 0; i < 2; ++i) out |= static_cast<uint16_t>(m_bytes[m_pos + i]) << (8 * i);
        m_pos += 2;
        return true;
    }
    bool U32(uint32_t& out)
    {
        if (Remaining() < 4) return false;
        out = 0;
        for (int i = 0; i < 4; ++i) out |= static_cast<uint32_t>(m_bytes[m_pos + i]) << (8 * i);
        m_pos += 4;
        return true;
    }
    bool U8(uint8_t& out)
    {
        if (Remaining() < 1) return false;
        out = m_bytes[m_pos++];
        return true;
    }
    bool U64(uint64_t& out)
    {
        if (Remaining() < 8) return false;
        out = 0;
        for (int i = 0; i < 8; ++i) out |= static_cast<uint64_t>(m_bytes[m_pos + i]) << (8 * i);
        m_pos += 8;
        return true;
    }
    bool Uint256(uint256& out)
    {
        if (Remaining() < 32) return false;
        std::memcpy(out.begin(), m_bytes.data() + m_pos, 32);
        m_pos += 32;
        return true;
    }
    bool Bytes(size_t n, std::vector<unsigned char>& out)
    {
        if (n > Remaining()) return false; // checked BEFORE allocating
        out.assign(m_bytes.begin() + m_pos, m_bytes.begin() + m_pos + n);
        m_pos += n;
        return true;
    }
    bool Fp3(gkr_field::Fp3& out)
    {
        gkr_field::Fp* dst[3] = {&out.c0, &out.c1, &out.c2};
        for (size_t i = 0; i < 3; ++i) {
            uint64_t raw{0};
            if (!U64(raw)) return false;
            // Reject the non-canonical representative outright rather than
            // folding it, so decode(encode(x)) is the identity and the
            // canonicality re-serialization check below cannot be bypassed.
            if (raw >= gkr_field::kP) return false;
            *dst[i] = static_cast<gkr_field::Fp>(raw);
        }
        return true;
    }
    bool Digest(Fri3AlgDigest& out)
    {
        for (size_t i = 0; i < alg_hash::kAlgHashDigestLen; ++i) {
            uint64_t raw{0};
            if (!U64(raw)) return false;
            if (raw >= gkr_field::kP) return false;
            out[i] = static_cast<gkr_field::Fp>(raw);
        }
        return true;
    }

private:
    const std::vector<unsigned char>& m_bytes;
    size_t m_pos{0};
};

constexpr size_t kFp3Bytes = 3 * 8;
constexpr size_t kDigestBytes = alg_hash::kAlgHashDigestLen * 8;

//! Bytes each row path contributes, exactly as WriteRowPaths emits them.
size_t RowPathBytes(const AirAlgRowPath& p)
{
    return 4 /*index*/ + 4 /*n_values*/ + p.values.size() * kFp3Bytes +
           4 /*n_siblings*/ + p.siblings.size() * kDigestBytes;
}

bool WriteRowPaths(const std::vector<std::vector<AirAlgRowPath>>& next_openings,
                   std::vector<unsigned char>& out,
                   std::string* why)
{
    if (next_openings.size() > kAirQuotientCodecMaxQueries) {
        return Fail(why, "too_many_queries");
    }
    PutU32(out, static_cast<uint32_t>(next_openings.size()));
    for (const auto& per_query : next_openings) {
        if (per_query.size() > kAirQuotientCodecMaxPathsPerQuery) {
            return Fail(why, "too_many_paths_per_query");
        }
        PutU32(out, static_cast<uint32_t>(per_query.size()));
        for (const auto& path : per_query) {
            if (path.values.size() > kRCFri3AlgBatchMaxColumns ||
                path.siblings.size() > kRCFri3AlgBatchMaxColumns) {
                return Fail(why, "path_vector_too_long");
            }
            PutU32(out, path.index);
            PutU32(out, static_cast<uint32_t>(path.values.size()));
            for (const auto& v : path.values) PutFp3(out, v);
            PutU32(out, static_cast<uint32_t>(path.siblings.size()));
            for (const auto& s : path.siblings) PutDigest(out, s);
        }
    }
    return true;
}

bool ReadRowPaths(Reader& r,
                  std::vector<std::vector<AirAlgRowPath>>& out,
                  std::string* why)
{
    uint32_t n_queries{0};
    if (!r.U32(n_queries)) return Fail(why, "truncated_query_count");
    if (n_queries > kAirQuotientCodecMaxQueries) {
        return Fail(why, "too_many_queries");
    }
    // A query costs at least its own path count field; refuse a count the
    // remaining bytes cannot possibly justify before reserving anything.
    if (static_cast<size_t>(n_queries) * 4 > r.Remaining()) {
        return Fail(why, "query_count_exceeds_input");
    }
    out.resize(n_queries);

    for (uint32_t q = 0; q < n_queries; ++q) {
        uint32_t n_paths{0};
        if (!r.U32(n_paths)) return Fail(why, "truncated_path_count");
        if (n_paths > kAirQuotientCodecMaxPathsPerQuery) {
            return Fail(why, "too_many_paths_per_query");
        }
        if (static_cast<size_t>(n_paths) * 12 > r.Remaining()) {
            return Fail(why, "path_count_exceeds_input");
        }
        out[q].resize(n_paths);
        for (uint32_t p = 0; p < n_paths; ++p) {
            AirAlgRowPath& path = out[q][p];
            uint32_t n_values{0};
            uint32_t n_siblings{0};
            if (!r.U32(path.index)) return Fail(why, "truncated_path_index");
            if (!r.U32(n_values)) return Fail(why, "truncated_value_count");
            if (n_values > kRCFri3AlgBatchMaxColumns) {
                return Fail(why, "value_count_over_cap");
            }
            // The decisive check: the claimed length must be covered by bytes
            // that actually remain, so no allocation can outrun the input.
            if (static_cast<size_t>(n_values) * kFp3Bytes > r.Remaining()) {
                return Fail(why, "value_count_exceeds_input");
            }
            path.values.resize(n_values);
            for (uint32_t i = 0; i < n_values; ++i) {
                if (!r.Fp3(path.values[i])) return Fail(why, "bad_value");
            }
            if (!r.U32(n_siblings)) return Fail(why, "truncated_sibling_count");
            if (n_siblings > kRCFri3AlgBatchMaxColumns) {
                return Fail(why, "sibling_count_over_cap");
            }
            if (static_cast<size_t>(n_siblings) * kDigestBytes > r.Remaining()) {
                return Fail(why, "sibling_count_exceeds_input");
            }
            path.siblings.resize(n_siblings);
            for (uint32_t i = 0; i < n_siblings; ++i) {
                if (!r.Digest(path.siblings[i])) return Fail(why, "bad_sibling");
            }
        }
    }
    return true;
}

bool WriteEnvelope(AirQuotientCodecLane lane,
                   const std::vector<unsigned char>& batch_bytes,
                   const uint256& trace_commit,
                   const std::vector<std::vector<AirAlgRowPath>>& next_openings,
                   std::vector<unsigned char>& out,
                   std::string* why)
{
    out.clear();
    if (batch_bytes.size() > std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "batch_too_large");
    }
    PutU32(out, kAirQuotientCodecMagic);
    PutU16(out, kAirQuotientCodecVersion);
    out.push_back(static_cast<unsigned char>(lane));
    out.push_back(0); // reserved, must be zero
    PutU32(out, static_cast<uint32_t>(batch_bytes.size()));
    out.insert(out.end(), batch_bytes.begin(), batch_bytes.end());
    PutUint256(out, trace_commit);
    if (!WriteRowPaths(next_openings, out, why)) {
        out.clear();
        return false;
    }
    if (out.size() > kAirQuotientCodecMaxBytes) {
        out.clear();
        return Fail(why, "encoded_over_cap");
    }
    return true;
}

/** Shared header/body parse. Leaves the batch blob to the caller's lane codec. */
bool ReadEnvelope(const std::vector<unsigned char>& in,
                  AirQuotientCodecLane& lane_out,
                  std::vector<unsigned char>& batch_bytes,
                  uint256& trace_commit,
                  std::vector<std::vector<AirAlgRowPath>>& next_openings,
                  std::string* why)
{
    if (in.size() > kAirQuotientCodecMaxBytes) return Fail(why, "input_over_cap");
    Reader r(in);
    uint32_t magic{0};
    uint16_t version{0};
    uint8_t lane_raw{0};
    uint8_t reserved{1};
    if (!r.U32(magic) || magic != kAirQuotientCodecMagic) {
        return Fail(why, "bad_magic");
    }
    if (!r.U16(version) || version != kAirQuotientCodecVersion) {
        return Fail(why, "bad_version");
    }
    if (!r.U8(lane_raw) || !r.U8(reserved)) return Fail(why, "truncated_header");
    if (reserved != 0) return Fail(why, "nonzero_reserved");
    if (lane_raw > static_cast<uint8_t>(AirQuotientCodecLane::DualAlgQ136)) {
        return Fail(why, "unknown_lane");
    }
    lane_out = static_cast<AirQuotientCodecLane>(lane_raw);

    uint32_t batch_len{0};
    if (!r.U32(batch_len)) return Fail(why, "truncated_batch_len");
    if (!r.Bytes(batch_len, batch_bytes)) return Fail(why, "truncated_batch");
    if (!r.Uint256(trace_commit)) return Fail(why, "truncated_trace_commit");
    if (!ReadRowPaths(r, next_openings, why)) return false;
    if (r.Remaining() != 0) return Fail(why, "trailing_bytes");
    return true;
}

} // namespace

size_t MeasuredAirQuotientWrapperBytes(
    const std::vector<std::vector<AirAlgRowPath>>& next_openings)
{
    size_t total = 4 /*magic*/ + 2 /*version*/ + 1 /*lane*/ + 1 /*reserved*/ +
                   4 /*batch_len*/ + 32 /*trace_commit*/ + 4 /*n_queries*/;
    for (const auto& per_query : next_openings) {
        total += 4; // n_paths
        for (const auto& path : per_query) total += RowPathBytes(path);
    }
    return total;
}

bool SerializeAirQuotientProofAlg(const AirQuotientProofAlg& proof,
                                  std::vector<unsigned char>& out,
                                  std::string* why)
{
    std::vector<unsigned char> batch_bytes;
    if (SerializeFri3AlgBatchProof(proof.batch, batch_bytes) == 0) {
        out.clear();
        return Fail(why, "batch_serialize_failed");
    }
    return WriteEnvelope(AirQuotientCodecLane::SingleAlg, batch_bytes,
                         proof.trace_commit, proof.next_openings, out, why);
}

std::optional<AirQuotientProofAlg> DeserializeAirQuotientProofAlg(
    const std::vector<unsigned char>& in, std::string* why)
{
    AirQuotientCodecLane lane{};
    std::vector<unsigned char> batch_bytes;
    AirQuotientProofAlg proof;
    if (!ReadEnvelope(in, lane, batch_bytes, proof.trace_commit,
                      proof.next_openings, why)) {
        return std::nullopt;
    }
    if (lane != AirQuotientCodecLane::SingleAlg) {
        Fail(why, "lane_mismatch_expected_single");
        return std::nullopt;
    }
    auto batch = DeserializeFri3AlgBatchProof(batch_bytes);
    if (!batch.has_value()) {
        Fail(why, "batch_deserialize_failed");
        return std::nullopt;
    }
    proof.batch = std::move(*batch);

    // Canonicality: exactly one encoding per proof.
    std::vector<unsigned char> reencoded;
    std::string reencode_why;
    if (!SerializeAirQuotientProofAlg(proof, reencoded, &reencode_why) ||
        reencoded != in) {
        Fail(why, "noncanonical_encoding");
        return std::nullopt;
    }
    return proof;
}

bool SerializeAirQuotientProofDualAlg(const AirQuotientProofDualAlg& proof,
                                      AirQuotientCodecLane lane,
                                      std::vector<unsigned char>& out,
                                      std::string* why)
{
    out.clear();
    std::vector<unsigned char> batch_bytes;
    size_t written{0};
    switch (lane) {
    case AirQuotientCodecLane::DualAlg:
        written = SerializeFri3AlgDualBatchProof(proof.batch.repeated, batch_bytes);
        break;
    case AirQuotientCodecLane::DualAlgQ136:
        written = SerializeFri3AlgDualQ136BatchProof(proof.batch.repeated, batch_bytes);
        break;
    case AirQuotientCodecLane::SingleAlg:
        return Fail(why, "single_lane_on_dual_proof");
    }
    if (written == 0) return Fail(why, "dual_batch_serialize_failed");
    return WriteEnvelope(lane, batch_bytes, proof.trace_commit,
                         proof.next_openings, out, why);
}

std::optional<AirQuotientProofDualAlg> DeserializeAirQuotientProofDualAlg(
    const std::vector<unsigned char>& in, std::string* why)
{
    AirQuotientCodecLane lane{};
    std::vector<unsigned char> batch_bytes;
    AirQuotientProofDualAlg proof;
    if (!ReadEnvelope(in, lane, batch_bytes, proof.trace_commit,
                      proof.next_openings, why)) {
        return std::nullopt;
    }
    std::optional<Fri3AlgDualBatchProof> repeated;
    switch (lane) {
    case AirQuotientCodecLane::DualAlg:
        repeated = DeserializeFri3AlgDualBatchProof(batch_bytes);
        break;
    case AirQuotientCodecLane::DualAlgQ136:
        repeated = DeserializeFri3AlgDualQ136BatchProof(batch_bytes);
        break;
    case AirQuotientCodecLane::SingleAlg:
        Fail(why, "lane_mismatch_expected_dual");
        return std::nullopt;
    }
    if (!repeated.has_value()) {
        Fail(why, "dual_batch_deserialize_failed");
        return std::nullopt;
    }
    proof.batch.repeated = std::move(*repeated);

    std::vector<unsigned char> reencoded;
    std::string reencode_why;
    if (!SerializeAirQuotientProofDualAlg(proof, lane, reencoded, &reencode_why) ||
        reencoded != in) {
        Fail(why, "noncanonical_encoding");
        return std::nullopt;
    }
    return proof;
}

std::optional<size_t> MeasuredAirQuotientProofAlgBytes(
    const AirQuotientProofAlg& proof)
{
    std::vector<unsigned char> bytes;
    std::string why;
    if (!SerializeAirQuotientProofAlg(proof, bytes, &why)) return std::nullopt;
    return bytes.size();
}

std::optional<size_t> MeasuredAirQuotientProofDualAlgBytes(
    const AirQuotientProofDualAlg& proof, AirQuotientCodecLane lane)
{
    std::vector<unsigned char> bytes;
    std::string why;
    if (!SerializeAirQuotientProofDualAlg(proof, lane, bytes, &why)) {
        return std::nullopt;
    }
    return bytes.size();
}

} // namespace matmul::v4::rc
