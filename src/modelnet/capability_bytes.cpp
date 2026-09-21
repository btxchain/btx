// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/capability.h>

#include <crypto/common.h>
#include <crypto/sha384.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <string>
#include <unistd.h>
#include <set>
#include <utility>

namespace modelnet {
namespace {

uint64_t DtypeWidth(const std::string& dt)
{
    if (dt == "F64" || dt == "I64" || dt == "U64") return 8;
    if (dt == "F32" || dt == "I32" || dt == "U32") return 4;
    if (dt == "F16" || dt == "BF16" || dt == "I16" || dt == "U16") return 2;
    return 1;
}

bool GgufPayloadBytes(uint32_t dtype, const std::vector<int64_t>& shape, uint64_t& nbytes, std::string& err)
{
    uint64_t n = 1;
    for (int64_t d : shape) {
        if (d < 0) {
            err = "gguf negative dim";
            return false;
        }
        const uint64_t dim = static_cast<uint64_t>(d);
        if (dim != 0 && n > std::numeric_limits<uint64_t>::max() / dim) {
            err = "gguf shape overflow";
            return false;
        }
        n *= dim;
    }
    auto blocks = [&](uint64_t blk, uint64_t bytes_per) -> bool {
        if (blk == 0 || n % blk != 0) {
            err = "gguf quantized block alignment";
            return false;
        }
        const uint64_t nb = n / blk;
        if (bytes_per != 0 && nb > std::numeric_limits<uint64_t>::max() / bytes_per) {
            err = "gguf quantized size overflow";
            return false;
        }
        nbytes = nb * bytes_per;
        return true;
    };
    switch (dtype) {
    case 0: nbytes = n * 4; return true; // F32
    case 1: nbytes = n * 2; return true; // F16
    case 2: return blocks(32, 18);      // Q4_0
    case 3: return blocks(32, 20);      // Q4_1
    case 6: return blocks(32, 22);      // Q5_0
    case 7: return blocks(32, 24);      // Q5_1
    case 8: return blocks(32, 34);      // Q8_0
    case 9: return blocks(32, 36);      // Q8_1
    default:
        err.clear();
        return false;
    }
}

bool CheckedProduct(const std::vector<int64_t>& shape, uint64_t& n)
{
    n = 1;
    for (int64_t d : shape) {
        if (d < 0) return false;
        const uint64_t u = static_cast<uint64_t>(d);
        if (u != 0 && n > (std::numeric_limits<uint64_t>::max() / u)) return false;
        n *= u;
    }
    return true;
}

bool ReadU32(Span<const unsigned char> s, size_t& off, uint32_t& v)
{
    if (off + 4 > s.size()) return false;
    v = ReadLE32(s.data() + off);
    off += 4;
    return true;
}

bool ReadU64(Span<const unsigned char> s, size_t& off, uint64_t& v)
{
    if (off + 8 > s.size()) return false;
    v = ReadLE64(s.data() + off);
    off += 8;
    return true;
}

bool SkipGgufValue(Span<const unsigned char> s, size_t& off, uint32_t type, int depth)
{
    if (depth > 8) return false;
    switch (type) {
    case 0: // u8
    case 1: // i8
    case 7: // bool
        if (off + 1 > s.size()) return false;
        off += 1;
        return true;
    case 2:
    case 3:
        if (off + 2 > s.size()) return false;
        off += 2;
        return true;
    case 4:
    case 5:
    case 6:
        if (off + 4 > s.size()) return false;
        off += 4;
        return true;
    case 10:
    case 11:
    case 12:
        if (off + 8 > s.size()) return false;
        off += 8;
        return true;
    case 8: {
        uint64_t n = 0;
        if (!ReadU64(s, off, n) || n > TENSOR_MAP_BYTES_MAX || off + n > s.size()) return false;
        off += static_cast<size_t>(n);
        return true;
    }
    case 9: {
        uint32_t inner = 0;
        uint64_t n = 0;
        if (!ReadU32(s, off, inner) || !ReadU64(s, off, n) || n > 1'000'000) return false;
        for (uint64_t i = 0; i < n; ++i) {
            if (!SkipGgufValue(s, off, inner, depth + 1)) return false;
        }
        return true;
    }
    default:
        return false;
    }
}

bool DeriveGgufMap(Span<const unsigned char> bytes, uint64_t file_size, uint32_t file_index, const Digest48& manifest_id,
                    TensorRangeMap& out, std::string& err_code, std::string& err)
{
    out = {};
    out.manifest_id = manifest_id;
    if (bytes.size() < 24 || std::memcmp(bytes.data(), "GGUF", 4) != 0) {
        err_code = "INVALID_MODEL";
        err = "gguf magic";
        return false;
    }
    size_t off = 4;
    uint32_t version = 0;
    uint64_t n_tensors = 0, n_kv = 0;
    if (!ReadU32(bytes, off, version) || !ReadU64(bytes, off, n_tensors) || !ReadU64(bytes, off, n_kv)) {
        err_code = "INVALID_MODEL";
        err = "gguf header";
        return false;
    }
    if (n_tensors > TENSOR_MAP_ENTRY_MAX) {
        err_code = "RESOURCE_LIMIT";
        err = "tensor count";
        return false;
    }
    uint64_t alignment = 32;
    for (uint64_t i = 0; i < n_kv; ++i) {
        uint64_t klen = 0;
        if (!ReadU64(bytes, off, klen) || klen > TENSOR_MAP_BYTES_MAX || off + klen > bytes.size()) {
            err_code = "INVALID_MODEL";
            err = "gguf kv key";
            return false;
        }
        const std::string key(reinterpret_cast<const char*>(bytes.data() + off), static_cast<size_t>(klen));
        off += static_cast<size_t>(klen);
        uint32_t vt = 0;
        if (!ReadU32(bytes, off, vt)) {
            err_code = "INVALID_MODEL";
            err = "gguf kv";
            return false;
        }
        if (key == "general.alignment" && (vt == 4 || vt == 5)) {
            uint32_t al = 0;
            if (!ReadU32(bytes, off, al) || al == 0 || al > (1u << 20)) {
                err_code = "INVALID_MODEL";
                err = "gguf alignment";
                return false;
            }
            alignment = al;
        } else if (key == "general.alignment" && (vt == 10 || vt == 11 || vt == 12)) {
            uint64_t al = 0;
            if (!ReadU64(bytes, off, al) || al == 0 || al > (uint64_t{1} << 20)) {
                err_code = "INVALID_MODEL";
                err = "gguf alignment";
                return false;
            }
            alignment = al;
        } else if (!SkipGgufValue(bytes, off, vt, 0)) {
            err_code = "INVALID_MODEL";
            err = "gguf kv";
            return false;
        }
    }
    std::vector<uint64_t> starts;
    std::vector<uint32_t> dtypes;
    for (uint64_t i = 0; i < n_tensors; ++i) {
        uint64_t nlen = 0;
        if (!ReadU64(bytes, off, nlen) || nlen > 4096 || off + nlen > bytes.size()) {
            err_code = "INVALID_MODEL";
            err = "gguf tensor name";
            return false;
        }
        TensorRange tr;
        tr.name.assign(reinterpret_cast<const char*>(bytes.data() + off), static_cast<size_t>(nlen));
        off += static_cast<size_t>(nlen);
        uint32_t n_dims = 0;
        if (!ReadU32(bytes, off, n_dims) || n_dims > 8) {
            err_code = "INVALID_MODEL";
            err = "gguf dims";
            return false;
        }
        for (uint32_t d = 0; d < n_dims; ++d) {
            uint64_t dim = 0;
            if (!ReadU64(bytes, off, dim) || dim > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
                err_code = "INVALID_MODEL";
                err = "gguf shape overflow";
                return false;
            }
            tr.shape.push_back(static_cast<int64_t>(dim));
        }
        uint32_t dtype = 0;
        uint64_t toff = 0;
        if (!ReadU32(bytes, off, dtype) || !ReadU64(bytes, off, toff)) {
            err_code = "INVALID_MODEL";
            err = "gguf tensor";
            return false;
        }
        tr.file_index = file_index;
        tr.dtype = "GGUF-" + std::to_string(dtype);
        tr.offset = toff;
        starts.push_back(toff);
        dtypes.push_back(dtype);
        out.tensors.push_back(std::move(tr));
    }
    const uint64_t data_base = (static_cast<uint64_t>(off) + alignment - 1) / alignment * alignment;
    for (size_t i = 0; i < out.tensors.size(); ++i) {
        out.tensors[i].offset = data_base + starts[i];
        uint64_t typed_len = 0;
        std::string tmsg;
        const bool typed = GgufPayloadBytes(dtypes[i], out.tensors[i].shape, typed_len, tmsg);
        uint64_t packed_end = file_size;
        for (size_t j = 0; j < starts.size(); ++j) {
            const uint64_t abs_j = data_base + starts[j];
            if (abs_j > out.tensors[i].offset && abs_j < packed_end) packed_end = abs_j;
        }
        if (packed_end < out.tensors[i].offset) {
            err_code = "INVALID_MODEL";
            err = "gguf offset";
            return false;
        }
        if (typed) {
            if (out.tensors[i].offset + typed_len > file_size) {
                err_code = "INVALID_MODEL";
                err = "gguf quantized range past file";
                return false;
            }
            if (out.tensors[i].offset + typed_len > packed_end) {
                err_code = "INVALID_MODEL";
                err = "gguf quantized overlap";
                return false;
            }
            out.tensors[i].length = typed_len;
        } else {
            out.tensors[i].length = packed_end - out.tensors[i].offset;
        }
        out.tensors[i].piece_begin = static_cast<uint32_t>(out.tensors[i].offset / PIECE_SIZE);
        out.tensors[i].piece_end =
            static_cast<uint32_t>((out.tensors[i].offset + out.tensors[i].length + PIECE_SIZE - 1) / PIECE_SIZE);
    }
    UniValue arr(UniValue::VARR);
    for (const auto& t : out.tensors) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("name", t.name);
        e.pushKV("file_index", static_cast<int>(t.file_index));
        e.pushKV("offset", std::to_string(t.offset));
        e.pushKV("length", std::to_string(t.length));
        e.pushKV("dtype", t.dtype);
        arr.push_back(e);
    }
    out.json = UniValue(UniValue::VOBJ);
    out.json.pushKV("manifest_id", manifest_id.Hex());
    out.json.pushKV("format", "GGUF");
    out.json.pushKV("alignment", std::to_string(alignment));
    out.json.pushKV("tensors", arr);
    if (!CapabilityObjectIdJson(TENSOR_MAP_DOMAIN, out.json, out.map_id, err)) {
        err_code = "NONCANONICAL_PAYLOAD";
        return false;
    }
    return true;
}

} // namespace

bool DeriveTensorRangeMap(Span<const unsigned char> verified_header_and_body, uint64_t file_size,
                           uint32_t file_index, const Digest48& manifest_id, TensorRangeMap& out,
                           std::string& err_code, std::string& err)
{
    if (verified_header_and_body.size() >= 4 && std::memcmp(verified_header_and_body.data(), "GGUF", 4) == 0) {
        return DeriveGgufMap(verified_header_and_body, file_size, file_index, manifest_id, out, err_code, err);
    }
    out = {};
    out.manifest_id = manifest_id;
    if (verified_header_and_body.size() < 8) {
        err_code = "INVALID_MODEL";
        err = "truncated safetensors";
        return false;
    }
    const uint64_t hlen = ReadLE64(verified_header_and_body.data());
    if (hlen == 0 || hlen > TENSOR_MAP_BYTES_MAX || 8 + hlen > verified_header_and_body.size()) {
        err_code = "INVALID_MODEL";
        err = "safetensors header";
        return false;
    }
    std::string json(reinterpret_cast<const char*>(verified_header_and_body.data() + 8), static_cast<size_t>(hlen));
    UniValue header;
    if (!header.read(json) || !header.isObject()) {
        err_code = "INVALID_MODEL";
        err = "header json";
        return false;
    }
    const uint64_t data_start = 8 + hlen;
    std::set<std::pair<uint64_t, uint64_t>> ranges;
    for (const auto& key : header.getKeys()) {
        if (key == "__metadata__") continue;
        if (out.tensors.size() >= TENSOR_MAP_ENTRY_MAX) {
            err_code = "RESOURCE_LIMIT";
            err = "tensor count";
            return false;
        }
        const UniValue& t = header[key];
        if (!t.isObject() || !t.exists("dtype") || !t.exists("shape") || !t.exists("data_offsets") ||
            t["data_offsets"].size() != 2) {
            err_code = "INVALID_MODEL";
            err = "tensor fields";
            return false;
        }
        TensorRange tr;
        tr.name = key;
        tr.file_index = file_index;
        tr.dtype = t["dtype"].get_str();
        for (const auto& d : t["shape"].getValues()) {
            if (!d.isNum()) {
                err_code = "INVALID_MODEL";
                err = "shape";
                return false;
            }
            tr.shape.push_back(d.getInt<int64_t>());
        }
        uint64_t start = 0, end = 0;
        if (t["data_offsets"][0].isNum()) start = t["data_offsets"][0].getInt<uint64_t>();
        if (t["data_offsets"][1].isNum()) end = t["data_offsets"][1].getInt<uint64_t>();
        if (end < start) {
            err_code = "INVALID_MODEL";
            err = "offsets";
            return false;
        }
        tr.offset = data_start + start;
        tr.length = end - start;
        uint64_t n = 0;
        if (!CheckedProduct(tr.shape, n)) {
            err_code = "INVALID_MODEL";
            err = "shape overflow";
            return false;
        }
        if (n * DtypeWidth(tr.dtype) != tr.length && n != 0) {
            err_code = "INVALID_MODEL";
            err = "dtype/shape/length";
            return false;
        }
        if (tr.offset + tr.length > file_size) {
            err_code = "INVALID_MODEL";
            err = "range past file";
            return false;
        }
        for (const auto& prev : ranges) {
            const uint64_t a = prev.first, b = prev.second;
            if (tr.offset < b && a < tr.offset + tr.length) {
                if (tr.offset != a || tr.offset + tr.length != b) {
                    err_code = "INVALID_MODEL";
                    err = "unexpected overlap";
                    return false;
                }
            }
        }
        ranges.insert({tr.offset, tr.offset + tr.length});
        tr.piece_begin = static_cast<uint32_t>(tr.offset / PIECE_SIZE);
        tr.piece_end = static_cast<uint32_t>((tr.offset + tr.length + PIECE_SIZE - 1) / PIECE_SIZE);
        out.tensors.push_back(std::move(tr));
    }
    UniValue arr(UniValue::VARR);
    for (const auto& t : out.tensors) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("name", t.name);
        e.pushKV("file_index", static_cast<int>(t.file_index));
        e.pushKV("offset", std::to_string(t.offset));
        e.pushKV("length", std::to_string(t.length));
        e.pushKV("dtype", t.dtype);
        arr.push_back(e);
    }
    out.json = UniValue(UniValue::VOBJ);
    out.json.pushKV("manifest_id", manifest_id.Hex());
    out.json.pushKV("tensors", arr);
    if (!CapabilityObjectIdJson(TENSOR_MAP_DOMAIN, out.json, out.map_id, err)) {
        err_code = "NONCANONICAL_PAYLOAD";
        return false;
    }
    return true;
}

bool SparseHoleIsUnverified(uint64_t offset, uint64_t length, const std::vector<bool>& verified_bitmap,
                            uint64_t piece_size)
{
    if (piece_size == 0) return true;
    const uint64_t begin = offset / piece_size;
    const uint64_t end = (offset + length + piece_size - 1) / piece_size;
    for (uint64_t i = begin; i < end; ++i) {
        if (i >= verified_bitmap.size() || !verified_bitmap[static_cast<size_t>(i)]) return true;
    }
    return false;
}

bool ReadVerifiedRange(const Digest48& manifest, uint32_t file_index, uint64_t offset, uint64_t length,
                        const std::vector<unsigned char>& verified_file, Generation16 gen, VerifiedRangeLease& out,
                        std::string& err_code, std::string& err)
{
    out = {};
    out.manifest = manifest;
    out.generation = gen;
    if (file_index != 0) {
        err_code = "SHARD_MISSING";
        err = "single-file verified buffer cannot satisfy a non-zero file_index";
        return false;
    }
    if (length == 0) return true;
    if (verified_file.empty()) {
        err_code = "RANGE_UNVERIFIED";
        err = "empty buffer is not a verified file";
        return false;
    }
    if (offset > verified_file.size() || length > verified_file.size() - offset) {
        err_code = "RANGE_UNVERIFIED";
        err = "range not covered by verified bytes";
        return false;
    }
    out.bytes.assign(verified_file.begin() + static_cast<std::ptrdiff_t>(offset),
                      verified_file.begin() + static_cast<std::ptrdiff_t>(offset + length));
    return true;
}

bool MaterializeCompleteFile(const std::vector<std::vector<unsigned char>>& pieces, const std::string& dest,
                             Generation16 gen, std::string& err_code, std::string& err)
{
    if (dest.find("..") != std::string::npos) {
        err_code = "INVALID_PARAMETER";
        err = "dest";
        return false;
    }
    if (pieces.empty()) {
        err_code = "RANGE_UNVERIFIED";
        err = "complete file requires at least one verified piece";
        return false;
    }
    for (const auto& p : pieces) {
        if (p.empty()) {
            err_code = "RANGE_UNVERIFIED";
            err = "empty piece cannot be materialized as a complete file (no sparse holes)";
            return false;
        }
    }
    const int fd = ::open(dest.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0444);
    if (fd < 0) {
        err_code = "OVERWRITE_REFUSED";
        err = "exclusive dest";
        return false;
    }
    off_t off = 0;
    for (const auto& p : pieces) {
        const ssize_t n = ::pwrite(fd, p.data(), p.size(), off);
        if (n < 0 || static_cast<size_t>(n) != p.size()) {
            ::close(fd);
            ::unlink(dest.c_str());
            err_code = "IO_ERROR";
            err = "pwrite";
            return false;
        }
        off += static_cast<off_t>(p.size());
    }
    if (::fsync(fd) != 0) {
        ::close(fd);
        ::unlink(dest.c_str());
        err_code = "IO_ERROR";
        err = "fsync";
        return false;
    }
    ::close(fd);
    const fs::path gen_path = fs::PathFromString(dest + ".gen");
    std::ofstream gf(gen_path);
    if (!gf.good()) {
        ::unlink(dest.c_str());
        err_code = "IO_ERROR";
        err = "generation sidecar";
        return false;
    }
    gf << GenerationHex(gen) << "\n" << pieces.size() << "\n";
    gf.close();
    return true;
}

bool StreamingEqualsFullFile(const std::vector<unsigned char>& streamed, const std::vector<unsigned char>& full)
{
    return streamed == full;
}

bool MapSignerMatchesManifest(const Digest48& map_manifest, const Digest48& expected, std::string& err_code,
                               std::string& err)
{
    if (map_manifest == expected) return true;
    err_code = "MAP_SIGNER_MISMATCH";
    err = "tensor map manifest is not the verified artifact identity";
    return false;
}

bool ReadVerifiedRangeFromPieces(const Digest48& manifest, uint64_t offset, uint64_t length,
                                 const std::vector<std::vector<unsigned char>>& pieces, uint64_t piece_size,
                                 const std::vector<bool>& verified_bitmap, Generation16 gen, VerifiedRangeLease& out,
                                 std::string& err_code, std::string& err)
{
    out = {};
    if (piece_size == 0) {
        err_code = "RANGE_UNVERIFIED";
        err = "piece size";
        return false;
    }
    if (length == 0) {
        out.manifest = manifest;
        out.generation = gen;
        return true;
    }
    if (SparseHoleIsUnverified(offset, length, verified_bitmap, piece_size)) {
        err_code = "RANGE_UNVERIFIED";
        err = "piece-spanning slice includes unverified subpiece";
        return false;
    }
    const uint64_t begin_i = offset / piece_size;
    const uint64_t end_i = (offset + length + piece_size - 1) / piece_size;
    std::vector<unsigned char> concat;
    concat.reserve(static_cast<size_t>(length));
    for (uint64_t i = begin_i; i < end_i; ++i) {
        if (i >= pieces.size() || i >= verified_bitmap.size() || !verified_bitmap[static_cast<size_t>(i)] ||
            pieces[static_cast<size_t>(i)].empty()) {
            err_code = "RANGE_UNVERIFIED";
            err = "empty or missing piece cannot be treated as verified";
            return false;
        }
        const uint64_t piece_file_off = i * piece_size;
        const uint64_t slice_lo = std::max(offset, piece_file_off);
        const uint64_t slice_hi = std::min(offset + length, piece_file_off + piece_size);
        if (slice_hi <= slice_lo) continue;
        const uint64_t local = slice_lo - piece_file_off;
        const uint64_t need = slice_hi - slice_lo;
        const auto& p = pieces[static_cast<size_t>(i)];
        if (local + need > p.size()) {
            err_code = "RANGE_UNVERIFIED";
            err = "verified bit set but piece bytes do not cover the slice";
            return false;
        }
        concat.insert(concat.end(), p.begin() + static_cast<std::ptrdiff_t>(local),
                      p.begin() + static_cast<std::ptrdiff_t>(local + need));
    }
    if (concat.size() != length) {
        err_code = "RANGE_UNVERIFIED";
        err = "incomplete piece span";
        return false;
    }
    return ReadVerifiedRange(manifest, 0, 0, length, concat, gen, out, err_code, err);
}

bool RangeTenantBoundary(const std::string& owner, const std::string& requester, std::string& err_code, std::string& err)
{
    if (owner == requester) return true;
    err_code = "TENANT_DENIED";
    err = "verified range is not visible across tenants";
    return false;
}

bool CoalesceRangeConsumers(const std::vector<std::pair<uint64_t, uint64_t>>& requests,
                             std::vector<std::pair<uint64_t, uint64_t>>& coalesced)
{
    coalesced.clear();
    if (requests.empty()) return true;
    auto sorted = requests;
    std::sort(sorted.begin(), sorted.end());
    uint64_t start = sorted[0].first;
    uint64_t end = sorted[0].first + sorted[0].second;
    for (size_t i = 1; i < sorted.size(); ++i) {
        const uint64_t a = sorted[i].first;
        const uint64_t b = sorted[i].first + sorted[i].second;
        if (a <= end) {
            if (b > end) end = b;
        } else {
            coalesced.emplace_back(start, end - start);
            start = a;
            end = b;
        }
    }
    coalesced.emplace_back(start, end - start);
    return true;
}

bool PreferLoadOverRarity(bool consumer_needs_now, uint32_t rarity_score, uint32_t& scheduled_priority)
{
    (void)rarity_score;
    scheduled_priority = consumer_needs_now ? 0u : 10u + std::min(rarity_score, 1000u);
    return consumer_needs_now;
}

bool CorruptProviderFallback(bool primary_corrupt, bool secondary_verified, std::string& err_code, std::string& err)
{
    if (!primary_corrupt) return true;
    if (secondary_verified) return true;
    err_code = "PROVIDER_CORRUPT";
    err = "no verified fallback provider";
    return false;
}

bool CancelVerifiedRange(PhysicalDisposition inflight, PhysicalDisposition& out)
{
    if (inflight == PhysicalDisposition::STILL_IN_FLIGHT) {
        out = PhysicalDisposition::STILL_IN_FLIGHT;
        return false;
    }
    out = PhysicalDisposition::STOPPED_QUIESCENT;
    return true;
}

bool RequiredShardsPresent(const std::vector<uint32_t>& required, const std::vector<uint32_t>& present,
                           std::string& err_code, std::string& err)
{
    std::set<uint32_t> have(present.begin(), present.end());
    for (uint32_t r : required) {
        if (have.count(r) == 0) {
            err_code = "SHARD_MISSING";
            err = "required shard set incomplete; no silent file-index substitution";
            return false;
        }
    }
    err_code.clear();
    err.clear();
    return true;
}

bool AdmitTensorMapCount(size_t tensor_count, uint64_t header_bytes, std::string& err_code, std::string& err)
{
    if (tensor_count > TENSOR_MAP_ENTRY_MAX) {
        err_code = "RESOURCE_LIMIT";
        err = "tensor count";
        return false;
    }
    if (header_bytes > TENSOR_MAP_BYTES_MAX) {
        err_code = "RESOURCE_LIMIT";
        err = "tensor map bytes";
        return false;
    }
    err_code.clear();
    err.clear();
    return true;
}

} // namespace modelnet
