// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/load01/load01.h>
#include <modelnet/nifdt_contract/contract.h>
#include <util/fs.h>
#include <modelnet/identity.h>
#include <modelnet/swarm_native_io.h>
#include <univalue.h>
#include <algorithm>
#include <bit>
#include <cmath>
#include <limits>
#include <set>

#include <cstdint>
#include <fstream>
#include <string>

namespace modelnet {
namespace {

constexpr std::uint64_t kFnvOffset = 14695981039346656037ULL;
constexpr std::uint64_t kFnvPrime = 1099511628211ULL;

void MixBytes(std::uint64_t& hash, const char* data, std::streamsize n)
{
    for (std::streamsize i = 0; i < n; ++i) {
        hash ^= static_cast<unsigned char>(data[i]);
        hash *= kFnvPrime;
    }
}

std::string Hex64(std::uint64_t hash)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 0; i < 16; ++i) {
        const int shift = (15 - i) * 4;
        out[static_cast<std::size_t>(i)] = kHex[(hash >> shift) & 0xF];
    }
    return out;
}

} // namespace

bool Load01::Load(const std::string& source_path, const std::string& digest_hex, std::string& err)
{
    if (source_path.empty() || digest_hex.empty()) {
        err = "FIELD";
        return false;
    }

    const fs::path path = fs::PathFromString(source_path);
    try {
        if (!fs::exists(path)) {
            err = "ABSENT";
            return false;
        }
        if (fs::is_directory(path) || !fs::is_regular_file(path)) {
            err = "IO";
            return false;
        }
    } catch (const fs::filesystem_error&) {
        err = "IO";
        return false;
    }

    std::ifstream in{path, std::ios::binary};
    if (!in) {
        err = "IO";
        return false;
    }

    std::uint64_t hash = kFnvOffset;
    int64_t nbytes = 0;
    char buf[4096];
    while (in.read(buf, sizeof(buf)) || in.gcount() > 0) {
        const std::streamsize n = in.gcount();
        if (n < 0 || in.bad()) {
            err = "IO";
            return false;
        }
        MixBytes(hash, buf, n);
        nbytes += static_cast<int64_t>(n);
    }
    if (in.bad()) {
        err = "IO";
        return false;
    }

    if (Hex64(hash) != digest_hex) {
        err = "DIGEST";
        return false;
    }

    // Integrity-only legacy loads cannot inherit previous native qualification.
    m_verified = false; m_consumed = false;
    m_resident.clear(); m_tensors.clear(); m_sources.clear();
    m_checkpoint.clear(); m_artifact.clear();
    m_bytes = nbytes;
    m_source = source_path;
    m_loaded = true;
    err.clear();
    return true;
}

std::vector<unsigned char> CheckpointSourceMessage(const CheckpointSourceReceipt& receipt)
{
    std::vector<unsigned char> out;
    native_io::AppendField(out, "BTX/CheckpointSource/v1");
    native_io::AppendField(out, receipt.artifact_id);
    native_io::AppendField(out, receipt.checkpoint_sha384);
    native_io::AppendNumber(out, receipt.bytes);
    native_io::AppendField(out, receipt.request_nonce);
    native_io::AppendNumber(out, static_cast<uint64_t>(receipt.expires_at_ms));
    native_io::AppendNumber(out, receipt.source_public_key.size());
    out.insert(out.end(), receipt.source_public_key.begin(), receipt.source_public_key.end());
    return out;
}
namespace {
uint64_t Little64(const unsigned char* bytes)
{
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) value |= static_cast<uint64_t>(bytes[i]) << (i * 8);
    return value;
}
float LittleFloat(const unsigned char* bytes)
{
    const uint32_t value = static_cast<uint32_t>(bytes[0]) | (static_cast<uint32_t>(bytes[1]) << 8) |
                           (static_cast<uint32_t>(bytes[2]) << 16) | (static_cast<uint32_t>(bytes[3]) << 24);
    return std::bit_cast<float>(value);
}
bool ParseSafeTensors(const std::vector<unsigned char>& bytes,
                      std::map<std::string, LoadedCheckpointTensor>& tensors, std::string& err)
{
    if (bytes.size() < 10) { err = "CHECKPOINT_FORMAT"; return false; }
    const uint64_t length = Little64(bytes.data());
    if (length == 0 || length > 16 * 1024 * 1024 || length > bytes.size() - 8) {
        err = "CHECKPOINT_HEADER_LIMIT"; return false;
    }
    UniValue header;
    if (!header.read(std::string(reinterpret_cast<const char*>(bytes.data() + 8), length)) || !header.isObject()) {
        err = "CHECKPOINT_HEADER"; return false;
    }
    static const std::map<std::string, uint64_t> widths{
        {"BOOL",1},{"U8",1},{"I8",1},{"F8_E4M3",1},{"F8_E5M2",1},
        {"I16",2},{"U16",2},{"F16",2},{"BF16",2},{"I32",4},{"U32",4},{"F32",4},
        {"I64",8},{"U64",8},{"F64",8}};
    std::set<std::string> names;
    std::vector<std::pair<uint64_t,uint64_t>> ranges;
    const uint64_t data = length + 8;
    try {
        for (const std::string& name : header.getKeys()) {
            if (!names.insert(name).second || name.empty() || name.size() > 4096) {
                err = "CHECKPOINT_DUPLICATE"; return false;
            }
            const UniValue& value = header[name];
            if (name == "__metadata__") {
                if (!value.isObject()) { err = "CHECKPOINT_METADATA"; return false; }
                for (const auto& item : value.getValues()) if (!item.isStr()) { err = "CHECKPOINT_METADATA"; return false; }
                continue;
            }
            if (!value.isObject() || value.size() != 3 || !value["dtype"].isStr() ||
                !value["shape"].isArray() || value["shape"].size() > 32 ||
                !value["data_offsets"].isArray() || value["data_offsets"].size() != 2) {
                err = "CHECKPOINT_TENSOR"; return false;
            }
            LoadedCheckpointTensor tensor;
            tensor.dtype = value["dtype"].get_str();
            const auto width = widths.find(tensor.dtype);
            if (width == widths.end()) { err = "CHECKPOINT_DTYPE"; return false; }
            uint64_t elements = 1;
            for (const auto& dim : value["shape"].getValues()) {
                if (!dim.isNum()) { err = "CHECKPOINT_SHAPE"; return false; }
                const uint64_t count = dim.getInt<uint64_t>();
                if (count > 0 && elements > (bytes.size() / width->second) / count) {
                    err = "CHECKPOINT_SHAPE"; return false;
                }
                elements *= count; tensor.shape.push_back(count);
            }
            const auto& offsets = value["data_offsets"];
            if (!offsets[0].isNum() || !offsets[1].isNum()) { err = "CHECKPOINT_OFFSETS"; return false; }
            const uint64_t begin = offsets[0].getInt<uint64_t>(), end = offsets[1].getInt<uint64_t>();
            if (end < begin || end > bytes.size() - data || end - begin != elements * width->second) {
                err = "CHECKPOINT_OFFSETS"; return false;
            }
            tensor.begin = data + begin; tensor.end = data + end;
            if (begin != end) ranges.emplace_back(begin, end);
            tensors.emplace(name, std::move(tensor));
        }
    } catch (const std::exception&) { err = "CHECKPOINT_NUMERIC"; return false; }
    if (tensors.empty() || tensors.size() > 100000) { err = "CHECKPOINT_TENSOR_COUNT"; return false; }
    std::sort(ranges.begin(), ranges.end());
    uint64_t consumed = 0;
    for (const auto& [begin, end] : ranges) {
        if (begin != consumed) { err = "CHECKPOINT_OVERLAP_OR_HOLE"; return false; }
        consumed = end;
    }
    if (consumed != bytes.size() - data) { err = "CHECKPOINT_TRAILING_DATA"; return false; }
    return true;
}
} // namespace

bool Load01::LoadVerified(const std::string& source_path, const CheckpointSourceReceipt& receipt,
                          const std::vector<unsigned char>& expected_source_key,
                          const std::string& expected_nonce, int64_t now_ms, uint64_t max_bytes,
                          std::string& err)
{
    if (source_path.empty() || !native_io::IsDigest(receipt.artifact_id) ||
        !native_io::IsDigest(receipt.checkpoint_sha384) || !native_io::IsDigest(expected_nonce, 32) ||
        receipt.request_nonce != expected_nonce || now_ms < 0 || receipt.expires_at_ms <= now_ms ||
        receipt.expires_at_ms - now_ms > 3600000 || receipt.bytes > static_cast<uint64_t>(INT64_MAX) ||
        max_bytes == 0 || expected_source_key.size() != MLDSA44_PK ||
        receipt.source_public_key != expected_source_key || receipt.signature.size() != MLDSA44_SIG) {
        err = "CHECKPOINT_RECEIPT"; return false;
    }
    const auto message = CheckpointSourceMessage(receipt);
    if (!VerifyMlDsa44(receipt.source_public_key, message, receipt.signature)) {
        err = "CHECKPOINT_SIGNATURE"; return false;
    }
    std::vector<unsigned char> candidate;
    if (!native_io::ReadVerified(fs::PathFromString(source_path), receipt.checkpoint_sha384,
                                receipt.bytes, max_bytes, candidate, err)) return false;
    std::map<std::string, LoadedCheckpointTensor> tensors;
    if (!ParseSafeTensors(candidate, tensors, err)) return false;
    // Parse and verify the entire new candidate before replacing the resident
    // checkpoint. Failed second-source attempts leave the old model intact.
    if (m_checkpoint != receipt.checkpoint_sha384 || m_artifact != receipt.artifact_id) m_sources.clear();
    m_sources.insert(receipt.source_public_key);
    m_resident = std::move(candidate); m_tensors = std::move(tensors);
    m_checkpoint = receipt.checkpoint_sha384; m_artifact = receipt.artifact_id;
    m_bytes = static_cast<int64_t>(receipt.bytes); m_source = source_path;
    m_loaded = true; m_verified = true; m_consumed = false;
    err.clear(); return true;
}
std::span<const unsigned char> Load01::TensorBytes(const std::string& name) const
{
    const auto it = m_tensors.find(name);
    if (!m_verified || it == m_tensors.end()) return {};
    return {m_resident.data() + it->second.begin, static_cast<size_t>(it->second.end - it->second.begin)};
}
bool Load01::LinearF32(const std::string& weights, const std::string& bias,
                       std::span<const float> input, std::vector<float>& output, std::string& err)
{
    const auto it = m_tensors.find(weights);
    if (!m_verified || it == m_tensors.end() || it->second.dtype != "F32" ||
        it->second.shape.size() != 2 || it->second.shape[1] != input.size() || input.empty() ||
        it->second.shape[0] == 0 || it->second.end - it->second.begin > 256 * 1024 * 1024) {
        err = "LINEAR_SHAPE_OR_LIMIT"; return false;
    }
    const auto rows = it->second.shape[0], columns = it->second.shape[1];
    const auto data = TensorBytes(weights);
    std::span<const unsigned char> bias_data;
    if (!bias.empty()) {
        const auto b = m_tensors.find(bias);
        if (b == m_tensors.end() || b->second.dtype != "F32" || b->second.shape != std::vector<uint64_t>{rows}) {
            err = "LINEAR_BIAS"; return false;
        }
        bias_data = TensorBytes(bias);
    }
    for (float value : input) if (!std::isfinite(value)) { err = "LINEAR_NONFINITE"; return false; }
    std::vector<float> candidate(static_cast<size_t>(rows));
    for (uint64_t row = 0; row < rows; ++row) {
        double value = bias.empty() ? 0 : LittleFloat(bias_data.data() + row * 4);
        for (uint64_t col = 0; col < columns; ++col) {
            const float weight = LittleFloat(data.data() + (row * columns + col) * 4);
            if (!std::isfinite(weight)) { err = "LINEAR_NONFINITE"; return false; }
            value += static_cast<double>(weight) * input[col];
        }
        const float result = static_cast<float>(value);
        if (!std::isfinite(result)) { err = "LINEAR_NONFINITE"; return false; }
        candidate[row] = result;
    }
    output = std::move(candidate); m_consumed = true; err.clear(); return true;
}
} // namespace modelnet
