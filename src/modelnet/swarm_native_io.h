// Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
#ifndef BITCOIN_MODELNET_SWARM_NATIVE_IO_H
#define BITCOIN_MODELNET_SWARM_NATIVE_IO_H
#include <crypto/sha384.h>
#include <util/fs.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <limits>
#include <span>
#include <string>
#include <vector>

namespace modelnet::native_io {
inline bool IsDigest(const std::string& value, size_t bytes = 48)
{
    return value.size() == bytes * 2 && std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
inline std::string Digest(std::span<const unsigned char> bytes)
{
    CSHA384 hash;
    hash.Write(bytes.data(), bytes.size());
    std::array<unsigned char, CSHA384::OUTPUT_SIZE> out{};
    hash.Finalize(out.data());
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(out.size() * 2);
    for (unsigned char value : out) { result += hex[value >> 4]; result += hex[value & 15]; }
    return result;
}
inline bool ReadVerified(const fs::path& path, const std::string& digest, uint64_t size,
                         uint64_t cap, std::vector<unsigned char>& bytes, std::string& err)
{
    if (!IsDigest(digest) || size == 0 || size > cap || size > std::numeric_limits<size_t>::max() ||
        size > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        err = "FILE_LIMIT_OR_DIGEST"; return false;
    }
    std::error_code ec;
    const auto status = fs::symlink_status(path, ec);
    if (ec || !fs::is_regular_file(status) || fs::is_symlink(status) || fs::file_size(path, ec) != size || ec) {
        err = "FILE_TYPE_OR_SIZE"; return false;
    }
    // The consumer receives these owned immutable bytes, never a later
    // reopen of a path that a peer could replace after verification.
    std::ifstream input(path, std::ios::binary);
    if (!input) { err = "FILE_READ"; return false; }
    std::vector<unsigned char> candidate;
    try { candidate.resize(static_cast<size_t>(size)); }
    catch (const std::bad_alloc&) { err = "FILE_MEMORY_LIMIT"; return false; }
    input.read(reinterpret_cast<char*>(candidate.data()), static_cast<std::streamsize>(candidate.size()));
    if (static_cast<uint64_t>(input.gcount()) != size || input.bad() || input.peek() != std::char_traits<char>::eof()) {
        err = "FILE_READ"; return false;
    }
    if (Digest(candidate) != digest) { err = "DIGEST"; return false; }
    bytes = std::move(candidate); err.clear(); return true;
}
inline void AppendField(std::vector<unsigned char>& out, const std::string& field)
{
    const uint64_t size = field.size();
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<unsigned char>(size >> (8 * i)));
    out.insert(out.end(), field.begin(), field.end());
}
inline void AppendNumber(std::vector<unsigned char>& out, uint64_t number)
{
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<unsigned char>(number >> (8 * i)));
}
} // namespace modelnet::native_io
#endif
