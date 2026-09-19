// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/erasure_store.h>

#include <modelnet/erasure_manifest.h>
#include <modelnet/io_executor.h>
#include <modelnet/types.h>

#include <crypto/sha384.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <set>
#include <unistd.h>

namespace modelnet {
namespace {

uint8_t GfPow(uint8_t a, int n)
{
    uint8_t r = 1;
    while (n) {
        if (n & 1) r = GfMul(r, a);
        a = GfMul(a, a);
        n >>= 1;
    }
    return r;
}

uint8_t GfInv(uint8_t a)
{
    return GfPow(a, 254);
}

std::vector<std::vector<uint8_t>> Generator(int k, int n)
{
    std::vector<std::vector<uint8_t>> g(n, std::vector<uint8_t>(k, 0));
    for (int i = 0; i < n; ++i) {
        if (i < k) {
            g[i][i] = 1;
        } else {
            for (int j = 0; j < k; ++j) g[i][j] = GfInv(static_cast<uint8_t>(i ^ j));
        }
    }
    return g;
}

bool Invert(const std::vector<std::vector<uint8_t>>& m, std::vector<std::vector<uint8_t>>& inv, std::string& err)
{
    const int n = static_cast<int>(m.size());
    if (n == 0) {
        err = "not square";
        return false;
    }
    std::vector<std::vector<uint8_t>> a(n, std::vector<uint8_t>(2 * n, 0));
    for (int i = 0; i < n; ++i) {
        if (static_cast<int>(m[i].size()) != n) {
            err = "not square";
            return false;
        }
        for (int j = 0; j < n; ++j) a[i][j] = m[i][j];
        a[i][n + i] = 1;
    }
    for (int c = 0; c < n; ++c) {
        int p = -1;
        for (int r = c; r < n; ++r) {
            if (a[r][c]) {
                p = r;
                break;
            }
        }
        if (p < 0) {
            err = "singular";
            return false;
        }
        std::swap(a[c], a[p]);
        const uint8_t invp = GfInv(a[c][c]);
        for (int j = 0; j < 2 * n; ++j) a[c][j] = GfMul(a[c][j], invp);
        for (int r = 0; r < n; ++r) {
            if (r == c) continue;
            const uint8_t f = a[r][c];
            for (int j = 0; j < 2 * n; ++j) a[r][j] ^= GfMul(f, a[c][j]);
        }
    }
    inv.assign(n, std::vector<uint8_t>(n, 0));
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) inv[i][j] = a[i][n + j];
    }
    return true;
}

bool Linear(const std::vector<std::vector<uint8_t>>& rows,
            const std::vector<std::vector<unsigned char>>& data,
            std::vector<std::vector<unsigned char>>& out, std::string& err)
{
    if (data.empty()) {
        err = "unequal shard sizes";
        return false;
    }
    const size_t len = data[0].size();
    for (const auto& s : data) {
        if (s.size() != len) {
            err = "unequal shard sizes";
            return false;
        }
    }
    out.clear();
    out.reserve(rows.size());
    for (const auto& row : rows) {
        std::vector<unsigned char> b(len, 0);
        for (size_t j = 0; j < row.size() && j < data.size(); ++j) {
            for (size_t i = 0; i < len; ++i) b[i] ^= GfMul(row[j], data[j][i]);
        }
        out.push_back(std::move(b));
    }
    return true;
}

} // namespace

uint8_t GfMul(uint8_t a, uint8_t b)
{
    unsigned x = 0;
    unsigned aa = a;
    while (b) {
        if (b & 1) x ^= aa;
        b >>= 1;
        aa <<= 1;
        if (aa & 256) aa ^= 0x11d;
    }
    return static_cast<uint8_t>(x);
}

bool EncodeShards(const std::vector<std::vector<unsigned char>>& data_shards, int n,
                  std::vector<std::vector<unsigned char>>& out, std::string& err)
{
    const int k = static_cast<int>(data_shards.size());
    if (!(1 <= k && k < n && n <= 255)) {
        err = "profile dimensions";
        return false;
    }
    return Linear(Generator(k, n), data_shards, out, err);
}

bool ReconstructShards(const std::vector<std::vector<unsigned char>>& shards,
                      const std::vector<int>& positions, int k, int n,
                      std::vector<std::vector<unsigned char>>& data_out, std::string& err)
{
    if (static_cast<int>(positions.size()) != k || static_cast<int>(shards.size()) != k) {
        err = "distinct k positions required";
        return false;
    }
    std::set<int> uniq(positions.begin(), positions.end());
    if (static_cast<int>(uniq.size()) != k) {
        err = "distinct k positions required";
        return false;
    }
    for (int p : positions) {
        if (p < 0 || p >= n) {
            err = "position";
            return false;
        }
    }
    auto g = Generator(k, n);
    std::vector<std::vector<uint8_t>> sub(k);
    for (int i = 0; i < k; ++i) sub[i] = g[positions[i]];
    std::vector<std::vector<uint8_t>> inv;
    if (!Invert(sub, inv, err)) return false;
    return Linear(inv, shards, data_out, err);
}

bool StripeReconstructable(const std::vector<std::vector<int>>& position_sets, int k)
{
    for (const auto& p : position_sets) {
        std::set<int> uniq(p.begin(), p.end());
        if (static_cast<int>(uniq.size()) < k) return false;
    }
    return true;
}

bool RepairCanonicalFromShards(const ErasureManifest& man,
                               const std::vector<std::vector<unsigned char>>& shards,
                               const std::vector<int>& positions,
                               std::vector<std::vector<unsigned char>>& data_out,
                               std::string& err,
                               int stripe_index)
{
    // Sufficiency is per stripe via ErasureManifestReconstructable. Never n,
    // never a summed global shard count.
    if (!ErasureManifestReconstructable(man)) {
        err = "global n is not sufficiency";
        return false;
    }
    const int k = man.data_shards;
    if (static_cast<int>(positions.size()) != k || static_cast<int>(shards.size()) != k) {
        err = "distinct k positions required";
        return false;
    }
    std::set<int> uniq(positions.begin(), positions.end());
    if (static_cast<int>(uniq.size()) != k) {
        err = "distinct k positions required";
        return false;
    }
    for (int p : positions) {
        if (p < 0 || p >= man.total_shards) {
            err = "position";
            return false;
        }
    }
    if (stripe_index < 0 && man.stripes.size() > 1) {
        err = "stripe_index required";
        return false;
    }
    if (stripe_index >= 0) {
        const ErasureStripe* bound = nullptr;
        for (const auto& st : man.stripes) {
            if (static_cast<int>(st.stripe_index) == stripe_index) {
                bound = &st;
                break;
            }
        }
        if (!bound) {
            err = "stripe_index";
            return false;
        }
        std::set<int> have(bound->positions.begin(), bound->positions.end());
        for (int p : positions) {
            if (!have.count(p)) {
                err = "stripe position";
                return false;
            }
        }
    }
    for (size_t i = 0; i < positions.size(); ++i) {
        std::string expected;
        for (const auto& st : man.stripes) {
            if (stripe_index >= 0 && static_cast<int>(st.stripe_index) != stripe_index) continue;
            for (size_t j = 0; j < st.positions.size() && j < st.shard_hash_hex.size(); ++j) {
                if (st.positions[j] == positions[i]) {
                    expected = st.shard_hash_hex[j];
                    break;
                }
            }
            if (!expected.empty()) break;
        }
        if (expected.empty()) continue;
        unsigned char d[CSHA384::OUTPUT_SIZE];
        CSHA384 hasher;
        hasher.Write(shards[i].data(), shards[i].size());
        hasher.Finalize(d);
        Digest48 got;
        std::memcpy(got.data.data(), d, Digest48::SIZE);
        if (got.Hex() != expected) {
            err = "shard hash mismatch";
            return false;
        }
    }
    return ReconstructShards(shards, positions, k, man.total_shards, data_out, err);
}

bool RepairStripeFromFiles(const ErasureManifest& man, const std::vector<std::string>& shard_paths,
                           const std::vector<int>& positions, const std::string& dest_path, std::string& err,
                           int stripe_index)
{
    if (dest_path.empty() || dest_path.find("..") != std::string::npos) {
        err = "dest";
        return false;
    }
    if (static_cast<int>(positions.size()) != man.data_shards ||
        shard_paths.size() != positions.size()) {
        err = "distinct k positions required";
        return false;
    }
    IoExecutor io;
    std::vector<std::vector<unsigned char>> shards;
    shards.reserve(shard_paths.size());
    for (const auto& path : shard_paths) {
        if (!io.Submit(err)) return false;
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            io.Complete();
            err = "shard open";
            return false;
        }
        std::vector<unsigned char> bytes;
        bytes.resize(static_cast<size_t>(man.shard_bytes) + 1);
        in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        const auto got = static_cast<size_t>(in.gcount());
        io.Complete();
        if (got != static_cast<size_t>(man.shard_bytes)) {
            err = "shard size";
            return false;
        }
        bytes.resize(got);
        shards.push_back(std::move(bytes));
    }
    std::vector<std::vector<unsigned char>> data_out;
    if (!RepairCanonicalFromShards(man, shards, positions, data_out, err, stripe_index)) return false;
    const std::string tmp_path = dest_path + ".tmp";
    ::unlink(tmp_path.c_str());
    if (!io.Submit(err)) return false;
    const int fd = ::open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
    if (fd < 0) {
        io.Complete();
        err = "dest open";
        return false;
    }
    bool ok = true;
    for (const auto& d : data_out) {
        if (d.empty()) continue;
        const ssize_t n = ::write(fd, d.data(), d.size());
        if (n < 0 || static_cast<size_t>(n) != d.size()) {
            ok = false;
            break;
        }
    }
    if (ok && ::fsync(fd) != 0) ok = false;
    if (::close(fd) != 0) ok = false;
    io.Complete();
    if (!ok) {
        ::unlink(tmp_path.c_str());
        err = "dest write";
        return false;
    }
    if (::rename(tmp_path.c_str(), dest_path.c_str()) != 0) {
        ::unlink(tmp_path.c_str());
        err = "dest rename";
        return false;
    }
    return true;
}

bool MapTorrentRange(const std::vector<TorrentFileMap>& files, uint64_t offset, uint64_t length,
                     std::vector<TorrentSlice>& out, std::string& err)
{
    out.clear();
    uint64_t total = 0;
    for (const auto& f : files) total += f.size;
    if (offset + length < offset || offset + length > total) {
        err = "outside torrent";
        return false;
    }
    uint64_t pos = 0;
    const uint64_t end = offset + length;
    for (const auto& f : files) {
        const uint64_t a = std::max(pos, offset);
        const uint64_t b = std::min(pos + f.size, end);
        if (a < b && !f.padding) {
            TorrentSlice s;
            s.name = f.name;
            s.file_offset = a - pos;
            s.length = b - a;
            out.push_back(std::move(s));
        }
        pos += f.size;
    }
    return true;
}

} // namespace modelnet
