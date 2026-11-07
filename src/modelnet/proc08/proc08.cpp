// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/proc08/proc08.h>
#include <modelnet/nifdt_contract/contract.h>
#include <util/fs.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace modelnet {
namespace {

constexpr std::uint64_t kFnvOffset = 14695981039346656037ULL;
constexpr std::uint64_t kFnvPrime = 1099511628211ULL;

std::string StripTrailingSlashes(std::string value)
{
    while (value.size() > 1 && value.back() == '/') {
        value.pop_back();
    }
    return value;
}

bool PathInsideRoot(const std::string& path, const std::string& root)
{
    const std::string p = StripTrailingSlashes(path);
    const std::string r = StripTrailingSlashes(root);
    if (p == r) {
        return true;
    }
    if (r == "/") {
        return !p.empty() && p.front() == '/';
    }
    return p.size() > r.size() && p.compare(0, r.size(), r) == 0 && p[r.size()] == '/';
}

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

bool Proc08::ReadEvidence(const std::string& dir, std::string& err)
{
    m_digest.clear();
    m_files = 0;
    if (dir.empty()) {
        err = "FIELD";
        return false;
    }

    const fs::path root = fs::PathFromString(dir);
    if (!fs::exists(root) || !fs::is_directory(root)) {
        err = "ABSENT";
        return false;
    }

    std::vector<fs::path> files;
    try {
        for (const fs::directory_entry& entry : fs::directory_iterator(root)) {
            const fs::path child{entry.path()};
            if (fs::is_regular_file(child)) {
                files.push_back(child);
            }
        }
    } catch (const fs::filesystem_error&) {
        err = "READ";
        return false;
    }

    if (files.empty()) {
        err = "EMPTY";
        return false;
    }

    std::sort(files.begin(), files.end(), [](const fs::path& a, const fs::path& b) {
        return fs::PathToString(a) < fs::PathToString(b);
    });

    std::uint64_t hash = kFnvOffset;
    char buf[4096];
    for (const fs::path& child : files) {
        std::ifstream in{child, std::ios::binary};
        if (!in) {
            err = "READ";
            return false;
        }
        while (in.read(buf, sizeof(buf)) || in.gcount() > 0) {
            MixBytes(hash, buf, in.gcount());
            if (in.bad()) {
                err = "READ";
                return false;
            }
        }
    }

    m_digest = Hex64(hash);
    m_files = static_cast<int>(files.size());
    err.clear();
    return true;
}

bool Proc08::AcceptResearchPath(const std::string& path, const std::string& worktree_root, std::string& err)
{
    if (path.empty() || worktree_root.empty()) {
        err = "FIELD";
        return false;
    }
    if (PathInsideRoot(path, worktree_root)) {
        m_research_outside = false;
        err = "INSIDE";
        return false;
    }
    if (!fs::exists(fs::PathFromString(path))) {
        err = "ABSENT";
        return false;
    }
    m_research_outside = true;
    err.clear();
    return true;
}

} // namespace modelnet
