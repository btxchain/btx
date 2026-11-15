// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_sandbox/nif_sandbox.h>

#include <modelnet/nifdt_contract/contract.h>
#include <util/fs.h>

#include <algorithm>
#include <fstream>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

constexpr unsigned char kPickle[] = {
    'P', 'Y', 'T', 'H', 'O', 'N', '_', 'P', 'I', 'C', 'K', 'L', 'E',
};

enum class NodeKind {
    Missing,
    Symlink,
    Directory,
    Regular,
    Other,
};

// lexically_normal() writes the preferred separator, which is '\' on Windows.
bool IsSeparator(char c)
{
    return c == '/' || c == static_cast<char>(fs::path::preferred_separator);
}

bool HasRootPrefix(const std::string& root_utf8, const std::string& path_utf8)
{
    if (root_utf8.empty() || path_utf8.empty()) return false;
    if (path_utf8 == root_utf8) return true;
    if (path_utf8.size() <= root_utf8.size()) return false;
    if (path_utf8.compare(0, root_utf8.size(), root_utf8) != 0) return false;
    return IsSeparator(root_utf8.back()) || IsSeparator(path_utf8[root_utf8.size()]);
}

NodeKind Classify(const fs::path& path)
{
#ifdef _WIN32
    // On MinGW, libstdc++ implements lstat with stat, so symlink_status() never
    // reports a symbolic link or a junction. Ask Windows for the reparse
    // attribute, and refuse every reparse point.
    const DWORD attributes{GetFileAttributesW(path.wstring().c_str())};
    if (attributes == INVALID_FILE_ATTRIBUTES) return NodeKind::Missing;
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) return NodeKind::Symlink;
#endif
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(path, ec);
    if (ec || status.type() == fs::file_type::not_found || status.type() == fs::file_type::none) {
        return NodeKind::Missing;
    }
    if (fs::is_symlink(status)) return NodeKind::Symlink;
    if (fs::is_directory(status)) return NodeKind::Directory;
    if (fs::is_regular_file(status)) return NodeKind::Regular;
    return NodeKind::Other;
}

bool BeginsWithElf(const std::vector<unsigned char>& body)
{
    return body.size() >= 4 &&
           body[0] == 0x7f &&
           body[1] == static_cast<unsigned char>('E') &&
           body[2] == static_cast<unsigned char>('L') &&
           body[3] == static_cast<unsigned char>('F');
}

bool ContainsPickle(const std::vector<unsigned char>& body)
{
    if (body.size() < sizeof(kPickle)) return false;
    return std::search(body.begin(), body.end(), std::begin(kPickle), std::end(kPickle)) != body.end();
}

} // namespace

namespace modelnet {

bool NifSandbox::Bind(const fs::path& root, std::string& err)
{
    if (root.utf8string().empty()) {
        err = "ROOT";
        return false;
    }
    const fs::path rebuilt = fs::u8path(root.utf8string());
    const fs::path normal{rebuilt.lexically_normal()};
    const std::string utf8 = normal.utf8string();
    if (utf8.empty()) {
        err = "ROOT";
        return false;
    }
    m_root = normal;
    m_root_utf8 = utf8;
    err.clear();
    return true;
}

bool NifSandbox::ReadFile(const fs::path& path, std::string& err)
{
    if (Classify(path) != NodeKind::Regular) {
        err = "DENIED";
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "DENIED";
        return false;
    }
    std::vector<unsigned char> bytes;
    char chunk[4096];
    while (true) {
        in.read(chunk, static_cast<std::streamsize>(sizeof(chunk)));
        const std::streamsize got = in.gcount();
        if (got > 0) {
            const auto* raw = reinterpret_cast<const unsigned char*>(chunk);
            bytes.insert(bytes.end(), raw, raw + static_cast<std::size_t>(got));
        }
        if (in.bad()) {
            err = "DENIED";
            return false;
        }
        if (!in) break;
    }
    m_bytes_read += static_cast<int64_t>(bytes.size());
    m_opened = std::move(bytes);
    err.clear();
    return true;
}

bool NifSandbox::OpenInside(const fs::path& normal, std::string& err)
{
    if (normal.utf8string() == m_root_utf8) {
        const NodeKind root = Classify(m_root);
        if (root == NodeKind::Missing || root == NodeKind::Symlink) {
            err = "DENIED";
            return false;
        }
        err.clear();
        return true;
    }

    const fs::path relative{normal.lexically_relative(m_root)};
    fs::path walked = m_root;
    NodeKind leaf = NodeKind::Missing;
    bool saw_part = false;
    for (const auto& part : relative) {
        const std::string part_utf8 = fs::path{part}.utf8string();
        // On Windows a name like "C:x" below the root comes back from
        // lexically_relative() as the root name "C:" and then "x", and
        // appending "C:" either moves the walk to that drive or drops it from
        // the name. Refuse any part with a root name or a root directory.
        if (part_utf8.empty() || part_utf8 == "." || part_utf8 == ".." ||
            part.has_root_name() || part.has_root_directory()) {
            err = "DENIED";
            return false;
        }
        walked /= part;
        leaf = Classify(walked);
        saw_part = true;
        if (leaf != NodeKind::Directory && leaf != NodeKind::Regular) {
            err = "DENIED";
            return false;
        }
    }
    if (!saw_part || !fs::exists(walked)) {
        err = "DENIED";
        return false;
    }
    if (leaf == NodeKind::Regular) return ReadFile(walked, err);
    if (leaf == NodeKind::Directory) {
        err.clear();
        return true;
    }
    err = "DENIED";
    return false;
}

bool NifSandbox::OpenPath(const fs::path& path, std::string& err)
{
    // Prefix is decided on the normalized utf8 form before any walk, so a
    // path that leaves the root is not followed and nothing is read.
    if (m_root_utf8.empty()) {
        err = "DENIED";
        return false;
    }
    const fs::path rebuilt = fs::u8path(path.utf8string());
    const fs::path normal{rebuilt.lexically_normal()};
    if (!HasRootPrefix(m_root_utf8, normal.utf8string())) {
        err = "DENIED";
        return false;
    }
    return OpenInside(normal, err);
}

bool NifSandbox::Egress(const std::string& host, std::string& err)
{
    static_cast<void>(host);
    err = "DENIED";
    return false;
}

bool NifSandbox::Download(const std::string& url, std::string& err)
{
    static_cast<void>(url);
    err = "DOWNLOAD";
    return false;
}

bool NifSandbox::LoadCheckpoint(const std::vector<unsigned char>& body, std::string& err)
{
    if (BeginsWithElf(body) || ContainsPickle(body)) {
        err = "CODE";
        return false;
    }
    m_data = body;
    err.clear();
    return true;
}

bool NifSandbox::SpawnChild(std::string& err)
{
    if (m_slots.size() >= 2) {
        err = "LIMIT";
        return false;
    }
    m_slots.push_back(static_cast<std::uint64_t>(m_slots.size()));
    err.clear();
    return true;
}

} // namespace modelnet
