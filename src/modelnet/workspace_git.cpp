// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/workspace_git.h>

#include <modelnet/git_snapshot.h>

#include <fstream>
#include <sstream>
#include <system_error>
#include <utility>

namespace modelnet {
namespace {

bool TreeNameOk(const std::string& name)
{
    if (name.empty() || name == "." || name == "..") return false;
    if (name.find('/') != std::string::npos || name.find('\\') != std::string::npos) return false;
    if (name.find('\0') != std::string::npos) return false;
    return true;
}

} // namespace

WorkspaceGit::WorkspaceGit(fs::path root) : m_root(std::move(root)) {}

bool WorkspaceGit::Create(const std::string& name, std::string& err)
{
    err.clear();
    if (!TreeNameOk(name)) {
        err = "BTX035_WORKSPACE";
        return false;
    }
    if (!m_book.OpenTree(name, err)) return false;
    const fs::path tree = m_root / name.c_str();
    if (!fs::create_directories(tree)) {
        err = "BTX035_WORKSPACE";
        return false;
    }
    return true;
}

bool WorkspaceGit::Materialize(const fs::path& tree, const std::string& path,
                               const std::vector<unsigned char>& bytes, std::string& err) const
{
    fs::path dest = tree;
    size_t begin = 0;
    while (begin <= path.size()) {
        const size_t slash = path.find('/', begin);
        const std::string seg = path.substr(begin, slash == std::string::npos ? std::string::npos : slash - begin);
        dest /= seg.c_str();
        if (slash == std::string::npos) break;
        begin = slash + 1;
    }
    const fs::path relative = dest.lexically_normal().lexically_relative(tree.lexically_normal());
    if (relative.empty() || *relative.begin() == "..") {
        err = "BTX035_PATH_UNSAFE";
        return false;
    }
    const fs::path parent = dest.parent_path();
    if (fs::exists(parent)) {
        if (!std::filesystem::is_directory(parent)) {
            err = "BTX035_WORKSPACE";
            return false;
        }
    } else if (!fs::create_directories(parent)) {
        err = "BTX035_WORKSPACE";
        return false;
    }
    std::ofstream out(dest, std::ios::binary | std::ios::trunc);
    if (!out) {
        err = "BTX035_WORKSPACE";
        return false;
    }
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    out.close();
    if (!out) {
        err = "BTX035_WORKSPACE";
        return false;
    }
    err.clear();
    return true;
}

bool WorkspaceGit::Write(const std::string& name, uint64_t generation, const std::string& path,
                         const std::vector<unsigned char>& bytes, std::string& err)
{
    err.clear();
    if (m_book.Generation(name) == 0) {
        err = "BTX035_WORKSPACE";
        return false;
    }
    if (!SafeGitPath(path, err)) return false;
    if (generation != m_book.Generation(name)) {
        err = "BTX035_GENERATION";
        return false;
    }
    if (!m_book.Put(name, generation, path, bytes, err)) return false;
    std::vector<unsigned char> stored;
    if (!m_book.Read(name, path, stored)) {
        err = "BTX035_WORKSPACE";
        return false;
    }
    return Materialize(m_root / name.c_str(), path, stored, err);
}

bool WorkspaceGit::Publish(const std::string& name, uint64_t generation, std::string& err)
{
    return m_book.Publish(name, generation, false, true, err);
}

bool WorkspaceGit::NotePrivate(const std::string& name, const std::string& text, std::string& err)
{
    return m_book.NotePrivate(name, text, err);
}

uint64_t WorkspaceGit::Generation(const std::string& name) const
{
    return m_book.Generation(name);
}

std::vector<std::string> WorkspaceGit::ExportFiles(const std::string& name) const
{
    std::vector<std::string> files;
    std::istringstream in(m_book.ExportPublic(name));
    std::string line;
    const std::string prefix = "file ";
    while (std::getline(in, line)) {
        if (line.compare(0, prefix.size(), prefix) != 0) continue;
        const std::string rest = line.substr(prefix.size());
        const size_t space = rest.rfind(' ');
        if (space == std::string::npos) continue;
        files.push_back(rest.substr(0, space));
    }
    return files;
}

std::string WorkspaceGit::ExportPublic(const std::string& name) const
{
    return m_book.ExportPublic(name);
}

} // namespace modelnet
