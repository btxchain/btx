// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/workspace_journal.h>

#include <sstream>

namespace modelnet {
namespace {

std::string Hex(const std::vector<unsigned char>& bytes)
{
    static const char* digits = "0123456789abcdef";
    std::string out(bytes.size() * 2, '\0');
    for (size_t i = 0; i < bytes.size(); ++i) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 0x0f];
    }
    return out;
}

} // namespace

bool Conflict(const std::vector<unsigned char>& path_a_bytes, const std::vector<unsigned char>& path_b_bytes)
{
    return path_a_bytes != path_b_bytes;
}

WorkspaceBook::Tree* WorkspaceBook::Find(const std::string& name)
{
    const auto it = m_trees.find(name);
    if (it == m_trees.end()) return nullptr;
    return &it->second;
}

const WorkspaceBook::Tree* WorkspaceBook::Find(const std::string& name) const
{
    const auto it = m_trees.find(name);
    if (it == m_trees.end()) return nullptr;
    return &it->second;
}

bool WorkspaceBook::OpenTree(const std::string& name, std::string& err)
{
    err.clear();
    if (name.empty() || m_trees.find(name) != m_trees.end()) {
        err = "BTX035_WORKSPACE";
        return false;
    }
    m_trees.emplace(name, Tree{});
    return true;
}

bool WorkspaceBook::Put(const std::string& name, uint64_t generation, const std::string& path,
                        const std::vector<unsigned char>& bytes, std::string& err)
{
    err.clear();
    Tree* tree = Find(name);
    if (tree == nullptr) {
        err = "BTX035_WORKSPACE";
        return false;
    }
    if (generation != tree->generation) {
        err = "BTX035_GENERATION";
        return false;
    }
    tree->live[path] = bytes;
    return true;
}

bool WorkspaceBook::Publish(const std::string& name, uint64_t generation, bool conflict, bool public_ok,
                            std::string& err)
{
    err.clear();
    Tree* tree = Find(name);
    if (tree == nullptr) {
        err = "BTX035_WORKSPACE";
        return false;
    }
    if (generation != tree->generation) {
        err = "BTX035_GENERATION";
        return false;
    }
    if (conflict) {
        err = "BTX035_CONFLICT";
        return false;
    }
    tree->closed[tree->generation] = tree->live;
    if (public_ok) {
        tree->publication_ids.push_back(tree->next_publication);
        ++tree->next_publication;
    }
    ++tree->generation;
    return true;
}

bool WorkspaceBook::Undo(const std::string& name, std::string& err)
{
    err.clear();
    Tree* tree = Find(name);
    if (tree == nullptr) {
        err = "BTX035_WORKSPACE";
        return false;
    }
    if (tree->generation <= 1) {
        err = "BTX035_UNDO";
        return false;
    }
    const uint64_t previous = tree->generation - 1;
    const auto closed = tree->closed.find(previous);
    if (closed == tree->closed.end()) {
        err = "BTX035_UNDO";
        return false;
    }
    tree->live = closed->second;
    tree->generation = previous;
    return true;
}

bool WorkspaceBook::NotePrivate(const std::string& name, const std::string& text, std::string& err)
{
    err.clear();
    Tree* tree = Find(name);
    if (tree == nullptr) {
        err = "BTX035_WORKSPACE";
        return false;
    }
    tree->private_notes.push_back(text);
    return true;
}

std::string WorkspaceBook::ExportPublic(const std::string& name) const
{
    const Tree* tree = Find(name);
    if (tree == nullptr) return {};
    std::ostringstream out;
    out << "workspace " << name << '\n';
    out << "generation " << tree->generation << '\n';
    for (const uint64_t id : tree->publication_ids) {
        out << "publication " << id << '\n';
    }
    for (const auto& entry : tree->live) {
        out << "file " << entry.first << ' ' << Hex(entry.second) << '\n';
    }
    return out.str();
}

bool WorkspaceBook::Cancel(const std::string& name, const std::string& op_id, std::string& err)
{
    err.clear();
    Tree* tree = Find(name);
    if (tree == nullptr || op_id.empty()) {
        err = "BTX035_WORKSPACE";
        return false;
    }
    if (tree->completed.count(op_id) != 0) {
        err = "BTX035_LATE";
        return false;
    }
    tree->cancelled.insert(op_id);
    return true;
}

bool WorkspaceBook::Complete(const std::string& name, const std::string& op_id, uint64_t generation,
                             const std::string& path, const std::vector<unsigned char>& bytes, std::string& err)
{
    err.clear();
    Tree* tree = Find(name);
    if (tree == nullptr || op_id.empty()) {
        err = "BTX035_WORKSPACE";
        return false;
    }
    if (tree->cancelled.count(op_id) != 0 || tree->completed.count(op_id) != 0) {
        err = "BTX035_LATE";
        return false;
    }
    if (generation != tree->generation) {
        err = "BTX035_GENERATION";
        return false;
    }
    tree->live[path] = bytes;
    tree->completed.insert(op_id);
    return true;
}

std::vector<std::string> WorkspaceBook::TreeNames() const
{
    std::vector<std::string> names;
    names.reserve(m_trees.size());
    for (const auto& item : m_trees) names.push_back(item.first);
    return names;
}

bool WorkspaceBook::ExportTree(const std::string& name, TreeImage& out) const
{
    const Tree* tree = Find(name);
    if (tree == nullptr) return false;
    out.generation = tree->generation;
    out.live = tree->live;
    out.closed = tree->closed;
    out.publication_ids = tree->publication_ids;
    out.next_publication = tree->next_publication;
    out.cancelled = tree->cancelled;
    out.completed = tree->completed;
    return true;
}

bool WorkspaceBook::ImportTree(const std::string& name, const TreeImage& image, std::string& err)
{
    err.clear();
    if (name.empty() || m_trees.find(name) != m_trees.end() || image.generation == 0 || image.next_publication == 0) {
        err = "BTX035_WORKSPACE";
        return false;
    }
    Tree tree;
    tree.generation = image.generation;
    tree.live = image.live;
    tree.closed = image.closed;
    tree.publication_ids = image.publication_ids;
    tree.next_publication = image.next_publication;
    tree.cancelled = image.cancelled;
    tree.completed = image.completed;
    m_trees.emplace(name, std::move(tree));
    return true;
}

uint64_t WorkspaceBook::Generation(const std::string& name) const
{
    const Tree* tree = Find(name);
    if (tree == nullptr) return 0;
    return tree->generation;
}

bool WorkspaceBook::Read(const std::string& name, const std::string& path, std::vector<unsigned char>& bytes) const
{
    bytes.clear();
    const Tree* tree = Find(name);
    if (tree == nullptr) return false;
    const auto it = tree->live.find(path);
    if (it == tree->live.end()) return false;
    bytes = it->second;
    return true;
}

std::vector<uint64_t> WorkspaceBook::PublicationIds(const std::string& name) const
{
    const Tree* tree = Find(name);
    if (tree == nullptr) return {};
    return tree->publication_ids;
}

size_t WorkspaceBook::PrivateNoteCount(const std::string& name) const
{
    const Tree* tree = Find(name);
    if (tree == nullptr) return 0;
    return tree->private_notes.size();
}

} // namespace modelnet
