// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_form/atomic.h>

#include <util/fs_helpers.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <system_error>

namespace modelnet {

bool SwarmFormRead(const fs::path& path, std::string& raw, std::string& err)
{
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(path, ec);
    if (!ec && fs::is_symlink(status)) {
        err = "SYMLINK";
        return false;
    }
    if (!fs::exists(path)) {
        err = "MISSING";
        return false;
    }
    if (!fs::is_regular_file(path, ec)) {
        err = "READ";
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "READ";
        return false;
    }
    std::string loaded((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (!in && !in.eof()) {
        err = "READ";
        return false;
    }
    raw = std::move(loaded);
    err.clear();
    return true;
}

bool SwarmFormWrite(const fs::path& path, const std::string& body, std::string& err)
{
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(path, ec);
    if (!ec && fs::is_symlink(status)) {
        err = "SYMLINK";
        return false;
    }
    const fs::path tmp = fs::u8path(path.utf8string() + ".tmp");
    ec.clear();
    const fs::file_status tmp_status = fs::symlink_status(tmp, ec);
    if (!ec && fs::is_symlink(tmp_status)) {
        err = "SYMLINK";
        return false;
    }
    FILE* file = fsbridge::fopen(tmp, "wb");
    if (!file) {
        err = "WRITE";
        return false;
    }
    const bool written = fwrite(body.data(), 1, body.size(), file) == body.size() && FileCommit(file);
    if (fclose(file) != 0 || !written) {
        err = "WRITE";
        std::filesystem::remove(tmp, ec);
        return false;
    }
    fs::rename(tmp, path, ec);
    if (ec) {
        err = "RENAME";
        std::error_code ignore;
        std::filesystem::remove(tmp, ignore);
        return false;
    }
    DirectoryCommit(path.parent_path());
    err.clear();
    return true;
}

} // namespace modelnet
