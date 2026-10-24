// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_form/atomic.h>

#include <util/fs_helpers.h>

#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <system_error>

#ifndef WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace modelnet {

bool SwarmReadRegularFile(const fs::path& path, std::string& raw)
{
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) return false;
#ifndef WIN32
    // The path can change after that check, and opening a FIFO for reading
    // waits for a writer. Open without waiting and check the file that was
    // opened.
    const int fd = ::open(path.c_str(), O_RDONLY | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        ::close(fd);
        return false;
    }
    FILE* file = ::fdopen(fd, "rb");
    if (!file) {
        ::close(fd);
        return false;
    }
#else
    FILE* file = fsbridge::fopen(path, "rb");
    if (!file) return false;
#endif
    std::string loaded;
    char buf[4096];
    size_t got;
    while ((got = fread(buf, 1, sizeof(buf), file)) > 0) loaded.append(buf, got);
    const bool read_ok = !ferror(file);
    fclose(file);
    if (!read_ok) return false;
    raw = std::move(loaded);
    return true;
}

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
    if (!SwarmReadRegularFile(path, raw)) {
        err = "READ";
        return false;
    }
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
#ifndef WIN32
    // Opening a FIFO for writing waits for a reader. Create the temp file
    // exclusively; if the name is taken (the temp file of an interrupted
    // write, a FIFO, a device), remove that entry and create it once more.
    // A second failure is an error, not a wait.
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd < 0 && errno == EEXIST) {
        std::filesystem::remove(tmp, ec);
        fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0666);
    }
    FILE* file = fd < 0 ? nullptr : ::fdopen(fd, "wb");
    if (!file && fd >= 0) {
        ::close(fd);
        std::filesystem::remove(tmp, ec);
    }
#else
    FILE* file = fsbridge::fopen(tmp, "wb");
#endif
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
