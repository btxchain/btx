// Copyright (c) 2015-2022 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/readwritefile.h>

#include <random.h>
#include <util/fs.h>
#include <util/fs_helpers.h>

#include <algorithm>
#include <cstdio>
#include <limits>
#include <string>
#include <system_error>
#include <utility>

std::pair<bool,std::string> ReadBinaryFile(const fs::path &filename, size_t maxsize)
{
    FILE *f = fsbridge::fopen(filename, "rb");
    if (f == nullptr)
        return std::make_pair(false,"");
    std::string retval;
    char buffer[128];
    do {
        const size_t n = fread(buffer, 1, std::min(sizeof(buffer), maxsize - retval.size()), f);
        // Check for reading errors so we don't return any data if we couldn't
        // read the entire file (or up to maxsize)
        if (ferror(f)) {
            fclose(f);
            return std::make_pair(false,"");
        }
        retval.append(buffer, buffer+n);
    } while (!feof(f) && retval.size() < maxsize);
    fclose(f);
    return std::make_pair(true,retval);
}

bool WriteBinaryFile(const fs::path &filename, const std::string &data)
{
    FILE *f = fsbridge::fopen(filename, "wb");
    if (f == nullptr)
        return false;
    if (fwrite(data.data(), 1, data.size(), f) != data.size()) {
        fclose(f);
        return false;
    }
    if (fclose(f) != 0) {
        return false;
    }
    return true;
}

bool WriteBinaryFileAtomically(const fs::path& filename, std::string_view data)
{
    std::error_code ec;
    const auto status = fs::symlink_status(filename, ec);
    if (ec && ec != std::errc::no_such_file_or_directory) return false;
    if (fs::exists(status) && !fs::is_regular_file(status)) return false;

    FastRandomContext rng;
    const fs::path tmp = filename.parent_path() / fs::PathFromString(".btx-export-" + std::to_string(rng.rand64()) + ".tmp");
    FILE* file = fsbridge::fopen(tmp, "wbx");
    if (!file) return false;
    const bool written = data.empty() || std::fwrite(data.data(), 1, data.size(), file) == data.size();
    const bool committed = written && FileCommit(file);
    const bool closed = std::fclose(file) == 0;
    ec.clear();
#ifndef WIN32
    if (committed && closed && fs::exists(status)) {
        fs::permissions(tmp, status.permissions() & fs::perms::all, fs::perm_options::replace, ec);
    }
#endif
    if (committed && closed && !ec && RenameOver(tmp, filename)) {
        const auto parent = filename.parent_path();
        // Replacement has already happened. DirectoryCommit is best-effort.
        DirectoryCommit(parent.empty() ? fs::PathFromString(".") : parent);
        return true;
    }
    fs::remove(tmp, ec);
    return false;
}
