// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_FS_HELPERS_H
#define BITCOIN_UTIL_FS_HELPERS_H

#include <util/fs.h>

#include <cstdint>
#include <cstdio>
#include <iosfwd>
#include <limits>
#include <optional>

/**
 * Ensure file contents are fully committed to disk, using a platform-specific
 * feature analogous to fsync().
 */
bool FileCommit(FILE* file);

/**
 * Sync directory contents. This is required on some environments to ensure that
 * newly created files are committed to disk.
 */
void DirectoryCommit(const fs::path& dirname);

bool TruncateFile(FILE* file, unsigned int length);

/**
 * Try to raise the file descriptor limit to the requested number.
 *
 * @param[in] min_fd  The requested minimum number of file descriptors.
 * @returns           The actual file descriptor limit. It may be lower or
 *                    higher than min_fd. Returns std::numeric_limits<int>::max()
 *                    if the OS imposes no limit (RLIM_INFINITY).
 *
 */
int RaiseFileDescriptorLimit(int min_fd);

void AllocateFileRange(FILE* file, unsigned int offset, unsigned int length);

/**
 * Rename src to dest.
 * @return true if the rename was successful.
 */
[[nodiscard]] bool RenameOver(fs::path src, fs::path dest);

namespace util {
enum class LockResult {
    Success,
    ErrorWrite,
    ErrorLock,
};
[[nodiscard]] LockResult LockDirectory(const fs::path& directory, const fs::path& lockfile_name, bool probe_only = false);
} // namespace util
void UnlockDirectory(const fs::path& directory, const fs::path& lockfile_name);
bool CheckDiskSpace(const fs::path& dir, uint64_t additional_bytes = 0);

/** Get the size of a file by scanning it.
 *
 * @param[in] path The file path
 * @param[in] max Stop seeking beyond this limit
 * @return The file size or max
 */
std::streampos GetFileSize(const char* path, std::streamsize max = std::numeric_limits<std::streamsize>::max());

//! Return the original FILE* unchanged. On systems that support it,
//! also advise the OS that the file will be accessed sequentially.
FILE* AdviseSequential(FILE*);

//! Close a file and return the result of fclose(). On systems that
//! support it, advise the OS to remove the file contents from the page
//! cache (which can help on memory-constrained systems).
int CloseAndUncache(FILE*);

/** Release all directory locks. This is used for unit testing only, at runtime
 * the global destructor will take care of the locks.
 */
void ReleaseDirectoryLocks();

bool TryCreateDirectories(const fs::path& p);
fs::path GetDefaultDataDir();

/** Convert fs::perms to symbolic string of the form 'rwxrwxrwx'
 *
 * @param[in] p the perms to be converted
 * @return Symbolic permissions string
 */
std::string PermsToSymbolicString(fs::perms p);
/** Interpret a custom permissions level string as fs::perms
 *
 * @param[in] s Permission level string
 * @return Permissions as fs::perms
 */
std::optional<fs::perms> InterpretPermString(const std::string& s);

/** Check actual directory writability by creating and removing a temporary file. */
bool IsDirWritable(const fs::path& dir_path);

/** Determine whether a path is a symbolic link or, on Windows, a reparse point. */
bool IsSymlink(const fs::path& path);

#ifdef WIN32
fs::path GetSpecialFolderPath(int nFolder, bool fCreate = true);
#endif

#endif // BITCOIN_UTIL_FS_HELPERS_H
