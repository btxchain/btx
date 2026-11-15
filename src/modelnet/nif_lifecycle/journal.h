// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_LIFECYCLE_JOURNAL_H
#define BITCOIN_MODELNET_NIF_LIFECYCLE_JOURNAL_H

#include <modelnet/nifdt_contract/contract.h>

#include <util/fs.h>

#include <string>

namespace modelnet {

/** First line of a lifecycle journal file. */
inline constexpr char kNifLifecycleJournalMagic[] = "nif-lifecycle-v1";

/**
 * Path of the journal file for one attempt.
 * The filename is the hex encoding of the attempt plus ".nif", so the file
 * stays a single component under journal_dir.
 */
fs::path NifLifecycleJournalPath(const fs::path& journal_dir, const std::string& attempt);

/**
 * Write record to path by creating the parent directory, writing a temp file,
 * and renaming it onto path. A symlink at path or at the temp path is SYMLINK
 * and is not followed.
 */
bool NifLifecycleJournalWrite(const fs::path& path, const NifRequestRecord& record, std::string& err);

/**
 * Read path and reconstruct every NifRequestRecord field.
 * A symlink is SYMLINK and is not followed.
 * A missing or unreadable file is JOURNAL. record is left unchanged on failure.
 */
bool NifLifecycleJournalRead(const fs::path& path, NifRequestRecord& record, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_LIFECYCLE_JOURNAL_H
