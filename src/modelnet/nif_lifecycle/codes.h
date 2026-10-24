// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_LIFECYCLE_CODES_H
#define BITCOIN_MODELNET_NIF_LIFECYCLE_CODES_H

namespace modelnet {

/** The attempt id is empty, or ReleaseChunk names an attempt that is not stored. Nothing new is stored. */
inline constexpr char kNifLifecycleAttempt[] = "ATTEMPT";

/** The journal file is missing or cannot be reconstructed. A missing file leaves that record empty. */
inline constexpr char kNifLifecycleJournal[] = "JOURNAL";

/** A historic receipt was offered as authority. Nothing is stored. */
inline constexpr char kNifLifecycleReceipt[] = "RECEIPT";

/** The journal path is a symlink. It is not followed. */
inline constexpr char kNifLifecycleSymlink[] = "SYMLINK";

/** The journal temp file was not written. */
inline constexpr char kNifLifecycleWrite[] = "WRITE";

/** The journal temp file was not renamed onto the record path. */
inline constexpr char kNifLifecycleRename[] = "RENAME";

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_LIFECYCLE_CODES_H
