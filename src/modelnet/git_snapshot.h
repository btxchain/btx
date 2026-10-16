// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GIT_SNAPSHOT_H
#define BITCOIN_MODELNET_GIT_SNAPSHOT_H

#include <modelnet/types.h>
#include <span.h>

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace modelnet {

/**
 * Lowercase hex SHA-384 of ASCII(kind) || ' ' || ASCII(decimal byte length) || 0x00 || content.
 * kind is blob, tree, commit, tag, research, train, lineage, model, piece, or replay. This is not a Git SHA-1 or SHA-256 object id.
 * A strong file identity is this digest plus SafeGitPath. No multi-file Merkle root is built here.
 */
bool GitObjectDigest(std::string_view kind, Span<const unsigned char> content, std::string& digest_hex, std::string& err);

/** True only for 96 lowercase hex characters. A 40-hex Git SHA-1 is rejected. */
bool IsStrongGitDigest(std::string_view hex);

/** Portable workspace path. On failure err is BTX035_PATH_UNSAFE. */
bool SafeGitPath(std::string_view path, std::string& err);

struct GitRefUpdate {
    std::string refname;
    uint64_t sequence{0};
    std::string record_id;
    std::string previous_update_id;
};

struct GitRefTip {
    uint64_t sequence{0};
    std::string record_id;
};

/**
 * Staged ref publication. AuthorizeAndStage accepts a non-empty batch.
 * Publish applies every staged update or none. AbandonStaged drops the batch
 * and leaves committed tips in place.
 *
 * JournalCommitment is D("BTX/035/Journal/v1", committed tips). It is not a file root.
 */
class RefJournal {
public:
    bool AuthorizeAndStage(const std::vector<GitRefUpdate>& updates, std::string& err);
    bool Publish(std::string& err);
    void AbandonStaged();

    bool HasStaged() const { return m_staged; }
    const std::map<std::string, GitRefTip>& Committed() const { return m_committed; }
    Digest48 JournalCommitment() const { return m_commitment; }

private:
    bool m_staged{false};
    std::vector<GitRefUpdate> m_pending;
    std::map<std::string, GitRefTip> m_committed;
    Digest48 m_commitment{};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_GIT_SNAPSHOT_H
