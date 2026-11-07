// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_VERIFY_H
#define BTX_MODELNET_SWARM_VERIFY_H

#include <util/fs.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Identity commitment only. Children are not verified by naming the root. */
enum class SwarmVerifyState { Discovered, Fetching, Incomplete, Verified, Admitted };

/**
 * Persistent piece gate. A checkpoint stays unusable until every required
 * child matches the canonical order, digest, and length and the lengths sum
 * to the committed total under the committed root. This book does not stream
 * a checkpoint. bytes_streamed stays false.
 */
class SwarmVerifyBook {
public:
    bool Discover(const std::string& root, int64_t total_length, const std::vector<std::string>& digests,
                  const std::vector<int64_t>& lengths, std::string& err);
    bool BeginFetch(std::string& err);
    /** Same order and same digest is idempotent. A different digest is DIGEST. */
    bool Submit(int order, const std::string& digest, int64_t length, std::string& err);
    bool NotePeerGone(std::string& err);
    /** root must equal the discovered root. Otherwise the state stays Incomplete. */
    bool Finish(const std::string& root, std::string& err);
    /** Only Verified becomes Admitted. Inference and training must call this. */
    bool Activate(std::string& err);
    SwarmVerifyState State() const { return m_state; }
    bool BytesStreamed() const { return false; }
    bool Persist(const fs::path& modeldir, std::string& err);
    bool Load(const fs::path& modeldir, std::string& err);

private:
    struct Piece {
        int order{0};
        std::string digest;
        int64_t length{0};
        bool present{false};
        int64_t got_length{0};
        std::string got_digest;
    };

    SwarmVerifyState m_state{SwarmVerifyState::Discovered};
    std::string m_root;
    int64_t m_total{0};
    std::vector<Piece> m_pieces;
    bool m_discovered{false};
};

const char* SwarmVerifyStateName(SwarmVerifyState state);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_VERIFY_H
