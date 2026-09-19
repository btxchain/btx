// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SUBPIECE_H
#define BITCOIN_MODELNET_SUBPIECE_H

#include <modelnet/types.h>
#include <univalue.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

inline constexpr const char* SUBPIECE_V1 = "SUBPIECE_V1";
inline constexpr uint64_t SUBPIECE_SIZE = 256ull * 1024;
inline constexpr int SUBPIECE_ASSEMBLY_MAX = 16;
inline constexpr uint64_t SUBPIECE_ASSEMBLY_BYTES_MAX = 256ull * MIB;
inline constexpr int SUBPIECE_PEERS_MAX = 4;
inline constexpr int SUBPIECE_ENDGAME_PEERS = 2;

struct SubpieceRequest {
    std::string artifact_id;
    uint32_t file_index{0};
    uint32_t piece_index{0};
    uint64_t offset{0};
    uint64_t length{0};
    std::string request_id;
};

uint64_t PiecePayloadBytes(uint64_t file_size_bytes, uint32_t piece_index);
bool SubpieceRangesOverlap(uint64_t a_off, uint64_t a_len, uint64_t b_off, uint64_t b_len);
bool ValidateSubpieceRequest(const SubpieceRequest& req, uint64_t file_size_bytes, std::string& err);
bool ParseSubpieceRequest(const UniValue& json, SubpieceRequest& out, std::string& err);
UniValue SubpieceRequestJson(const SubpieceRequest& req);

class SubpieceAssembly {
    int m_max{SUBPIECE_ASSEMBLY_MAX};
    uint64_t m_bytes_max{SUBPIECE_ASSEMBLY_BYTES_MAX};
    int m_peers_max{SUBPIECE_PEERS_MAX};
    uint64_t m_bytes{0};
    std::vector<SubpieceRequest> m_accepted;

public:
    bool Admit(const SubpieceRequest& req, uint64_t file_size_bytes, int peer_count, std::string& err);
    size_t Accepted() const { return m_accepted.size(); }
    uint64_t Bytes() const { return m_bytes; }
    bool CompletePiece(uint32_t piece_index, uint64_t file_size_bytes) const;
};

/** True only for a fully assembled canonical piece. Subpieces are never advertised. */
bool AdvertiseFullPieceOnly();

} // namespace modelnet

#endif // BITCOIN_MODELNET_SUBPIECE_H
