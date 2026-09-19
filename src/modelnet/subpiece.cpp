// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/subpiece.h>

#include <cstdlib>

namespace modelnet {

uint64_t PiecePayloadBytes(uint64_t file_size_bytes, uint32_t piece_index)
{
    const uint64_t start = static_cast<uint64_t>(piece_index) * PIECE_SIZE;
    if (start >= file_size_bytes) return 0;
    const uint64_t remain = file_size_bytes - start;
    return remain < PIECE_SIZE ? remain : PIECE_SIZE;
}

bool SubpieceRangesOverlap(uint64_t a_off, uint64_t a_len, uint64_t b_off, uint64_t b_len)
{
    if (a_len == 0 || b_len == 0) return false;
    const uint64_t a_end = a_off + a_len;
    const uint64_t b_end = b_off + b_len;
    return a_off < b_end && b_off < a_end;
}

bool ValidateSubpieceRequest(const SubpieceRequest& req, uint64_t file_size_bytes, std::string& err)
{
    if (req.length == 0) {
        err = "empty subpiece";
        return false;
    }
    if (req.length > SUBPIECE_SIZE) {
        err = "subpiece length";
        return false;
    }
    if (req.offset % SUBPIECE_SIZE != 0) {
        err = "subpiece offset unaligned";
        return false;
    }
    if (req.offset + req.length < req.offset) {
        err = "subpiece overflow";
        return false;
    }
    const uint64_t piece_bytes = PiecePayloadBytes(file_size_bytes, req.piece_index);
    if (piece_bytes == 0) {
        err = "piece out of file";
        return false;
    }
    if (req.offset >= piece_bytes || req.offset + req.length > piece_bytes) {
        err = "subpiece out of piece";
        return false;
    }
    return true;
}

bool ParseSubpieceRequest(const UniValue& json, SubpieceRequest& out, std::string& err)
{
    out = {};
    if (!json.isObject()) {
        err = "subpiece json";
        return false;
    }
    if (json.exists("artifact_id") && json["artifact_id"].isStr()) out.artifact_id = json["artifact_id"].get_str();
    if (json.exists("request_id") && json["request_id"].isStr()) out.request_id = json["request_id"].get_str();
    auto num = [&](const char* k, uint64_t& dst) {
        if (!json.exists(k)) return;
        if (json[k].isNum()) dst = json[k].getInt<uint64_t>();
        else if (json[k].isStr()) dst = std::strtoull(json[k].get_str().c_str(), nullptr, 10);
    };
    uint64_t file = 0, piece = 0, off = 0, len = 0;
    num("file_index", file);
    num("piece_index", piece);
    num("offset", off);
    num("length", len);
    out.file_index = static_cast<uint32_t>(file);
    out.piece_index = static_cast<uint32_t>(piece);
    out.offset = off;
    out.length = len;
    return true;
}

UniValue SubpieceRequestJson(const SubpieceRequest& req)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("capability", SUBPIECE_V1);
    o.pushKV("artifact_id", req.artifact_id);
    o.pushKV("file_index", static_cast<int>(req.file_index));
    o.pushKV("piece_index", static_cast<int>(req.piece_index));
    o.pushKV("offset", static_cast<int64_t>(req.offset));
    o.pushKV("length", static_cast<int64_t>(req.length));
    o.pushKV("request_id", req.request_id);
    return o;
}

bool SubpieceAssembly::Admit(const SubpieceRequest& req, uint64_t file_size_bytes, int peer_count, std::string& err)
{
    if (peer_count > m_peers_max) {
        err = "subpiece peer cap";
        return false;
    }
    if (static_cast<int>(m_accepted.size()) >= m_max) {
        err = "subpiece assembly cap";
        return false;
    }
    if (!ValidateSubpieceRequest(req, file_size_bytes, err)) return false;
    if (m_bytes + req.length < m_bytes || m_bytes + req.length > m_bytes_max) {
        err = "subpiece assembly bytes";
        return false;
    }
    for (const auto& prev : m_accepted) {
        if (prev.piece_index != req.piece_index) continue;
        if (SubpieceRangesOverlap(prev.offset, prev.length, req.offset, req.length)) {
            err = "subpiece overlap";
            return false;
        }
    }
    m_accepted.push_back(req);
    m_bytes += req.length;
    return true;
}

bool SubpieceAssembly::CompletePiece(uint32_t piece_index, uint64_t file_size_bytes) const
{
    const uint64_t need = PiecePayloadBytes(file_size_bytes, piece_index);
    if (need == 0) return false;
    uint64_t got = 0;
    for (const auto& r : m_accepted) {
        if (r.piece_index == piece_index) got += r.length;
    }
    return got == need;
}

bool AdvertiseFullPieceOnly()
{
    return true;
}

} // namespace modelnet
