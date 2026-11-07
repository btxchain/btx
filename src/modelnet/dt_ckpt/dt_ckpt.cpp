// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_ckpt/dt_ckpt.h>

#include <modelnet/dt_ckpt/codes.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_piecepipe/codes.h>
#include <modelnet/swarm_piecepipe/digest.h>
#include <modelnet/swarm_piecepipe/limits.h>
#include <modelnet/swarm_piecepipe/swarm_piecepipe.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace modelnet {
namespace {

static_assert(kSwarmPiecePipeBodyLimit == 33554432, "checkpoint body cap is 33554432 bytes");
static_assert(NIFDT_AUTOMATIC_SPEND[0] == '0' && NIFDT_AUTOMATIC_SPEND[1] == '\0', "spend stays 0");

constexpr char kFrameMagic[] = "BTXCKPT1";
constexpr std::size_t kFrameMagicLen = 8;

bool AddSize(std::size_t& total, std::size_t n)
{
    if (n > kSwarmPiecePipeBodyLimit || total > kSwarmPiecePipeBodyLimit - n) {
        return false;
    }
    total += n;
    return true;
}

void AppendU8(std::vector<unsigned char>& out, unsigned char v)
{
    out.push_back(v);
}

void AppendU32(std::vector<unsigned char>& out, std::uint32_t v)
{
    out.push_back(static_cast<unsigned char>(v));
    out.push_back(static_cast<unsigned char>(v >> 8));
    out.push_back(static_cast<unsigned char>(v >> 16));
    out.push_back(static_cast<unsigned char>(v >> 24));
}

void AppendU64(std::vector<unsigned char>& out, std::uint64_t v)
{
    for (int shift = 0; shift < 64; shift += 8) {
        out.push_back(static_cast<unsigned char>(v >> shift));
    }
}

void AppendBytes(std::vector<unsigned char>& out, const std::vector<unsigned char>& bytes)
{
    AppendU32(out, static_cast<std::uint32_t>(bytes.size()));
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void AppendString(std::vector<unsigned char>& out, const std::string& text)
{
    AppendU32(out, static_cast<std::uint32_t>(text.size()));
    out.insert(out.end(), text.begin(), text.end());
}

bool FitsU32(std::size_t n)
{
    return n <= std::numeric_limits<std::uint32_t>::max();
}

bool MomentsPresent(const DtCkpt::State& state)
{
    return !state.adam_m.empty() && !state.adam_v.empty();
}

bool FrameFits(const DtCkpt::State& state)
{
    if (!FitsU32(state.weights.size()) || !FitsU32(state.adam_m.size()) || !FitsU32(state.adam_v.size()) ||
        !FitsU32(state.recipe_id.size()) || !FitsU32(state.topology_id.size())) {
        return false;
    }
    std::size_t total = 0;
    if (!AddSize(total, kFrameMagicLen) || !AddSize(total, 1) || !AddSize(total, 8) || !AddSize(total, 8) ||
        !AddSize(total, 8) || !AddSize(total, 8)) {
        return false;
    }
    if (!AddSize(total, 4) || !AddSize(total, state.recipe_id.size())) return false;
    if (!AddSize(total, 4) || !AddSize(total, state.topology_id.size())) return false;
    if (!AddSize(total, 4) || !AddSize(total, state.weights.size())) return false;
    if (!AddSize(total, 4) || !AddSize(total, state.adam_m.size())) return false;
    if (!AddSize(total, 4) || !AddSize(total, state.adam_v.size())) return false;
    return true;
}

std::vector<unsigned char> Encode(const DtCkpt::State& state)
{
    std::vector<unsigned char> out;
    out.insert(out.end(), kFrameMagic, kFrameMagic + kFrameMagicLen);
    AppendU8(out, MomentsPresent(state) ? 1 : 0);
    AppendU64(out, state.step);
    AppendU64(out, state.rng);
    AppendU64(out, state.cursor);
    AppendU64(out, state.cohort_epoch);
    AppendString(out, state.recipe_id);
    AppendString(out, state.topology_id);
    AppendBytes(out, state.weights);
    AppendBytes(out, state.adam_m);
    AppendBytes(out, state.adam_v);
    return out;
}

bool ReadU8(const std::vector<unsigned char>& body, std::size_t& off, unsigned char& v)
{
    if (off >= body.size()) return false;
    v = body[off];
    ++off;
    return true;
}

bool ReadU32(const std::vector<unsigned char>& body, std::size_t& off, std::uint32_t& v)
{
    if (off > body.size() || body.size() - off < 4) return false;
    v = static_cast<std::uint32_t>(body[off]) |
        (static_cast<std::uint32_t>(body[off + 1]) << 8) |
        (static_cast<std::uint32_t>(body[off + 2]) << 16) |
        (static_cast<std::uint32_t>(body[off + 3]) << 24);
    off += 4;
    return true;
}

bool ReadU64(const std::vector<unsigned char>& body, std::size_t& off, std::uint64_t& v)
{
    if (off > body.size() || body.size() - off < 8) return false;
    v = 0;
    for (int shift = 0; shift < 64; shift += 8) {
        v |= static_cast<std::uint64_t>(body[off]) << shift;
        ++off;
    }
    return true;
}

bool ReadBytes(const std::vector<unsigned char>& body, std::size_t& off, std::uint32_t n, std::vector<unsigned char>& out)
{
    if (off > body.size() || body.size() - off < n) return false;
    out.assign(body.begin() + static_cast<std::ptrdiff_t>(off), body.begin() + static_cast<std::ptrdiff_t>(off + n));
    off += n;
    return true;
}

bool ReadString(const std::vector<unsigned char>& body, std::size_t& off, std::string& out)
{
    std::uint32_t n = 0;
    if (!ReadU32(body, off, n)) return false;
    std::vector<unsigned char> bytes;
    if (!ReadBytes(body, off, n, bytes)) return false;
    out.assign(bytes.begin(), bytes.end());
    return true;
}

bool ContainsBytes(const std::vector<unsigned char>& body, const unsigned char* pat, std::size_t n)
{
    if (n == 0 || body.size() < n) return false;
    return std::search(body.begin(), body.end(), pat, pat + n) != body.end();
}

bool ContainsAscii(const std::vector<unsigned char>& body, const char* marker)
{
    const std::size_t n = std::strlen(marker);
    return ContainsBytes(body, reinterpret_cast<const unsigned char*>(marker), n);
}

bool ContainsExecutable(const std::vector<unsigned char>& body)
{
    const unsigned char elf[] = {0x7f, 'E', 'L', 'F'};
    const unsigned char mz[] = {'M', 'Z'};
    const unsigned char shebang[] = {'#', '!'};
    const unsigned char wasm[] = {0x00, 'a', 's', 'm'};
    const unsigned char macho_be[] = {0xfe, 0xed, 0xfa, 0xce};
    const unsigned char macho_be64[] = {0xfe, 0xed, 0xfa, 0xcf};
    const unsigned char macho_le[] = {0xce, 0xfa, 0xed, 0xfe};
    const unsigned char macho_le64[] = {0xcf, 0xfa, 0xed, 0xfe};
    const unsigned char fat_be[] = {0xca, 0xfe, 0xba, 0xbe};
    const unsigned char fat_le[] = {0xbe, 0xba, 0xfe, 0xca};
    return ContainsBytes(body, elf, sizeof(elf)) || ContainsBytes(body, mz, sizeof(mz)) ||
           ContainsBytes(body, shebang, sizeof(shebang)) || ContainsBytes(body, wasm, sizeof(wasm)) ||
           ContainsBytes(body, macho_be, sizeof(macho_be)) || ContainsBytes(body, macho_be64, sizeof(macho_be64)) ||
           ContainsBytes(body, macho_le, sizeof(macho_le)) || ContainsBytes(body, macho_le64, sizeof(macho_le64)) ||
           ContainsBytes(body, fat_be, sizeof(fat_be)) || ContainsBytes(body, fat_le, sizeof(fat_le));
}

bool DecodeClosure(const std::vector<unsigned char>& body, DtCkpt::State& state)
{
    if (body.size() < kFrameMagicLen || std::memcmp(body.data(), kFrameMagic, kFrameMagicLen) != 0) {
        return false;
    }
    std::size_t off = kFrameMagicLen;
    unsigned char flag = 0;
    DtCkpt::State decoded;
    if (!ReadU8(body, off, flag) || (flag != 0 && flag != 1)) return false;
    if (!ReadU64(body, off, decoded.step)) return false;
    if (!ReadU64(body, off, decoded.rng)) return false;
    if (!ReadU64(body, off, decoded.cursor)) return false;
    if (!ReadU64(body, off, decoded.cohort_epoch)) return false;
    if (!ReadString(body, off, decoded.recipe_id)) return false;
    if (!ReadString(body, off, decoded.topology_id)) return false;
    std::uint32_t n = 0;
    if (!ReadU32(body, off, n) || !ReadBytes(body, off, n, decoded.weights)) return false;
    if (!ReadU32(body, off, n) || !ReadBytes(body, off, n, decoded.adam_m)) return false;
    if (!ReadU32(body, off, n) || !ReadBytes(body, off, n, decoded.adam_v)) return false;
    if (off != body.size()) return false;
    if (decoded.weights.empty()) return false;
    if ((flag == 1) != MomentsPresent(decoded)) return false;
    state = std::move(decoded);
    return true;
}

} // namespace

bool DtCkpt::Save(const State& state, std::string& err)
{
    if (state.weights.empty()) {
        err = kDtCkptWeights;
        return false;
    }
    if (!FrameFits(state)) {
        err = kSwarmPiecePipePieceLimit;
        return false;
    }
    const std::vector<unsigned char> body = Encode(state);
    if (body.size() > kSwarmPiecePipeBodyLimit) {
        err = kSwarmPiecePipePieceLimit;
        return false;
    }
    if (ContainsAscii(body, kDtCkptPickle)) {
        err = kDtCkptPickle;
        return false;
    }
    if (ContainsExecutable(body)) {
        err = kDtCkptCode;
        return false;
    }
    State roundtrip;
    if (!DecodeClosure(body, roundtrip) || !(roundtrip == state)) {
        err = kDtCkptManifest;
        return false;
    }
    const std::string id = SwarmPiecePipeDigest(body);
    if (!m_pipe.Split(body, err)) {
        return false;
    }
    if (id != m_artifact) {
        m_promoted = false;
    }
    m_saved = state;
    m_artifact = id;
    m_have = true;
    m_exact = MomentsPresent(state);
    m_hole = false;
    err.clear();
    return true;
}

bool DtCkpt::Resume(std::string& err)
{
    if (!m_have || m_hole) {
        err = kDtCkptManifest;
        return false;
    }
    if (!m_pipe.Resume(m_artifact, err) || !usable(m_artifact)) {
        err = kDtCkptManifest;
        return false;
    }
    err.clear();
    return true;
}

bool DtCkpt::Promote(std::string& err)
{
    if (!Resume(err)) {
        m_promoted = false;
        return false;
    }
    if (!m_exact) {
        err = kDtCkptPartial;
        m_promoted = false;
        return false;
    }
    m_promoted = true;
    err.clear();
    return true;
}

bool DtCkpt::Restore(std::string& err)
{
    if (!m_have || m_hole) {
        err = kDtCkptManifest;
        return false;
    }
    if (!m_exact) {
        err = kDtCkptPartial;
        return false;
    }
    if (!m_promoted) {
        err = kDtCkptManifest;
        return false;
    }
    if (!Resume(err)) {
        m_promoted = false;
        return false;
    }
    m_live.weights = m_saved.weights;
    m_live.adam_m = m_saved.adam_m;
    m_live.adam_v = m_saved.adam_v;
    m_live.step = m_saved.step;
    m_live.rng = m_saved.rng;
    m_live.cursor = m_saved.cursor;
    m_live.recipe_id = m_saved.recipe_id;
    m_live.topology_id = m_saved.topology_id;
    m_live.cohort_epoch = m_saved.cohort_epoch;
    err.clear();
    return true;
}

bool DtCkpt::Drop(const std::string& id, std::string& err)
{
    const bool required = required_slice(id);
    const bool dropped = m_pipe.Drop(id, err);
    if (required) {
        m_hole = true;
        m_promoted = false;
        err = kDtCkptManifest;
        return false;
    }
    return dropped;
}

std::vector<std::string> DtCkpt::slice_ids() const
{
    if (!m_have) {
        return {};
    }
    return m_pipe.SliceIds(m_artifact);
}

bool DtCkpt::has_piece(const std::string& id) const
{
    return m_pipe.HasPiece(id);
}

std::size_t DtCkpt::piece_count() const
{
    return m_pipe.PieceCount();
}

bool DtCkpt::usable(const std::string& artifact) const
{
    if (m_hole && artifact == m_artifact) {
        return false;
    }
    return m_pipe.usable(artifact);
}

bool DtCkpt::launched() const
{
    return m_pipe.launched();
}

bool DtCkpt::gpu() const
{
    return m_pipe.gpu();
}

bool DtCkpt::broadcast() const
{
    return m_pipe.broadcast();
}

std::string DtCkpt::automatic_spend() const
{
    return NIFDT_AUTOMATIC_SPEND;
}

std::int64_t DtCkpt::bytes_moved() const
{
    return m_pipe.bytes_moved();
}

bool DtCkpt::required_slice(const std::string& id) const
{
    if (!m_have || id.empty()) {
        return false;
    }
    const std::vector<std::string> ids = m_pipe.SliceIds(m_artifact);
    return std::find(ids.begin(), ids.end(), id) != ids.end();
}

} // namespace modelnet
