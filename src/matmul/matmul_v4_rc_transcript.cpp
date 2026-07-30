// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_transcript.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <span.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <memory>
#include <utility>

namespace matmul::v4::rc {
namespace {

uint256 Sha256dBytes(const unsigned char* data, size_t len)
{
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(data, len).Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    return uint256{Span<const unsigned char>{d2, sizeof(d2)}};
}

uint256 HashNode(const uint256& left, const uint256& right)
{
    unsigned char buf[1 + 64];
    buf[0] = kRCNodeTag;
    std::memcpy(buf + 1, left.data(), 32);
    std::memcpy(buf + 1 + 32, right.data(), 32);
    return Sha256dBytes(buf, sizeof(buf));
}

uint256 HashLeafBytes(uint32_t t_leaf, const unsigned char* leaf_bytes)
{
    std::vector<unsigned char> pre;
    pre.reserve(1 + t_leaf);
    pre.push_back(kRCLeafTag);
    pre.insert(pre.end(), leaf_bytes, leaf_bytes + t_leaf);
    return Sha256dBytes(pre.data(), pre.size());
}

size_t NextPow2(size_t n)
{
    size_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

/** Shared sink engine: V1 flat tile absorb or V2 typed subroots. */
class SinkEngine {
public:
    SinkEngine(uint32_t t_leaf, uint8_t version, bool retain_leaves, bool retain_pages)
        : m_t_leaf(t_leaf), m_version(version), m_retain_leaves(retain_leaves),
          m_retain_pages(retain_pages)
    {
        assert(t_leaf > 0);
        assert(version == kRCTranscriptVersionV1 || version == kRCTranscriptVersionV2);
        m_partial.reserve(t_leaf);
    }

    void BeginRound(uint32_t r)
    {
        assert(!m_in_round);
        m_in_round = true;
        m_finalized = false;
        m_round = r;
        m_phase = 0;
        m_layer = 0;
        m_in_phase = false;
        m_in_layer = false;
        m_bytes_absorbed = 0;
        m_partial.clear();
        m_frontier.Reset();
        m_leaves.clear();
        m_pages.clear();
        m_seg_commits.clear();
        m_phase1_root.SetNull();
        m_layer_roots.clear();
        m_have_phase1 = false;
        m_peak_ws = SoftWsNow();
    }

    void BeginPhase(uint32_t phase)
    {
        assert(m_in_round && !m_finalized);
        assert(!m_in_phase && !m_in_layer);
        m_in_phase = true;
        m_phase = phase;
        if (m_version == kRCTranscriptVersionV2) {
            m_seg_commits.clear();
        }
    }

    void BeginLayer(uint32_t layer)
    {
        assert(m_in_round && !m_finalized);
        assert(!m_in_layer);
        // Layers live under phase 2 in the typed model; V1 ignores structure.
        m_in_layer = true;
        m_layer = layer;
        if (m_version == kRCTranscriptVersionV2) {
            m_seg_commits.clear();
        }
    }

    void SubmitSegment(RCSegType type, uint32_t layer, uint32_t seg_id,
                       Span<const unsigned char> canonical_bytes)
    {
        assert(m_in_round && !m_finalized);
        if (m_version == kRCTranscriptVersionV1) {
            AbsorbFlat(canonical_bytes);
            return;
        }
        SubmitTyped(type, layer, seg_id, canonical_bytes);
    }

    void SubmitExtractedTensor(RCSegType type, uint32_t layer, Span<const int8_t> tensor)
    {
        assert(m_in_round && !m_finalized);
        const auto bytes = Span<const unsigned char>{
            reinterpret_cast<const unsigned char*>(tensor.data()), tensor.size()};
        if (m_version == kRCTranscriptVersionV1) {
            AbsorbFlat(bytes);
            return;
        }
        // Extracted tensors use seg_id = 0 (single full tensor).
        SubmitTyped(type, layer, /*seg_id=*/0, bytes);
    }

    void EndLayer()
    {
        assert(m_in_round && !m_finalized && m_in_layer);
        if (m_version == kRCTranscriptVersionV2) {
            const uint256 root =
                FinalizeSubroot(kRCLayerCommitV2Tag, sizeof(kRCLayerCommitV2Tag) - 1,
                                Span<const uint256>{m_seg_commits.data(), m_seg_commits.size()});
            m_layer_roots.push_back(root);
            m_seg_commits.clear();
        }
        m_in_layer = false;
    }

    void EndPhase()
    {
        assert(m_in_round && !m_finalized && m_in_phase && !m_in_layer);
        if (m_version == kRCTranscriptVersionV2) {
            const uint256 root =
                FinalizeSubroot(kRCPhaseCommitV2Tag, sizeof(kRCPhaseCommitV2Tag) - 1,
                                Span<const uint256>{m_seg_commits.data(), m_seg_commits.size()});
            if (m_phase == 1) {
                m_phase1_root = root;
                m_have_phase1 = true;
            }
            m_seg_commits.clear();
        }
        m_in_phase = false;
    }

    uint256 EndRound()
    {
        assert(m_in_round && !m_finalized);
        assert(!m_in_phase && !m_in_layer);
        m_finalized = true;
        m_in_round = false;
        if (m_version == kRCTranscriptVersionV1) {
            return FinalizeFlatRound();
        }
        return FinalizeTypedRound();
    }

    uint8_t Version() const { return m_version; }
    size_t BytesAbsorbed() const { return m_bytes_absorbed; }
    size_t SoftWorkingSetBytes() const { return m_peak_ws; }
    const std::vector<uint256>& Leaves() const { return m_leaves; }
    const std::vector<std::vector<unsigned char>>& Pages() const { return m_pages; }

private:
    uint32_t m_t_leaf{0};
    uint8_t m_version{kRCTranscriptVersionV1};
    bool m_retain_leaves{false};
    bool m_retain_pages{false};

    bool m_in_round{false};
    bool m_finalized{false};
    uint32_t m_round{0};
    uint32_t m_phase{0};
    uint32_t m_layer{0};
    bool m_in_phase{false};
    bool m_in_layer{false};

    std::vector<unsigned char> m_partial;
    RCMerkleFrontier m_frontier;
    size_t m_bytes_absorbed{0};
    size_t m_peak_ws{0};

    std::vector<uint256> m_leaves;
    std::vector<std::vector<unsigned char>> m_pages;

    std::vector<uint256> m_seg_commits;
    uint256 m_phase1_root{};
    std::vector<uint256> m_layer_roots;
    bool m_have_phase1{false};

    size_t SoftWsNow() const
    {
        size_t n = m_partial.capacity() + m_frontier.FrontierSlots() * 32;
        n += m_seg_commits.capacity() * 32;
        n += m_layer_roots.capacity() * 32;
        if (m_retain_leaves) n += m_leaves.capacity() * 32;
        if (m_retain_pages) {
            for (const auto& p : m_pages) n += p.capacity();
            n += m_pages.capacity() * sizeof(std::vector<unsigned char>);
        }
        return n;
    }

    void NoteWs()
    {
        m_peak_ws = std::max(m_peak_ws, SoftWsNow());
    }

    void OnLeaf(const uint256& leaf_hash, const unsigned char* leaf_bytes)
    {
        m_frontier.AppendLeaf(leaf_hash);
        if (m_retain_leaves) m_leaves.push_back(leaf_hash);
        if (m_retain_pages && leaf_bytes != nullptr) {
            m_pages.emplace_back(leaf_bytes, leaf_bytes + m_t_leaf);
        }
        NoteWs();
    }

    void EmitFlatLeaf(const unsigned char* leaf_bytes)
    {
        OnLeaf(HashLeafBytes(m_t_leaf, leaf_bytes), leaf_bytes);
    }

    void AbsorbFlat(Span<const unsigned char> bytes)
    {
        if (bytes.empty()) {
            NoteWs();
            return;
        }
        m_bytes_absorbed += bytes.size();
        size_t off = 0;
        while (off < bytes.size()) {
            const size_t space = static_cast<size_t>(m_t_leaf) - m_partial.size();
            const size_t n = std::min(space, bytes.size() - off);
            m_partial.insert(m_partial.end(), bytes.data() + off, bytes.data() + off + n);
            off += n;
            if (m_partial.size() == m_t_leaf) {
                EmitFlatLeaf(m_partial.data());
                m_partial.clear();
            }
        }
        NoteWs();
    }

    uint256 TileRootOf(Span<const unsigned char> bytes) const
    {
        RCMerkleFrontier fr;
        std::vector<unsigned char> partial;
        partial.reserve(m_t_leaf);
        size_t absorbed = 0;
        size_t off = 0;
        while (off < bytes.size()) {
            const size_t space = static_cast<size_t>(m_t_leaf) - partial.size();
            const size_t n = std::min(space, bytes.size() - off);
            partial.insert(partial.end(), bytes.data() + off, bytes.data() + off + n);
            off += n;
            absorbed += n;
            if (partial.size() == m_t_leaf) {
                fr.AppendLeaf(HashLeafBytes(m_t_leaf, partial.data()));
                partial.clear();
            }
        }
        if (absorbed == 0 && fr.LeafCount() == 0) {
            std::vector<unsigned char> leaf(m_t_leaf, 0);
            fr.AppendLeaf(HashLeafBytes(m_t_leaf, leaf.data()));
        } else if (!partial.empty()) {
            partial.resize(m_t_leaf, 0);
            fr.AppendLeaf(HashLeafBytes(m_t_leaf, partial.data()));
        }
        return fr.FinalizeRoot(RCTranscriptPadLeafHash());
    }

    uint256 MakeSegCommit(RCSegType type, uint32_t layer, uint32_t seg_id,
                          Span<const unsigned char> bytes) const
    {
        const uint256 content = TileRootOf(bytes);
        std::vector<unsigned char> pre;
        pre.reserve(sizeof(kRCSegCommitV2Tag) - 1 + 4 + 4 + 4 + 32);
        pre.insert(pre.end(), reinterpret_cast<const unsigned char*>(kRCSegCommitV2Tag),
                   reinterpret_cast<const unsigned char*>(kRCSegCommitV2Tag) +
                       sizeof(kRCSegCommitV2Tag) - 1);
        unsigned char le[4];
        WriteLE32(le, static_cast<uint32_t>(type));
        pre.insert(pre.end(), le, le + 4);
        WriteLE32(le, layer);
        pre.insert(pre.end(), le, le + 4);
        WriteLE32(le, seg_id);
        pre.insert(pre.end(), le, le + 4);
        pre.insert(pre.end(), content.begin(), content.end());
        return Sha256dBytes(pre.data(), pre.size());
    }

    void SubmitTyped(RCSegType type, uint32_t layer, uint32_t seg_id,
                     Span<const unsigned char> bytes)
    {
        m_bytes_absorbed += bytes.size();
        const uint256 commit = MakeSegCommit(type, layer, seg_id, bytes);
        m_seg_commits.push_back(commit);
        if (m_retain_leaves) m_leaves.push_back(commit);
        if (m_retain_pages) {
            m_pages.emplace_back(bytes.begin(), bytes.end());
        }
        NoteWs();
    }

    uint256 FinalizeSubroot(const char* wrap_tag, size_t taglen,
                            Span<const uint256> commits) const
    {
        RCMerkleFrontier fr;
        if (commits.empty()) {
            // Empty phase/layer: one domain-separated empty commit.
            std::vector<unsigned char> pre;
            pre.insert(pre.end(), reinterpret_cast<const unsigned char*>(wrap_tag),
                       reinterpret_cast<const unsigned char*>(wrap_tag) + taglen);
            fr.AppendLeaf(Sha256dBytes(pre.data(), pre.size()));
        } else {
            for (const uint256& c : commits) fr.AppendLeaf(c);
        }
        const uint256 raw = fr.FinalizeRoot(RCTranscriptPadLeafHash());
        std::vector<unsigned char> wrap;
        wrap.reserve(taglen + 32);
        wrap.insert(wrap.end(), reinterpret_cast<const unsigned char*>(wrap_tag),
                    reinterpret_cast<const unsigned char*>(wrap_tag) + taglen);
        wrap.insert(wrap.end(), raw.begin(), raw.end());
        return Sha256dBytes(wrap.data(), wrap.size());
    }

    uint256 FinalizeFlatRound()
    {
        // Match RoundMerkleStream: empty stream still emits one zero leaf.
        if (m_bytes_absorbed == 0 && m_frontier.LeafCount() == 0) {
            std::vector<unsigned char> leaf(m_t_leaf, 0);
            EmitFlatLeaf(leaf.data());
        } else if (!m_partial.empty()) {
            m_partial.resize(m_t_leaf, 0);
            EmitFlatLeaf(m_partial.data());
            m_partial.clear();
        }
        return m_frontier.FinalizeRoot(RCTranscriptPadLeafHash());
    }

    uint256 FinalizeTypedRound()
    {
        assert(m_have_phase1);
        std::vector<unsigned char> buf;
        buf.reserve(sizeof(kRCRoundRootV2Tag) - 1 + 32 + m_layer_roots.size() * 32);
        buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCRoundRootV2Tag),
                   reinterpret_cast<const unsigned char*>(kRCRoundRootV2Tag) +
                       sizeof(kRCRoundRootV2Tag) - 1);
        buf.insert(buf.end(), m_phase1_root.begin(), m_phase1_root.end());
        for (const uint256& lr : m_layer_roots) {
            buf.insert(buf.end(), lr.begin(), lr.end());
        }
        return Sha256dBytes(buf.data(), buf.size());
    }
};

} // namespace

RCEpisodeOptions OptionsForExecMode(RCExecMode mode, uint32_t phase1_tile_delta)
{
    RCEpisodeOptions o;
    o.phase1_tile_delta = phase1_tile_delta;
    switch (mode) {
    case RCExecMode::Resident:
        o.checkpoint = RCEpisodeOptions::Checkpoint::StoreAll;
        break;
    case RCExecMode::Checkpointed:
        o.checkpoint = RCEpisodeOptions::Checkpoint::StoreEvery4;
        break;
    case RCExecMode::Streamed:
        o.checkpoint = RCEpisodeOptions::Checkpoint::StoreOnlyX0;
        break;
    }
    return o;
}

void RCMerkleFrontier::Reset()
{
    m_frontier.clear();
    m_leaf_count = 0;
}

void RCMerkleFrontier::AppendLeaf(const uint256& leaf_hash)
{
    uint256 h = leaf_hash;
    size_t i = 0;
    while (true) {
        if (i == m_frontier.size()) {
            m_frontier.emplace_back(std::nullopt);
        }
        if (!m_frontier[i].has_value()) {
            m_frontier[i] = h;
            break;
        }
        h = HashNode(*m_frontier[i], h);
        m_frontier[i] = std::nullopt;
        ++i;
    }
    ++m_leaf_count;
}

uint256 RCMerkleFrontier::FinalizeRoot(const uint256& pad_leaf)
{
    const size_t target = NextPow2(m_leaf_count == 0 ? 1 : m_leaf_count);
    while (m_leaf_count < target) {
        AppendLeaf(pad_leaf);
    }
    // After padding to pow2, exactly one occupied slot remains (the root).
    uint256 root;
    bool found = false;
    for (const auto& slot : m_frontier) {
        if (slot.has_value()) {
            assert(!found);
            root = *slot;
            found = true;
        }
    }
    assert(found);
    return root;
}

size_t RCMerkleFrontier::FrontierSlots() const
{
    return m_frontier.size();
}

uint256 RCTranscriptPadLeafHash()
{
    std::vector<unsigned char> pre;
    pre.push_back(kRCPadLeafTag);
    pre.insert(pre.end(), reinterpret_cast<const unsigned char*>(kRCPadTag),
               reinterpret_cast<const unsigned char*>(kRCPadTag) + sizeof(kRCPadTag) - 1);
    return Sha256dBytes(pre.data(), pre.size());
}

uint256 RCTranscriptFoldRoot(std::vector<uint256> level)
{
    assert(!level.empty());
    while (level.size() > 1) {
        std::vector<uint256> parent;
        parent.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            parent.push_back(HashNode(level[i], level[i + 1]));
        }
        level.swap(parent);
    }
    return level.front();
}

uint256 RCTranscriptMaterializedFlatRoot(Span<const int8_t> stream, uint32_t t_leaf)
{
    return BuildTileTreeRoot(std::vector<int8_t>(stream.begin(), stream.end()), t_leaf);
}

// --- RCStreamingSink --------------------------------------------------------

struct RCStreamingSink::Impl {
    SinkEngine eng;
    explicit Impl(uint32_t t_leaf, uint8_t version)
        : eng(t_leaf, version, /*retain_leaves=*/false, /*retain_pages=*/false)
    {
    }
};

RCStreamingSink::RCStreamingSink(uint32_t t_leaf, uint8_t version)
    : m_t_leaf(t_leaf), m_version(version), m_impl(std::make_unique<Impl>(t_leaf, version))
{
}

RCStreamingSink::~RCStreamingSink() = default;
RCStreamingSink::RCStreamingSink(RCStreamingSink&&) noexcept = default;
RCStreamingSink& RCStreamingSink::operator=(RCStreamingSink&&) noexcept = default;

void RCStreamingSink::BeginRound(uint32_t r) { m_impl->eng.BeginRound(r); }
void RCStreamingSink::BeginPhase(uint32_t phase) { m_impl->eng.BeginPhase(phase); }
void RCStreamingSink::BeginLayer(uint32_t layer) { m_impl->eng.BeginLayer(layer); }
void RCStreamingSink::SubmitSegment(RCSegType type, uint32_t layer, uint32_t seg_id,
                                    Span<const unsigned char> canonical_bytes)
{
    m_impl->eng.SubmitSegment(type, layer, seg_id, canonical_bytes);
}
void RCStreamingSink::SubmitExtractedTensor(RCSegType type, uint32_t layer,
                                            Span<const int8_t> tensor)
{
    m_impl->eng.SubmitExtractedTensor(type, layer, tensor);
}
void RCStreamingSink::EndLayer() { m_impl->eng.EndLayer(); }
void RCStreamingSink::EndPhase() { m_impl->eng.EndPhase(); }
uint256 RCStreamingSink::EndRound() { return m_impl->eng.EndRound(); }
uint8_t RCStreamingSink::Version() const { return m_impl->eng.Version(); }
size_t RCStreamingSink::BytesAbsorbed() const { return m_impl->eng.BytesAbsorbed(); }
size_t RCStreamingSink::SoftWorkingSetBytes() const
{
    return m_impl->eng.SoftWorkingSetBytes();
}

// --- RCResidentSink ---------------------------------------------------------

struct RCResidentSink::Impl {
    SinkEngine eng;
    explicit Impl(uint32_t t_leaf, uint8_t version, bool retain_pages)
        : eng(t_leaf, version, /*retain_leaves=*/true, retain_pages)
    {
    }
};

RCResidentSink::RCResidentSink(uint32_t t_leaf, uint8_t version, bool retain_pages)
    : m_impl(std::make_unique<Impl>(t_leaf, version, retain_pages))
{
}

RCResidentSink::~RCResidentSink() = default;
RCResidentSink::RCResidentSink(RCResidentSink&&) noexcept = default;
RCResidentSink& RCResidentSink::operator=(RCResidentSink&&) noexcept = default;

void RCResidentSink::BeginRound(uint32_t r) { m_impl->eng.BeginRound(r); }
void RCResidentSink::BeginPhase(uint32_t phase) { m_impl->eng.BeginPhase(phase); }
void RCResidentSink::BeginLayer(uint32_t layer) { m_impl->eng.BeginLayer(layer); }
void RCResidentSink::SubmitSegment(RCSegType type, uint32_t layer, uint32_t seg_id,
                                   Span<const unsigned char> canonical_bytes)
{
    m_impl->eng.SubmitSegment(type, layer, seg_id, canonical_bytes);
}
void RCResidentSink::SubmitExtractedTensor(RCSegType type, uint32_t layer,
                                           Span<const int8_t> tensor)
{
    m_impl->eng.SubmitExtractedTensor(type, layer, tensor);
}
void RCResidentSink::EndLayer() { m_impl->eng.EndLayer(); }
void RCResidentSink::EndPhase() { m_impl->eng.EndPhase(); }
uint256 RCResidentSink::EndRound() { return m_impl->eng.EndRound(); }
uint8_t RCResidentSink::Version() const { return m_impl->eng.Version(); }
const std::vector<uint256>& RCResidentSink::Leaves() const { return m_impl->eng.Leaves(); }
const std::vector<std::vector<unsigned char>>& RCResidentSink::Pages() const
{
    return m_impl->eng.Pages();
}

} // namespace matmul::v4::rc
