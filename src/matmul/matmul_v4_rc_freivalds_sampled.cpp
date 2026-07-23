// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_freivalds_sampled.h>

#include <crypto/common.h>                 // WriteLE32
#include <matmul/matmul_v4.h>              // matmul::v4::DeriveSigma
#include <matmul/matmul_v4_rc.h>           // BuildTileTreeLeaves / Open/VerifyMerkleProof
#include <matmul/matmul_v4_rc_freivalds.h> // FreivaldsCheckGemm (frozen Fable primitive)
#include <matmul/matmul_v4_rc_fri_ext3.h>  // Sha256dBytes
#include <matmul/matmul_v4_rc_gkr_air.h>   // gkr_air Extract tile re-exec

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <list>
#include <map>
#include <mutex>
#include <unordered_map>

namespace matmul::v4::rc {

namespace {

double Secs(std::chrono::steady_clock::time_point s)
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - s).count();
}

// A layer's extract_out is committed to the round tile-tree stream iff it is one
// of SV / Fwd(down). QKt's S and the fused-FFN UP wire's H are NOT streamed (both
// are recomputed by the verifier from anchored inputs — see header).
bool LayerInStream(RCGkrLayerKind k)
{
    return k == RCGkrLayerKind::GemmPhase1SV || k == RCGkrLayerKind::GemmPhase2Fwd;
}

// Byte offset of a layer's extract_out within its round stream. MUST match the
// RCGkrReconstructRoundStream layout: Z ‖ for l: (Down_l). Fused FFN commits ONE
// output per layer (the DOWN projection X[l+1] = b_seq×d_model); the UP wire's H
// is internal and never streamed.
uint64_t LayerStreamOffset(const RCEpisodeParams& p, RCGkrLayerKind kind, uint32_t layer)
{
    const uint64_t z = static_cast<uint64_t>(p.n_q) * p.d_head;
    const uint64_t per_l = static_cast<uint64_t>(p.b_seq) * p.d_model; // one DOWN output / layer
    switch (kind) {
    case RCGkrLayerKind::GemmPhase1SV:
        return 0;
    case RCGkrLayerKind::GemmPhase2Fwd:
        return z + static_cast<uint64_t>(layer) * per_l;
    default:
        return 0; // QKt / FfnUp: not in stream (never sampled as a stream unit)
    }
}

// SHA256d(kRCLeafTag ‖ bytes) — byte-identical to RoundMerkleStream::EmitLeaf.
uint256 LeafHashFromBytes(const std::vector<uint8_t>& leaf_bytes)
{
    std::vector<unsigned char> pre;
    pre.reserve(1 + leaf_bytes.size());
    pre.push_back(kRCLeafTag);
    pre.insert(pre.end(), leaf_bytes.begin(), leaf_bytes.end());
    return Sha256dBytes(pre.data(), pre.size());
}

std::vector<int8_t> TransposeI8Local(const std::vector<int8_t>& src, uint32_t rows, uint32_t cols)
{
    std::vector<int8_t> out(static_cast<size_t>(rows) * cols);
    for (uint32_t i = 0; i < rows; ++i)
        for (uint32_t j = 0; j < cols; ++j)
            out[static_cast<size_t>(j) * rows + i] = src[static_cast<size_t>(i) * cols + j];
    return out;
}

// The sampleable-unit list: Λ layer indices whose extract_out is streamed.
// Identical on prover and verifier — derived from the public wiring only.
std::vector<uint32_t> SampleableUnits(const std::vector<RCGkrSampledLayerProv>& prov)
{
    std::vector<uint32_t> units;
    for (uint32_t i = 0; i < prov.size(); ++i)
        if (LayerInStream(prov[i].kind)) units.push_back(i);
    return units;
}

// Common trivial/target/digest/round-seed gates + base_seed derivation. Mirrors
// VerifyWinnerProofV7Compact's cheap gate block (reasons prefixed "v7fs:").
bool CheckGatesAndSeed(uint32_t version, const RCEpisodeParams& episode, int32_t proof_height,
                       const uint256& claimed_digest, const uint256& pow_bind,
                       const uint256& episode_sigma, const std::vector<uint256>& round_roots,
                       const std::vector<uint256>& round_seeds, const CBlockHeader& header,
                       int32_t height, const arith_uint256& target, uint256& base_seed,
                       std::string& why)
{
    if (version != kRCGkrProofVersionV7) { why = "v7fs:version"; return false; }
    if (!ValidateRCEpisodeParams(episode)) { why = "v7fs:params_invalid"; return false; }
    if (proof_height != height) { why = "v7fs:height"; return false; }
    if (pow_bind != RCGkrDerivePowBind(claimed_digest)) { why = "v7fs:pow_bind"; return false; }
    if (claimed_digest != header.matmul_digest) { why = "v7fs:digest_not_header_bound"; return false; }
    if (episode_sigma != matmul::v4::DeriveSigma(header)) { why = "v7fs:sigma"; return false; }
    if (round_roots.size() != episode.rounds) { why = "v7fs:round_roots_size"; return false; }
    const uint256 digest = RCGkrEpisodeDigestFromRoots(round_roots);
    if (digest != claimed_digest) { why = "v7fs:digest_from_roots"; return false; }
    if (UintToArith256(digest) > target) { why = "v7fs:target"; return false; }
    for (uint32_t r = 0; r < episode.rounds; ++r) {
        const uint256 expect =
            (r == 0) ? RCGkrRoundSeed(episode_sigma, 0) : RCGkrRoundSeed(round_roots[r - 1], r);
        if (r >= round_seeds.size() || expect != round_seeds[r]) { why = "v7fs:round_seeds"; return false; }
    }
    base_seed = RCGkrFsSeedV7(header, height, episode, target, claimed_digest, episode_sigma,
                              round_roots);
    return true;
}

// Per-sampled-layer core: (b) Freivalds A·B=Y, (c) extract_in==Y(+A) and the
// native Extract sampler re-exec extract_in→extract_out. Shared by both modes.
bool CheckLayerFreivaldsExtract(RCGkrLayerKind kind, uint32_t m, uint32_t k, uint32_t n,
                                const std::vector<int8_t>& A, const std::vector<int8_t>& B,
                                const std::vector<int64_t>& Y,
                                const std::vector<int64_t>& extract_in,
                                const std::vector<int8_t>& extract_out,
                                const uint256& extract_prf,
                                const std::vector<int8_t>& residual,
                                const uint256& base_seed, uint32_t layer_index,
                                uint64_t& n_extract_tiles, std::string& why)
{
    (void)kind;
    const size_t mk = static_cast<size_t>(m) * k;
    const size_t kn = static_cast<size_t>(k) * n;
    const size_t mn = static_cast<size_t>(m) * n;
    if (A.size() != mk || B.size() != kn || Y.size() != mn || extract_in.size() != mn ||
        extract_out.size() != mn) {
        why = "v7fs:wire_shape";
        return false;
    }
    // (b) GEMM correctness by Freivalds random projection (O(mk+kn+mn)).
    const uint256 seed = FreivaldsLayerChallengeSeed(base_seed, layer_index);
    std::string fw;
    if (!FreivaldsCheckGemm(A, B, Y, m, k, n, seed, kRCFreivaldsReps, &fw)) {
        why = "v7fs:freivalds:" + fw;
        return false;
    }
    // (c) accumulator/residual relation: extract_in == Y (+ residual). For the
    // fused DOWN layer the residual is X[l] (the layer input, shaped m×n), NOT the
    // A=H operand; empty for the non-residual kinds.
    if (!residual.empty() && residual.size() != mn) { why = "v7fs:residual_shape"; return false; }
    for (size_t idx = 0; idx < mn; ++idx) {
        int64_t expect = Y[idx];
        if (!residual.empty()) expect += static_cast<int64_t>(residual[idx]);
        if (extract_in[idx] != expect) { why = "v7fs:extract_in:binding"; return false; }
    }
    // (c) Extract sampler glue, re-executed natively for THIS layer's tiles.
    if (n % kRCMxBlockLen != 0) { why = "v7fs:extract:n_block"; return false; }
    gkr_air::TableTM tm;
    gkr_air::TableTX tx;
    const uint32_t n_blocks = n / kRCMxBlockLen;
    for (uint32_t i = 0; i < m; ++i) {
        for (uint32_t bj = 0; bj < n_blocks; ++bj) {
            gkr_air::TilePublic pub;
            pub.prf_key = extract_prf;
            pub.i = i;
            pub.bj = bj;
            std::array<int64_t, kRCMxBlockLen> in{};
            const size_t off = static_cast<size_t>(i) * n + static_cast<size_t>(bj) * kRCMxBlockLen;
            for (uint32_t t = 0; t < kRCMxBlockLen; ++t) in[t] = extract_in[off + t];
            const gkr_air::TileWitness tw = gkr_air::TraceTile(pub, in);
            const gkr_air::TileCheckResult cr = gkr_air::CheckTileConstraints(tw, tm, tx);
            if (!cr.ok) { why = "v7fs:extract_air:" + cr.failure; return false; }
            for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
                if (tw.out[t] != extract_out[off + t]) { why = "v7fs:extract_air:out_binding"; return false; }
            }
            ++n_extract_tiles;
        }
    }
    return true;
}

// Covering leaf window [leaf*T_leaf, +T_leaf) of `stream`, zero-padded at tail.
std::vector<uint8_t> LeafWindow(const std::vector<int8_t>& stream, uint32_t t_leaf, uint32_t leaf)
{
    std::vector<uint8_t> w(t_leaf, 0);
    const size_t start = static_cast<size_t>(leaf) * t_leaf;
    for (uint32_t b = 0; b < t_leaf; ++b) {
        const size_t s = start + b;
        if (s < stream.size()) w[b] = static_cast<uint8_t>(stream[s]);
    }
    return w;
}

// Verify a single covering leaf: its bytes hash + Merkle path reproduce
// round_root, AND its overlap with extract_out[stream_offset .. +len) matches.
bool CheckCoveringLeaf(const std::vector<uint8_t>& leaf_bytes, uint32_t leaf_index,
                       const RCMerkleProof& mproof, const uint256& round_root, uint32_t t_leaf,
                       uint64_t stream_offset, const std::vector<int8_t>& extract_out,
                       std::string& why)
{
    if (leaf_bytes.size() != t_leaf) { why = "v7fs:tiletree:leaf_size"; return false; }
    const uint256 leaf_hash = LeafHashFromBytes(leaf_bytes);
    if (!VerifyMerkleProof(leaf_hash, leaf_index, mproof, round_root)) {
        why = "v7fs:tiletree:open";
        return false;
    }
    // Overlap of this leaf's byte range with the extract_out byte range.
    const uint64_t leaf_start = static_cast<uint64_t>(leaf_index) * t_leaf;
    const uint64_t leaf_end = leaf_start + t_leaf;
    const uint64_t eo_start = stream_offset;
    const uint64_t eo_end = stream_offset + extract_out.size();
    const uint64_t lo = std::max(leaf_start, eo_start);
    const uint64_t hi = std::min(leaf_end, eo_end);
    for (uint64_t s = lo; s < hi; ++s) {
        const uint8_t from_leaf = leaf_bytes[s - leaf_start];
        const uint8_t from_eo = static_cast<uint8_t>(extract_out[s - eo_start]);
        if (from_leaf != from_eo) { why = "v7fs:tiletree:bytes"; return false; }
    }
    return true;
}

// ===========================================================================
// ANCHORED per-tile carrier (v3, scratchpad/sound-carrier-design.md §4): a
// sampled layer opens s_tile FS-derived output tiles (each a single (row i,
// 32-col block bj)); per tile the verifier ANCHORS the layer-input row (open
// X[l] row from round_roots, or PRF-regenerate at l=0 / SV) and RECOMPUTES the
// full contraction (H-row + Y-row for DOWN, or S-row + Y for SV) to check the
// committed extract_out. No relayed Y / contraction segments; no tautology.
// ===========================================================================

// One output tile's FS-derived plan: which (row, bcol). Contraction is always
// full (recomputed from anchored operands), so there is no segment plan.
struct TilePlan {
    uint32_t row{0};
    uint32_t bcol{0};
};

// SHA256d(kRCFreivaldsSegPosTag ‖ base_seed ‖ LE32(layer_index) ‖ LE32(ctr)).
uint256 SegPosDigest(const uint256& base_seed, uint32_t layer_index, uint32_t ctr)
{
    constexpr size_t kTagLen = sizeof(kRCFreivaldsSegPosTag) - 1;
    std::vector<unsigned char> buf(kTagLen + 32 + 4 + 4);
    std::memcpy(buf.data(), kRCFreivaldsSegPosTag, kTagLen);
    std::memcpy(buf.data() + kTagLen, base_seed.data(), 32);
    WriteLE32(buf.data() + kTagLen + 32, layer_index);
    WriteLE32(buf.data() + kTagLen + 32 + 4, ctr);
    return Sha256dBytes(buf.data(), buf.size());
}
uint64_t SegPosU64(const uint256& base_seed, uint32_t layer_index, uint32_t ctr)
{
    const uint256 h = SegPosDigest(base_seed, layer_index, ctr);
    uint64_t v = 0;
    for (int b = 0; b < 8; ++b) v |= static_cast<uint64_t>(h.data()[b]) << (8 * b);
    return v;
}

// Deterministic, verifier-recomputable output-tile plan for a sampled layer of
// shape (m, n). Identical on prover and verifier (the miner cannot choose which
// output entries are opened). FS derivation is byte-identical to the v2 segment
// carrier's (SegPosDigest/SegPosU64) so the coin stays target-bound + unbiasable.
std::vector<TilePlan> TilePositions(const uint256& base_seed, uint32_t layer_index, uint32_t m,
                                    uint32_t n)
{
    std::vector<TilePlan> plans;
    if (m == 0 || n < kRCMxBlockLen) return plans;
    const uint32_t n_blocks = n / kRCMxBlockLen;
    const uint64_t tile_space = static_cast<uint64_t>(m) * n_blocks;
    const uint32_t want_tiles =
        static_cast<uint32_t>(std::min<uint64_t>(kRCFreivaldsSegOutTiles, tile_space));
    uint32_t ctr = 0;
    const uint32_t max_iters = (want_tiles + 8u) * 64u + 4096u;
    std::vector<uint64_t> seen; // (row<<32 | bcol) dedupe (tiny sets)
    while (plans.size() < want_tiles && ctr < max_iters) {
        const uint64_t t = SegPosU64(base_seed, layer_index, ctr++);
        const uint32_t row = static_cast<uint32_t>(t % m);
        const uint32_t bcol = static_cast<uint32_t>((t / m) % n_blocks);
        const uint64_t key = (static_cast<uint64_t>(row) << 32) | bcol;
        if (std::find(seen.begin(), seen.end(), key) != seen.end()) continue;
        seen.push_back(key);
        plans.push_back(TilePlan{row, bcol});
    }
    return plans;
}

// PRF operand-expansion cache keyed by seed (weights + leaf activations expand
// once per verify; each Λ seed is domain-separated so it maps to one shape).
using RegenCache = std::map<uint256, std::vector<int8_t>>;
const std::vector<int8_t>& RegenLeaf(RegenCache& cache, const uint256& seed, uint32_t rows,
                                     uint32_t cols)
{
    auto it = cache.find(seed);
    if (it != cache.end()) return it->second;
    return cache.emplace(seed, ExpandMxDequantInt8(seed, rows, cols)).first->second;
}

// Extract one 32-col output block (row i, block bj) from an int64 accumulator row,
// using the position-indexed Extract sampler. Returns the T int8 outputs.
std::array<int8_t, kRCMxBlockLen> ExtractBlock(const uint256& prf, uint32_t i, uint32_t bj,
                                               const int64_t* acc_block)
{
    std::array<int8_t, kRCMxBlockLen> out{};
    ExtractMXTileInt64(prf, i, bj, acc_block, out.data());
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// FS sample derivation.
// ---------------------------------------------------------------------------
uint256 FreivaldsLayerChallengeSeed(const uint256& base_seed, uint32_t layer_index)
{
    constexpr size_t kTagLen = sizeof(kRCFreivaldsGemmSeedTag) - 1;
    std::vector<unsigned char> buf(kTagLen + 32 + 4);
    std::memcpy(buf.data(), kRCFreivaldsGemmSeedTag, kTagLen);
    std::memcpy(buf.data() + kTagLen, base_seed.data(), 32);
    WriteLE32(buf.data() + kTagLen + 32, layer_index);
    return Sha256dBytes(buf.data(), buf.size());
}

std::vector<uint32_t> FreivaldsSampleLayers(const uint256& base_seed, uint32_t n_units,
                                            uint32_t lambda)
{
    std::vector<uint32_t> out;
    if (n_units == 0 || lambda == 0) return out;
    const uint32_t want = std::min(lambda, n_units);
    out.reserve(want);
    std::vector<char> chosen(n_units, 0);
    constexpr size_t kTagLen = sizeof(kRCFreivaldsSampleTag) - 1;
    std::vector<unsigned char> buf(kTagLen + 32 + 4);
    std::memcpy(buf.data(), kRCFreivaldsSampleTag, kTagLen);
    std::memcpy(buf.data() + kTagLen, base_seed.data(), 32);
    // Domain-separated SHA counter; reject duplicates for distinctness. A bounded
    // counter guard keeps this terminating even in pathological cases.
    uint32_t counter = 0;
    const uint32_t max_iters = (want + 8u) * 64u + 4096u;
    while (out.size() < want && counter < max_iters) {
        WriteLE32(buf.data() + kTagLen + 32, counter);
        ++counter;
        const uint256 h = Sha256dBytes(buf.data(), buf.size());
        // Reduce the low 8 LE bytes mod n_units (bias ≤ n_units/2^64, negligible).
        uint64_t v = 0;
        for (int b = 0; b < 8; ++b) v |= static_cast<uint64_t>(h.data()[b]) << (8 * b);
        const uint32_t idx = static_cast<uint32_t>(v % n_units);
        if (!chosen[idx]) {
            chosen[idx] = 1;
            out.push_back(idx);
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Full-wires sublinear verifier.
// ---------------------------------------------------------------------------
bool VerifyEpisodeFreivaldsSampled(const RCGkrProofV7& proof, const CBlockHeader& header,
                                   int32_t height, const arith_uint256& target, std::string* why,
                                   RCFreivaldsSampledTiming* out_timing, uint32_t lambda)
{
    const auto t0 = std::chrono::steady_clock::now();
    RCFreivaldsSampledTiming tm;
    auto fail = [&](const std::string& m) {
        if (why) *why = m;
        if (out_timing) { tm.ok = false; tm.total_s = Secs(t0); tm.note = m; *out_timing = tm; }
        return false;
    };

    std::string gwhy;
    uint256 base_seed;
    if (!CheckGatesAndSeed(proof.version, proof.episode, proof.height, proof.claimed_digest,
                           proof.pow_bind, proof.episode_sigma, proof.round_roots,
                           proof.round_seeds, header, height, target, base_seed, gwhy)) {
        return fail(gwhy);
    }
    // Layout parity: wires must equal the canonical Λ enumeration (kind/dims).
    const RCGkrLayout layout_l = RCGkrTraceLayout(proof.episode);
    if (proof.wires.size() != layout_l.layers.size()) return fail("v7fs:layout_count");
    for (size_t li = 0; li < layout_l.layers.size(); ++li) {
        const auto& ls = layout_l.layers[li];
        const auto& w = proof.wires[li];
        if (!(ls.kind == w.kind && ls.round == w.round && ls.layer == w.layer && ls.m == w.m &&
              ls.n == w.n && ls.k == w.k)) {
            return fail("v7fs:layout_layer_mismatch");
        }
    }
    const std::vector<RCGkrSampledLayerProv> prov =
        RCGkrEpisodeLayerProvenance(header, proof.episode, proof.round_roots);
    if (prov.size() != proof.wires.size()) return fail("v7fs:wiring_count");
    tm.gates_s = Secs(t0);

    // FS sample derivation over the sampleable units.
    const auto t_s = std::chrono::steady_clock::now();
    const std::vector<uint32_t> sampleable = SampleableUnits(prov);
    tm.n_units_total = static_cast<uint32_t>(sampleable.size());
    const std::vector<uint32_t> units = FreivaldsSampleLayers(base_seed, tm.n_units_total, lambda);
    tm.n_sampled = static_cast<uint32_t>(units.size());
    tm.sample_s = Secs(t_s);

    // The λ sampled-layer checks. Round streams/leaves are built at most once per
    // round that actually holds a sampled layer.
    const auto t_p = std::chrono::steady_clock::now();
    std::unordered_map<uint32_t, std::vector<uint256>> leaves_cache;
    std::unordered_map<uint32_t, std::vector<int8_t>> stream_cache;
    const uint32_t t_leaf = proof.episode.T_leaf;
    for (uint32_t u : units) {
        const uint32_t li = sampleable[u];
        const RCGkrV7WireWitness& w = proof.wires[li];
        const RCGkrSampledLayerProv& lp = prov[li];
        // (b)+(c). The fused DOWN residual is X[l] (the layer input) = the UP wire's
        // A operand (down.A chains to the UP wire's H), NOT w.A (=H).
        std::vector<int8_t> resid;
        if (lp.fwd_residual) {
            if (lp.a.is_leaf || lp.a.src_idx >= proof.wires.size()) return fail("v7fs:residual_src");
            resid = proof.wires[lp.a.src_idx].A;
        }
        std::string cwhy;
        if (!CheckLayerFreivaldsExtract(lp.kind, w.m, w.k, w.n, w.A, w.B, w.Y, w.extract_in,
                                        w.extract_out, lp.extract_prf, resid, base_seed,
                                        li, tm.n_extract_tiles, cwhy)) {
            return fail(cwhy);
        }
        ++tm.n_freivalds_calls;
        // (d) chained-operand byte-equality against the referenced prior wires.
        auto chain_ok = [&](const RCGkrSampledOperandProv& ref, const std::vector<int8_t>& committed,
                            const char* label) -> bool {
            if (ref.is_leaf) return true;
            if (ref.src_idx >= proof.wires.size()) { fail(std::string("v7fs:chain_src:") + label); return false; }
            const std::vector<int8_t>& src = proof.wires[ref.src_idx].extract_out;
            if (src.size() != static_cast<size_t>(ref.erows) * ref.ecols) { fail(std::string("v7fs:chain_dims:") + label); return false; }
            const std::vector<int8_t> expected =
                ref.transpose ? TransposeI8Local(src, ref.erows, ref.ecols) : src;
            if (expected != committed) { fail(std::string("v7fs:chain:") + label); return false; }
            return true;
        };
        if (!chain_ok(lp.a, w.A, "A")) return false;
        if (!chain_ok(lp.b, w.B, "B")) return false;
        // (a) tile-tree opening of extract_out against round_roots[round].
        const uint32_t r = w.round;
        if (r >= proof.round_roots.size()) return fail("v7fs:round_index");
        auto sit = stream_cache.find(r);
        if (sit == stream_cache.end()) {
            sit = stream_cache.emplace(r, RCGkrReconstructRoundStream(proof.wires, r, proof.episode))
                      .first;
            leaves_cache.emplace(r, BuildTileTreeLeaves(sit->second, t_leaf));
        }
        const std::vector<int8_t>& stream_r = sit->second;
        const std::vector<uint256>& leaves = leaves_cache.at(r);
        const uint64_t off = LayerStreamOffset(proof.episode, lp.kind, lp.layer);
        const uint64_t len = w.extract_out.size();
        const uint32_t first_leaf = static_cast<uint32_t>(off / t_leaf);
        const uint32_t last_leaf = static_cast<uint32_t>((off + len - 1) / t_leaf);
        for (uint32_t lf = first_leaf; lf <= last_leaf; ++lf) {
            if (lf >= leaves.size()) return fail("v7fs:tiletree:leaf_index");
            const RCMerkleProof mp = OpenMerkleProof(leaves, lf);
            const std::vector<uint8_t> lb = LeafWindow(stream_r, t_leaf, lf);
            std::string owhy;
            if (!CheckCoveringLeaf(lb, lf, mp, proof.round_roots[r], t_leaf, off, w.extract_out,
                                   owhy)) {
                return fail(owhy);
            }
            tm.n_merkle_hashes += mp.siblings.size();
            ++tm.n_merkle_openings;
        }
        ++tm.n_layers_checked;
    }
    tm.perlayer_s = Secs(t_p);
    tm.ok = true;
    tm.total_s = Secs(t0);
    tm.note = "v7fs full-wires: " + std::to_string(tm.n_layers_checked) + "/" +
              std::to_string(tm.n_units_total) + " layers Freivalds-checked (flat in N)";
    if (out_timing) *out_timing = tm;
    if (why) *why = tm.note;
    return true;
}

// Per-sampled-layer relay byte bound (v3 anchored carrier): a function of T_leaf
// and the tree depth only — NOT of m,n,k (width unpin). Per tile ≈ the anchored
// A-row covering leaf (T_leaf + Merkle path) + the extract_out block + its
// covering leaf (T_leaf + path). Tree depth for any reachable N is < 32 (a round
// stream is < 2^40 bytes and T_leaf ≥ 64 ⇒ < 2^34 leaves); the bound uses depth 32.
size_t RCFreivaldsSegLayerByteBound(const RCEpisodeParams& params)
{
    const uint32_t T = kRCMxBlockLen;              // 32
    constexpr uint32_t kDepth = 32;                // safe tree-depth upper bound
    const uint64_t one_leaf_open = 3 + params.T_leaf          // covering leaf (full bytes)
                                   + 3 + static_cast<uint64_t>(kDepth) * 32; // Merkle proof
    const uint64_t per_tile =
        8 + 5                       // row + bcol
        + 3 + T                     // extract_out
        + 1                         // a_prf_regen flag
        + 9 + 5                     // a_row_stream_offset + a_row_leaf_index
        + 3 + one_leaf_open         // anchored A-row leaf + proof
        + 9 + 5                     // extract_out stream_offset + first_leaf
        + 3 + one_leaf_open;        // extract_out covering leaf + proof
    return static_cast<size_t>(kRCFreivaldsSegOutTiles) * static_cast<size_t>(per_tile) + 64;
}

// ---------------------------------------------------------------------------
// Carrier builder (miner side) — SEGMENT carrier. For each FS-sampled layer,
// open s_tile random output tiles (a single (row, 32-col block) each) and, per
// tile, s_ctr random contraction segments. Relay is bounded by the segment
// footprint, independent of the full operand size (design §2c resolution).
// O(N) to reconstruct the round leaves once (intrinsic to the miner's digest).
// ---------------------------------------------------------------------------
bool BuildFreivaldsSampledCarrier(const RCGkrProofV7& proof, const CBlockHeader& header,
                                  int32_t height, const arith_uint256& target,
                                  RCFreivaldsSampledCarrier& out, std::string* why, uint32_t lambda)
{
    auto fail = [&](const std::string& m) { if (why) *why = m; return false; };
    std::string gwhy;
    uint256 base_seed;
    if (!CheckGatesAndSeed(proof.version, proof.episode, proof.height, proof.claimed_digest,
                           proof.pow_bind, proof.episode_sigma, proof.round_roots,
                           proof.round_seeds, header, height, target, base_seed, gwhy)) {
        return fail(gwhy);
    }
    const std::vector<RCGkrSampledLayerProv> prov =
        RCGkrEpisodeLayerProvenance(header, proof.episode, proof.round_roots);
    if (prov.size() != proof.wires.size()) return fail("v7fs:wiring_count");
    const std::vector<uint32_t> sampleable = SampleableUnits(prov);
    const std::vector<uint32_t> units =
        FreivaldsSampleLayers(base_seed, static_cast<uint32_t>(sampleable.size()), lambda);

    out = RCFreivaldsSampledCarrier{};
    out.version = kRCFreivaldsSampledCarrierVersion;
    out.episode = proof.episode;
    out.height = proof.height;
    out.claimed_digest = proof.claimed_digest;
    out.pow_bind = proof.pow_bind;
    out.episode_sigma = proof.episode_sigma;
    out.round_seeds = proof.round_seeds;
    out.round_roots = proof.round_roots;
    out.lambda = lambda;

    const uint32_t t_leaf = proof.episode.T_leaf;
    const uint32_t T = kRCMxBlockLen;
    std::unordered_map<uint32_t, std::vector<uint256>> leaves_cache;
    std::unordered_map<uint32_t, std::vector<int8_t>> stream_cache;
    for (uint32_t u : units) {
        const uint32_t li = sampleable[u];
        const RCGkrV7WireWitness& w = proof.wires[li];
        const RCGkrSampledLayerProv& lp = prov[li];
        RCFreivaldsSampledLayer e;
        e.layer_index = li;
        e.round = w.round;
        e.kind = w.kind;
        e.m = w.m; e.n = w.n; e.k = w.k;

        const uint32_t r = w.round;
        auto sit = stream_cache.find(r);
        if (sit == stream_cache.end()) {
            sit = stream_cache.emplace(r, RCGkrReconstructRoundStream(proof.wires, r, proof.episode))
                      .first;
            leaves_cache.emplace(r, BuildTileTreeLeaves(sit->second, t_leaf));
        }
        const std::vector<int8_t>& stream = sit->second;
        const std::vector<uint256>& leaves = leaves_cache.at(r);
        const uint64_t layer_off = LayerStreamOffset(proof.episode, lp.kind, lp.layer);

        const std::vector<TilePlan> plans = TilePositions(base_seed, li, w.m, w.n);
        for (const TilePlan& pl : plans) {
            RCFreivaldsSampledTile tile;
            tile.row = pl.row;
            tile.bcol = pl.bcol;
            const size_t ybase = static_cast<size_t>(pl.row) * w.n + static_cast<size_t>(pl.bcol) * T;
            tile.extract_out.assign(w.extract_out.begin() + ybase, w.extract_out.begin() + ybase + T);

            // Anchor the layer-input A-row (X[l] row for DOWN, S row for SV).
            if (lp.kind == RCGkrLayerKind::GemmPhase1SV) {
                tile.a_prf_regen = true; // S regenerated from Q,K (QKt + Extract)
            } else {
                // DOWN: X[l] is the UP wire's A operand (down.A chains to the UP wire).
                if (lp.a.is_leaf || lp.a.src_idx >= prov.size()) return fail("v7fs:build:down_a");
                const RCGkrSampledOperandProv& xprov = prov[lp.a.src_idx].a;
                if (xprov.is_leaf) {
                    tile.a_prf_regen = true; // X0 regenerated at l==0
                } else {
                    // Open X[l] committed row from round_roots (same round r).
                    const RCGkrSampledLayerProv& src = prov[xprov.src_idx];
                    const uint64_t off_A = LayerStreamOffset(proof.episode, src.kind, src.layer) +
                                           static_cast<uint64_t>(pl.row) * proof.episode.d_model;
                    tile.a_row_stream_offset = off_A;
                    tile.a_row_leaf_index = static_cast<uint32_t>(off_A / t_leaf);
                    if (tile.a_row_leaf_index >= leaves.size()) return fail("v7fs:build:a_leaf_index");
                    tile.a_row_leaf = LeafWindow(stream, t_leaf, tile.a_row_leaf_index);
                    tile.a_row_proof = OpenMerkleProof(leaves, tile.a_row_leaf_index);
                }
            }

            // Tile-tree opening of this 32-byte extract_out block.
            const uint64_t off = layer_off + static_cast<uint64_t>(pl.row) * w.n +
                                 static_cast<uint64_t>(pl.bcol) * T;
            tile.stream_offset = off;
            tile.first_leaf = static_cast<uint32_t>(off / t_leaf);
            const uint32_t last_leaf = static_cast<uint32_t>((off + T - 1) / t_leaf);
            for (uint32_t lf = tile.first_leaf; lf <= last_leaf; ++lf) {
                if (lf >= leaves.size()) return fail("v7fs:build:leaf_index");
                tile.leaf_bytes.push_back(LeafWindow(stream, t_leaf, lf));
                tile.leaf_proofs.push_back(OpenMerkleProof(leaves, lf));
            }
            e.tiles.push_back(std::move(tile));
        }
        out.sampled.push_back(std::move(e));
    }
    return true;
}

// ---------------------------------------------------------------------------
// Carrier verifier (relay-optimized; operates on the SEGMENT carrier ALONE).
// Per sampled layer, recompute the FS output-tile + segment positions and, for
// each carried tile: (b) segment-Freivalds A·(B·r)=Y·r over the sampled
// contraction (EXACT when the segments cover [0,k); deterrence otherwise —
// header), (c) extract_in==Y(+resid) → Extract → extract_out re-exec, (a) open
// extract_out against round_roots. O(λ·s_tile·(s_ctr·L_seg + log N)).
// ---------------------------------------------------------------------------
bool VerifyEpisodeFreivaldsSampledCarrier(const RCFreivaldsSampledCarrier& carrier,
                                          const CBlockHeader& header, int32_t height,
                                          const arith_uint256& target, std::string* why,
                                          RCFreivaldsSampledTiming* out_timing)
{
    const auto t0 = std::chrono::steady_clock::now();
    RCFreivaldsSampledTiming tm;
    auto fail = [&](const std::string& m) {
        if (why) *why = m;
        if (out_timing) { tm.ok = false; tm.total_s = Secs(t0); tm.note = m; *out_timing = tm; }
        return false;
    };
    if (carrier.version != kRCFreivaldsSampledCarrierVersion) return fail("v7fs:carrier_version");

    std::string gwhy;
    uint256 base_seed;
    if (!CheckGatesAndSeed(kRCGkrProofVersionV7, carrier.episode, carrier.height,
                           carrier.claimed_digest, carrier.pow_bind, carrier.episode_sigma,
                           carrier.round_roots, carrier.round_seeds, header, height, target,
                           base_seed, gwhy)) {
        return fail(gwhy);
    }
    const std::vector<RCGkrSampledLayerProv> prov =
        RCGkrEpisodeLayerProvenance(header, carrier.episode, carrier.round_roots);
    const std::vector<uint32_t> sampleable = SampleableUnits(prov);
    tm.n_units_total = static_cast<uint32_t>(sampleable.size());
    const std::vector<uint32_t> units =
        FreivaldsSampleLayers(base_seed, tm.n_units_total, carrier.lambda);
    tm.n_sampled = static_cast<uint32_t>(units.size());
    if (carrier.sampled.size() != units.size()) return fail("v7fs:carrier_count");
    tm.gates_s = Secs(t0);

    const auto t_p = std::chrono::steady_clock::now();
    const uint32_t t_leaf = carrier.episode.T_leaf;
    const uint32_t T = kRCMxBlockLen;
    RegenCache regen; // PRF operand expansions (weights + leaf activations), once per verify
    for (size_t j = 0; j < units.size(); ++j) {
        const uint32_t li = sampleable[units[j]];
        const RCFreivaldsSampledLayer& e = carrier.sampled[j];
        if (e.layer_index != li) return fail("v7fs:carrier_order");
        if (li >= prov.size()) return fail("v7fs:carrier_layer_index");
        const RCGkrSampledLayerProv& lp = prov[li];
        if (!(e.kind == lp.kind && e.m == lp.m && e.n == lp.n && e.k == lp.k)) {
            return fail("v7fs:carrier_layer_mismatch");
        }
        if (e.n % T != 0) return fail("v7fs:carrier_n_block");
        if (e.round >= carrier.round_roots.size()) return fail("v7fs:round_index");
        const uint64_t layer_off = LayerStreamOffset(carrier.episode, lp.kind, lp.layer);
        // Recompute the FS output-tile plan — the miner cannot choose which output
        // tiles are opened (FS coin is target-bound via base_seed).
        const std::vector<TilePlan> plans = TilePositions(base_seed, li, e.m, e.n);
        if (e.tiles.size() != plans.size()) return fail("v7fs:carrier_tile_count");
        for (size_t ti = 0; ti < plans.size(); ++ti) {
            const TilePlan& pl = plans[ti];
            const RCFreivaldsSampledTile& tile = e.tiles[ti];
            if (tile.row != pl.row || tile.bcol != pl.bcol) return fail("v7fs:carrier_tile_pos");
            if (tile.extract_out.size() != T) return fail("v7fs:tile_shape");
            if (tile.row >= e.m || tile.bcol >= e.n / T) return fail("v7fs:tile_range");

            // ANCHORED RECOMPUTE (scratchpad/sound-carrier-design.md §4): recompute
            // this tile's extract_out from anchored operands, then require it to
            // equal the committed value opened against target-bound round_roots.
            std::array<int8_t, kRCMxBlockLen> eo{};
            if (lp.kind == RCGkrLayerKind::GemmPhase1SV) {
                // SV: regen S row (QKt + Extract from Q,K), then S·V block + Extract.
                if (!tile.a_prf_regen || !tile.a_row_leaf.empty()) return fail("v7fs:sv_anchor");
                if (lp.a.is_leaf || lp.a.src_idx >= prov.size()) return fail("v7fs:sv_qkt_src");
                const RCGkrSampledLayerProv& qkt = prov[lp.a.src_idx];
                if (qkt.kind != RCGkrLayerKind::GemmPhase1QKt) return fail("v7fs:sv_qkt_kind");
                const uint32_t d_head = carrier.episode.d_head;
                const uint32_t n_ctx = e.k; // == carrier.episode.n_ctx
                if (n_ctx % T != 0) return fail("v7fs:sv_ctx_block");
                const std::vector<int8_t>& Q =
                    RegenLeaf(regen, qkt.a.seed, carrier.episode.n_q, d_head);
                const std::vector<int8_t>& K = RegenLeaf(regen, qkt.b.seed, n_ctx, d_head);
                const std::vector<int8_t>& V = RegenLeaf(regen, lp.b.seed, n_ctx, d_head);
                // S row i (int8, n_ctx wide) = Extract(prf_S, Q[i]·Kᵀ).
                std::vector<int8_t> S_row(n_ctx);
                std::array<int64_t, kRCMxBlockLen> blk{};
                for (uint32_t bt = 0; bt < n_ctx / T; ++bt) {
                    for (uint32_t c = 0; c < T; ++c) {
                        const uint32_t t = bt * T + c;
                        int64_t acc = 0;
                        for (uint32_t d = 0; d < d_head; ++d)
                            acc += static_cast<int64_t>(Q[static_cast<size_t>(tile.row) * d_head + d]) *
                                   static_cast<int64_t>(K[static_cast<size_t>(t) * d_head + d]);
                        blk[c] = acc;
                    }
                    const auto so = ExtractBlock(qkt.extract_prf, tile.row, bt, blk.data());
                    for (uint32_t c = 0; c < T; ++c) S_row[bt * T + c] = so[c];
                }
                // Y block = S_row · V[:, bcol-block], then Extract(prf_Z). No residual.
                std::array<int64_t, kRCMxBlockLen> yblk{};
                for (uint32_t c = 0; c < T; ++c) {
                    const uint32_t col = tile.bcol * T + c;
                    int64_t acc = 0;
                    for (uint32_t t = 0; t < n_ctx; ++t)
                        acc += static_cast<int64_t>(S_row[t]) *
                               static_cast<int64_t>(V[static_cast<size_t>(t) * d_head + col]);
                    yblk[c] = acc;
                }
                eo = ExtractBlock(lp.extract_prf, tile.row, tile.bcol, yblk.data());
            } else {
                // DOWN: H-row = Extract(X_row·W_up); Y-block = Extract(H_row·W_down + X_row).
                if (lp.a.is_leaf || lp.a.src_idx >= prov.size()) return fail("v7fs:down_a_src");
                const RCGkrSampledLayerProv& up = prov[lp.a.src_idx];
                if (up.kind != RCGkrLayerKind::GemmPhase2FfnUp) return fail("v7fs:down_up_kind");
                const uint32_t d_model = e.n; // == carrier.episode.d_model
                const uint32_t d_ff = e.k;    // == carrier.episode.d_ff
                if (d_ff % T != 0) return fail("v7fs:down_ff_block");
                if (d_model > t_leaf) return fail("v7fs:a_row_multileaf");
                // Anchor X[l] row (d_model int8).
                std::vector<int8_t> X_row(d_model);
                const RCGkrSampledOperandProv& xprov = up.a;
                if (xprov.is_leaf) {
                    // l == 0: X0 PRF-regenerated (no committed leaf).
                    if (!tile.a_prf_regen || !tile.a_row_leaf.empty())
                        return fail("v7fs:down_l0_anchor");
                    const std::vector<int8_t>& X0 =
                        RegenLeaf(regen, xprov.seed, carrier.episode.b_seq, d_model);
                    for (uint32_t d = 0; d < d_model; ++d)
                        X_row[d] = X0[static_cast<size_t>(tile.row) * d_model + d];
                } else {
                    // l >= 1: open X[l] committed row from round_roots (one leaf).
                    if (tile.a_prf_regen) return fail("v7fs:down_anchor_flag");
                    if (xprov.src_idx >= prov.size()) return fail("v7fs:down_x_src");
                    const RCGkrSampledLayerProv& src = prov[xprov.src_idx];
                    const uint64_t off_A = LayerStreamOffset(carrier.episode, src.kind, src.layer) +
                                           static_cast<uint64_t>(tile.row) * d_model;
                    if (tile.a_row_stream_offset != off_A) return fail("v7fs:a_off");
                    const uint32_t a_leaf = static_cast<uint32_t>(off_A / t_leaf);
                    if (tile.a_row_leaf_index != a_leaf) return fail("v7fs:a_leaf_index");
                    if (tile.a_row_leaf.size() != t_leaf) return fail("v7fs:a_leaf_size");
                    const uint64_t rel = off_A - static_cast<uint64_t>(a_leaf) * t_leaf;
                    if (rel + d_model > t_leaf) return fail("v7fs:a_row_span");
                    for (uint32_t d = 0; d < d_model; ++d)
                        X_row[d] = static_cast<int8_t>(tile.a_row_leaf[rel + d]);
                    std::string awhy;
                    if (!CheckCoveringLeaf(tile.a_row_leaf, a_leaf, tile.a_row_proof,
                                           carrier.round_roots[e.round], t_leaf, off_A, X_row, awhy))
                        return fail(awhy);
                    tm.n_merkle_hashes += tile.a_row_proof.siblings.size();
                    ++tm.n_merkle_openings;
                }
                const std::vector<int8_t>& W_up = RegenLeaf(regen, up.b.seed, d_model, d_ff);
                const std::vector<int8_t>& W_down = RegenLeaf(regen, lp.b.seed, d_ff, d_model);
                // H-row = Extract(X_row·W_up) over the full d_ff width.
                std::vector<int8_t> H_row(d_ff);
                std::array<int64_t, kRCMxBlockLen> blk{};
                for (uint32_t bj = 0; bj < d_ff / T; ++bj) {
                    for (uint32_t c = 0; c < T; ++c) {
                        const uint32_t col = bj * T + c;
                        int64_t acc = 0;
                        for (uint32_t d = 0; d < d_model; ++d)
                            acc += static_cast<int64_t>(X_row[d]) *
                                   static_cast<int64_t>(W_up[static_cast<size_t>(d) * d_ff + col]);
                        blk[c] = acc;
                    }
                    const auto ho = ExtractBlock(up.extract_prf, tile.row, bj, blk.data());
                    for (uint32_t c = 0; c < T; ++c) H_row[bj * T + c] = ho[c];
                }
                // Y-block = Extract(H_row·W_down[:,bcol] + X_row[bcol]) (residual +X[l]).
                std::array<int64_t, kRCMxBlockLen> yblk{};
                for (uint32_t c = 0; c < T; ++c) {
                    const uint32_t col = tile.bcol * T + c;
                    int64_t acc = 0;
                    for (uint32_t t = 0; t < d_ff; ++t)
                        acc += static_cast<int64_t>(H_row[t]) *
                               static_cast<int64_t>(W_down[static_cast<size_t>(t) * d_model + col]);
                    acc += static_cast<int64_t>(X_row[col]); // residual +X[l] (H5)
                    yblk[c] = acc;
                }
                eo = ExtractBlock(lp.extract_prf, tile.row, tile.bcol, yblk.data());
            }
            // The recomputed extract_out must equal the relayed tile.extract_out.
            for (uint32_t c = 0; c < T; ++c)
                if (eo[c] != tile.extract_out[c]) return fail("v7fs:recompute_mismatch");
            ++tm.n_extract_tiles;
            ++tm.n_freivalds_calls;

            // (a) open extract_out block against round_roots (binds it to target).
            const uint64_t off_expect = layer_off + static_cast<uint64_t>(tile.row) * e.n +
                                        static_cast<uint64_t>(tile.bcol) * T;
            if (tile.stream_offset != off_expect) return fail("v7fs:carrier_offset");
            const uint32_t first_leaf = static_cast<uint32_t>(off_expect / t_leaf);
            const uint32_t last_leaf = static_cast<uint32_t>((off_expect + T - 1) / t_leaf);
            if (tile.first_leaf != first_leaf) return fail("v7fs:carrier_first_leaf");
            const uint32_t n_leaves = last_leaf - first_leaf + 1;
            if (tile.leaf_bytes.size() != n_leaves || tile.leaf_proofs.size() != n_leaves) {
                return fail("v7fs:carrier_leaf_count");
            }
            for (uint32_t x = 0; x < n_leaves; ++x) {
                const uint32_t lf = first_leaf + x;
                std::string owhy;
                if (!CheckCoveringLeaf(tile.leaf_bytes[x], lf, tile.leaf_proofs[x],
                                       carrier.round_roots[e.round], t_leaf, off_expect,
                                       tile.extract_out, owhy)) {
                    return fail(owhy);
                }
                tm.n_merkle_hashes += tile.leaf_proofs[x].siblings.size();
                ++tm.n_merkle_openings;
            }
        }
        ++tm.n_layers_checked;
    }
    tm.perlayer_s = Secs(t_p);
    tm.ok = true;
    tm.total_s = Secs(t0);
    tm.note = "v7fs anchored carrier: " + std::to_string(tm.n_layers_checked) + "/" +
              std::to_string(tm.n_units_total) + " layers recomputed from anchored operands";
    if (out_timing) *out_timing = tm;
    if (why) *why = tm.note;
    return true;
}

// ===========================================================================
// RELAY: carrier serialization (byte-exact) + bounded deserialization.
// Hand-rolled little-endian codec so every untrusted read is explicitly
// budget- and count-checked. The carrier is a RELAY-ONLY object — this byte
// layout is NOT consensus-serialized (it never enters a block/digest/FS seed);
// the consensus binding is the SEMANTIC check in the carrier verifier.
// ===========================================================================
namespace {

void PutU32(std::vector<unsigned char>& b, uint32_t v)
{
    b.push_back(static_cast<unsigned char>(v & 0xff));
    b.push_back(static_cast<unsigned char>((v >> 8) & 0xff));
    b.push_back(static_cast<unsigned char>((v >> 16) & 0xff));
    b.push_back(static_cast<unsigned char>((v >> 24) & 0xff));
}
void PutU64(std::vector<unsigned char>& b, uint64_t v)
{
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xff));
}
// Bitcoin CompactSize (canonical).
void PutCompact(std::vector<unsigned char>& b, uint64_t n)
{
    if (n < 253) {
        b.push_back(static_cast<unsigned char>(n));
    } else if (n <= 0xffff) {
        b.push_back(253);
        b.push_back(static_cast<unsigned char>(n & 0xff));
        b.push_back(static_cast<unsigned char>((n >> 8) & 0xff));
    } else if (n <= 0xffffffffULL) {
        b.push_back(254);
        PutU32(b, static_cast<uint32_t>(n));
    } else {
        b.push_back(255);
        PutU64(b, n);
    }
}
void PutBytes(std::vector<unsigned char>& b, const unsigned char* p, size_t n)
{
    b.insert(b.end(), p, p + n);
}
void PutHash(std::vector<unsigned char>& b, const uint256& h) { PutBytes(b, h.data(), 32); }
void PutEpisode(std::vector<unsigned char>& b, const RCEpisodeParams& e)
{
    // Exactly the 8 consensus shape fields, in the canonical order used by the
    // FS seed (RCGkrFsSeedV7). phase1_tile_delta is an RCEpisodeOptions execution
    // knob (0 under consensus, never digest-bearing) and is intentionally absent.
    PutU32(b, e.rounds);
    PutU32(b, e.d_head);
    PutU32(b, e.n_q);
    PutU32(b, e.n_ctx);
    PutU32(b, e.L_lyr);
    PutU32(b, e.d_model);
    PutU32(b, e.d_ff);
    PutU32(b, e.b_seq);
    PutU32(b, e.T_leaf);
}

/** Budget-checked, non-throwing reader over an untrusted span. */
struct BoundedReader {
    const unsigned char* p;
    size_t remaining;
    bool ok{true};
    std::string err;

    explicit BoundedReader(Span<const unsigned char> in)
        : p(in.data()), remaining(in.size()) {}

    bool fail(const std::string& m) { ok = false; if (err.empty()) err = m; return false; }
    bool need(size_t n) { return remaining >= n ? true : fail("carrier:underrun"); }

    bool U32(uint32_t& v)
    {
        if (!need(4)) return false;
        v = static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
            (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
        p += 4; remaining -= 4; return true;
    }
    bool U64(uint64_t& v)
    {
        if (!need(8)) return false;
        v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
        p += 8; remaining -= 8; return true;
    }
    bool U8(uint8_t& v)
    {
        if (!need(1)) return false;
        v = *p++; --remaining; return true;
    }
    bool Hash(uint256& h)
    {
        if (!need(32)) return false;
        std::memcpy(h.data(), p, 32);
        p += 32; remaining -= 32; return true;
    }
    // Canonical CompactSize with a caller-supplied hard cap.
    bool Compact(uint64_t& n, uint64_t cap)
    {
        if (!need(1)) return false;
        const uint8_t ch = *p++; --remaining;
        if (ch < 253) {
            n = ch;
        } else if (ch == 253) {
            if (!need(2)) return false;
            n = static_cast<uint64_t>(p[0]) | (static_cast<uint64_t>(p[1]) << 8);
            p += 2; remaining -= 2;
            if (n < 253) return fail("carrier:noncanonical_compact");
        } else if (ch == 254) {
            uint32_t v; if (!U32(v)) return false;
            n = v;
            if (n <= 0xffff) return fail("carrier:noncanonical_compact");
        } else {
            if (!U64(n)) return false;
            if (n <= 0xffffffffULL) return fail("carrier:noncanonical_compact");
        }
        if (n > cap) return fail("carrier:count_over_cap");
        return true;
    }
    bool Episode(RCEpisodeParams& e)
    {
        return U32(e.rounds) && U32(e.d_head) && U32(e.n_q) && U32(e.n_ctx) &&
               U32(e.L_lyr) && U32(e.d_model) && U32(e.d_ff) && U32(e.b_seq) && U32(e.T_leaf);
    }
    // Read a length-prefixed int8 vector; count bounded by remaining bytes and
    // the whole-carrier element ceiling, so allocation can never exceed input.
    bool VecI8(std::vector<int8_t>& v)
    {
        uint64_t cnt;
        if (!Compact(cnt, kRCCarrierMaxVecElems)) return false;
        if (!need(cnt)) return false;   // 1 byte/elem
        v.resize(cnt);
        for (uint64_t i = 0; i < cnt; ++i) v[i] = static_cast<int8_t>(p[i]);
        p += cnt; remaining -= cnt; return true;
    }
    bool VecI64(std::vector<int64_t>& v)
    {
        uint64_t cnt;
        if (!Compact(cnt, kRCCarrierMaxVecElems / 8 + 1)) return false;
        if (!need(cnt * 8)) return false;
        v.resize(cnt);
        for (uint64_t i = 0; i < cnt; ++i) {
            uint64_t u = 0;
            for (int j = 0; j < 8; ++j) u |= static_cast<uint64_t>(p[8 * i + j]) << (8 * j);
            v[i] = static_cast<int64_t>(u);
        }
        p += cnt * 8; remaining -= cnt * 8; return true;
    }
    bool VecHash(std::vector<uint256>& v, uint64_t cap)
    {
        uint64_t cnt;
        if (!Compact(cnt, cap)) return false;
        if (!need(cnt * 32)) return false;
        v.resize(cnt);
        for (uint64_t i = 0; i < cnt; ++i) { std::memcpy(v[i].data(), p + 32 * i, 32); }
        p += cnt * 32; remaining -= cnt * 32; return true;
    }
    bool RawBytes(std::vector<uint8_t>& v)
    {
        uint64_t cnt;
        if (!Compact(cnt, kRCCarrierMaxVecElems)) return false;
        if (!need(cnt)) return false;
        v.resize(cnt);
        std::memcpy(v.data(), p, cnt);
        p += cnt; remaining -= cnt; return true;
    }
};

} // namespace

void SerializeRCFreivaldsCarrier(const RCFreivaldsSampledCarrier& c,
                                 std::vector<unsigned char>& out)
{
    out.clear();
    PutU32(out, c.version);
    PutEpisode(out, c.episode);
    PutU32(out, static_cast<uint32_t>(c.height));
    PutHash(out, c.claimed_digest);
    PutHash(out, c.pow_bind);
    PutHash(out, c.episode_sigma);
    PutCompact(out, c.round_seeds.size());
    for (const auto& h : c.round_seeds) PutHash(out, h);
    PutCompact(out, c.round_roots.size());
    for (const auto& h : c.round_roots) PutHash(out, h);
    PutU32(out, c.lambda);
    PutCompact(out, c.sampled.size());
    for (const auto& e : c.sampled) {
        PutU32(out, e.layer_index);
        PutU32(out, e.round);
        PutU32(out, static_cast<uint32_t>(e.kind));
        PutU32(out, e.m);
        PutU32(out, e.n);
        PutU32(out, e.k);
        PutCompact(out, e.tiles.size());
        for (const auto& tile : e.tiles) {
            PutU32(out, tile.row);
            PutU32(out, tile.bcol);
            PutCompact(out, tile.extract_out.size());
            for (int8_t x : tile.extract_out) out.push_back(static_cast<unsigned char>(x));
            // Anchored A-row (empty + flag when PRF-regenerable).
            out.push_back(tile.a_prf_regen ? 1 : 0);
            PutU64(out, tile.a_row_stream_offset);
            PutU32(out, tile.a_row_leaf_index);
            PutCompact(out, tile.a_row_leaf.size());
            PutBytes(out, tile.a_row_leaf.data(), tile.a_row_leaf.size());
            PutCompact(out, tile.a_row_proof.siblings.size());
            for (const auto& s : tile.a_row_proof.siblings) PutHash(out, s);
            // extract_out tile-tree opening.
            PutU64(out, tile.stream_offset);
            PutU32(out, tile.first_leaf);
            PutCompact(out, tile.leaf_bytes.size());
            for (const auto& lb : tile.leaf_bytes) {
                PutCompact(out, lb.size());
                PutBytes(out, lb.data(), lb.size());
            }
            PutCompact(out, tile.leaf_proofs.size());
            for (const auto& pf : tile.leaf_proofs) {
                PutCompact(out, pf.siblings.size());
                for (const auto& s : pf.siblings) PutHash(out, s);
            }
        }
    }
}

bool DeserializeRCFreivaldsCarrierBounded(Span<const unsigned char> in,
                                          RCFreivaldsSampledCarrier& out, std::string* why)
{
    auto bad = [&](const std::string& m) { if (why) *why = m; return false; };
    // Hard byte ceiling BEFORE touching the bytes: an oversize frame is rejected
    // for the cost of a size compare, never a copy or allocation.
    if (in.size() > kRCFreivaldsCarrierMaxSerializedBytes) return bad("carrier:oversize");

    BoundedReader r(in);
    RCFreivaldsSampledCarrier c;
    if (!r.U32(c.version)) return bad(r.err);
    if (c.version != kRCFreivaldsSampledCarrierVersion) return bad("carrier:version");
    if (!r.Episode(c.episode)) return bad(r.err);
    uint32_t h_raw; if (!r.U32(h_raw)) return bad(r.err);
    c.height = static_cast<int32_t>(h_raw);
    if (!r.Hash(c.claimed_digest)) return bad(r.err);
    if (!r.Hash(c.pow_bind)) return bad(r.err);
    if (!r.Hash(c.episode_sigma)) return bad(r.err);
    if (!r.VecHash(c.round_seeds, kRCCarrierMaxRounds)) return bad(r.err);
    if (!r.VecHash(c.round_roots, kRCCarrierMaxRounds)) return bad(r.err);
    if (!r.U32(c.lambda)) return bad(r.err);

    uint64_t n_sampled;
    if (!r.Compact(n_sampled, kRCCarrierMaxSampledLayers)) return bad(r.err);
    c.sampled.resize(n_sampled);
    for (uint64_t i = 0; i < n_sampled; ++i) {
        RCFreivaldsSampledLayer& e = c.sampled[i];
        uint32_t kind_raw;
        if (!r.U32(e.layer_index) || !r.U32(e.round) || !r.U32(kind_raw) ||
            !r.U32(e.m) || !r.U32(e.n) || !r.U32(e.k)) {
            return bad(r.err);
        }
        e.kind = static_cast<RCGkrLayerKind>(kind_raw);
        uint64_t n_tiles;
        if (!r.Compact(n_tiles, kRCCarrierMaxTilesPerLayer)) return bad(r.err);
        e.tiles.resize(n_tiles);
        for (uint64_t ti = 0; ti < n_tiles; ++ti) {
            RCFreivaldsSampledTile& tile = e.tiles[ti];
            if (!r.U32(tile.row) || !r.U32(tile.bcol)) return bad(r.err);
            if (!r.VecI8(tile.extract_out)) return bad(r.err);
            // Anchored A-row.
            uint8_t regen;
            if (!r.U8(regen)) return bad(r.err);
            tile.a_prf_regen = (regen != 0);
            if (!r.U64(tile.a_row_stream_offset) || !r.U32(tile.a_row_leaf_index)) return bad(r.err);
            if (!r.RawBytes(tile.a_row_leaf)) return bad(r.err);
            if (!r.VecHash(tile.a_row_proof.siblings, kRCCarrierMaxMerkleSiblings)) return bad(r.err);
            // extract_out tile-tree opening.
            if (!r.U64(tile.stream_offset) || !r.U32(tile.first_leaf)) return bad(r.err);
            uint64_t n_leaves;
            if (!r.Compact(n_leaves, kRCCarrierMaxLeavesPerTile)) return bad(r.err);
            tile.leaf_bytes.resize(n_leaves);
            for (uint64_t x = 0; x < n_leaves; ++x) {
                if (!r.RawBytes(tile.leaf_bytes[x])) return bad(r.err);
            }
            uint64_t n_proofs;
            if (!r.Compact(n_proofs, kRCCarrierMaxLeavesPerTile)) return bad(r.err);
            tile.leaf_proofs.resize(n_proofs);
            for (uint64_t x = 0; x < n_proofs; ++x) {
                if (!r.VecHash(tile.leaf_proofs[x].siblings, kRCCarrierMaxMerkleSiblings)) {
                    return bad(r.err);
                }
            }
        }
    }
    if (r.remaining != 0) return bad("carrier:trailing_data");
    out = std::move(c);
    return true;
}

// ===========================================================================
// RELAY: process-local carrier store (LRU+TTL). Same policy and limits as the
// V7 proof store (kRCGkrProofCacheMaxEntries / kRCGkrProofCacheTtlSeconds);
// independent mutex so carrier traffic never contends the GKR cache lock.
// ===========================================================================
namespace {
std::mutex g_rc_carrier_mu;
struct RCCarrierStoreEntry {
    RCFreivaldsSampledCarrier carrier;
    std::chrono::steady_clock::time_point expires_at;
    std::list<uint256>::iterator lru_it;
};
std::list<uint256> g_rc_carrier_lru;
std::map<uint256, RCCarrierStoreEntry> g_rc_carrier_store;

void CarrierEvictExpiredLocked(std::chrono::steady_clock::time_point now)
{
    for (auto it = g_rc_carrier_store.begin(); it != g_rc_carrier_store.end();) {
        if (it->second.expires_at <= now) {
            g_rc_carrier_lru.erase(it->second.lru_it);
            it = g_rc_carrier_store.erase(it);
        } else {
            ++it;
        }
    }
}
void CarrierEvictLruLocked()
{
    while (g_rc_carrier_store.size() > kRCGkrProofCacheMaxEntries) {
        const uint256 oldest = g_rc_carrier_lru.back();
        g_rc_carrier_lru.pop_back();
        g_rc_carrier_store.erase(oldest);
    }
}
} // namespace

void RCFreivaldsCarrierStorePut(const uint256& block_hash, RCFreivaldsSampledCarrier carrier)
{
    std::lock_guard<std::mutex> lock(g_rc_carrier_mu);
    const auto now = std::chrono::steady_clock::now();
    CarrierEvictExpiredLocked(now);
    const auto expires = now + std::chrono::seconds(kRCGkrProofCacheTtlSeconds);
    auto it = g_rc_carrier_store.find(block_hash);
    if (it != g_rc_carrier_store.end()) {
        g_rc_carrier_lru.erase(it->second.lru_it);
        g_rc_carrier_lru.push_front(block_hash);
        it->second.carrier = std::move(carrier);
        it->second.expires_at = expires;
        it->second.lru_it = g_rc_carrier_lru.begin();
    } else {
        g_rc_carrier_lru.push_front(block_hash);
        RCCarrierStoreEntry entry;
        entry.carrier = std::move(carrier);
        entry.expires_at = expires;
        entry.lru_it = g_rc_carrier_lru.begin();
        g_rc_carrier_store.emplace(block_hash, std::move(entry));
    }
    CarrierEvictLruLocked();
}

bool RCFreivaldsCarrierStoreGet(const uint256& block_hash, RCFreivaldsSampledCarrier& out)
{
    std::lock_guard<std::mutex> lock(g_rc_carrier_mu);
    const auto now = std::chrono::steady_clock::now();
    auto it = g_rc_carrier_store.find(block_hash);
    if (it == g_rc_carrier_store.end()) return false;
    if (it->second.expires_at <= now) {
        g_rc_carrier_lru.erase(it->second.lru_it);
        g_rc_carrier_store.erase(it);
        return false;
    }
    g_rc_carrier_lru.erase(it->second.lru_it);
    g_rc_carrier_lru.push_front(block_hash);
    it->second.lru_it = g_rc_carrier_lru.begin();
    out = it->second.carrier;
    return true;
}

bool RCFreivaldsCarrierStoreHave(const uint256& block_hash)
{
    std::lock_guard<std::mutex> lock(g_rc_carrier_mu);
    CarrierEvictExpiredLocked(std::chrono::steady_clock::now());
    return g_rc_carrier_store.count(block_hash) != 0;
}

void RCFreivaldsCarrierStoreClear()
{
    std::lock_guard<std::mutex> lock(g_rc_carrier_mu);
    g_rc_carrier_store.clear();
    g_rc_carrier_lru.clear();
}

size_t RCFreivaldsCarrierStoreSizeForTest()
{
    std::lock_guard<std::mutex> lock(g_rc_carrier_mu);
    CarrierEvictExpiredLocked(std::chrono::steady_clock::now());
    return g_rc_carrier_store.size();
}

} // namespace matmul::v4::rc
