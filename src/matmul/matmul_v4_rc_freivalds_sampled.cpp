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
#include <unordered_map>

namespace matmul::v4::rc {

namespace {

double Secs(std::chrono::steady_clock::time_point s)
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - s).count();
}

// A layer's extract_out is committed to the round tile-tree stream iff it is one
// of SV / Fwd / Bwd / Wgrad (QKt's output S is not streamed — see header).
bool LayerInStream(RCGkrLayerKind k)
{
    return k == RCGkrLayerKind::GemmPhase1SV || k == RCGkrLayerKind::GemmPhase2Fwd ||
           k == RCGkrLayerKind::GemmPhase2Bwd || k == RCGkrLayerKind::GemmPhase2Wgrad;
}

// Byte offset of a layer's extract_out within its round stream. MUST match the
// RCGkrReconstructRoundStream layout: Z ‖ for l: (Fwd_l ‖ Bwd_l ‖ Wgrad_l).
uint64_t LayerStreamOffset(const RCEpisodeParams& p, RCGkrLayerKind kind, uint32_t layer)
{
    const uint64_t z = static_cast<uint64_t>(p.n_q) * p.d_head;
    const uint64_t fwd = static_cast<uint64_t>(p.b_seq) * p.d_model;
    const uint64_t bwd = fwd;
    const uint64_t wg = static_cast<uint64_t>(p.d_model) * p.d_model;
    const uint64_t per_l = fwd + bwd + wg;
    switch (kind) {
    case RCGkrLayerKind::GemmPhase1SV:
        return 0;
    case RCGkrLayerKind::GemmPhase2Fwd:
        return z + static_cast<uint64_t>(layer) * per_l;
    case RCGkrLayerKind::GemmPhase2Bwd:
        return z + static_cast<uint64_t>(layer) * per_l + fwd;
    case RCGkrLayerKind::GemmPhase2Wgrad:
        return z + static_cast<uint64_t>(layer) * per_l + fwd + bwd;
    default:
        return 0; // QKt: not in stream (never sampled)
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
                                const uint256& extract_prf, bool fwd_residual,
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
    // (c) accumulator/residual relation: extract_in == Y (+ A for the Fwd residual).
    for (size_t idx = 0; idx < mn; ++idx) {
        int64_t expect = Y[idx];
        if (fwd_residual) expect += static_cast<int64_t>(A[idx]);
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
        // (b)+(c)
        std::string cwhy;
        if (!CheckLayerFreivaldsExtract(lp.kind, w.m, w.k, w.n, w.A, w.B, w.Y, w.extract_in,
                                        w.extract_out, lp.extract_prf, lp.fwd_residual, base_seed,
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

// ---------------------------------------------------------------------------
// Carrier builder (miner side).
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
        e.A = w.A; e.B = w.B; e.Y = w.Y; e.extract_in = w.extract_in; e.extract_out = w.extract_out;
        const uint32_t r = w.round;
        auto sit = stream_cache.find(r);
        if (sit == stream_cache.end()) {
            sit = stream_cache.emplace(r, RCGkrReconstructRoundStream(proof.wires, r, proof.episode))
                      .first;
            leaves_cache.emplace(r, BuildTileTreeLeaves(sit->second, t_leaf));
        }
        const std::vector<int8_t>& stream = sit->second;
        const std::vector<uint256>& leaves = leaves_cache.at(r);
        const uint64_t off = LayerStreamOffset(proof.episode, lp.kind, lp.layer);
        const uint64_t len = w.extract_out.size();
        e.stream_offset = off;
        e.first_leaf = static_cast<uint32_t>(off / t_leaf);
        const uint32_t last_leaf = static_cast<uint32_t>((off + len - 1) / t_leaf);
        for (uint32_t lf = e.first_leaf; lf <= last_leaf; ++lf) {
            if (lf >= leaves.size()) return fail("v7fs:build:leaf_index");
            e.leaf_bytes.push_back(LeafWindow(stream, t_leaf, lf));
            e.leaf_proofs.push_back(OpenMerkleProof(leaves, lf));
        }
        out.sampled.push_back(std::move(e));
    }
    return true;
}

// ---------------------------------------------------------------------------
// Carrier verifier (relay-optimized; operates on the carrier ALONE).
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

    // Map carried layer_index → entry for chained-operand lookups.
    std::unordered_map<uint32_t, const RCFreivaldsSampledLayer*> by_index;
    for (const auto& e : carrier.sampled) by_index[e.layer_index] = &e;

    const auto t_p = std::chrono::steady_clock::now();
    const uint32_t t_leaf = carrier.episode.T_leaf;
    for (size_t j = 0; j < units.size(); ++j) {
        const uint32_t li = sampleable[units[j]];
        const RCFreivaldsSampledLayer& e = carrier.sampled[j];
        if (e.layer_index != li) return fail("v7fs:carrier_order");
        if (li >= prov.size()) return fail("v7fs:carrier_layer_index");
        const RCGkrSampledLayerProv& lp = prov[li];
        if (!(e.kind == lp.kind && e.m == lp.m && e.n == lp.n && e.k == lp.k)) {
            return fail("v7fs:carrier_layer_mismatch");
        }
        // (b)+(c)
        std::string cwhy;
        if (!CheckLayerFreivaldsExtract(lp.kind, e.m, e.k, e.n, e.A, e.B, e.Y, e.extract_in,
                                        e.extract_out, lp.extract_prf, lp.fwd_residual, base_seed,
                                        li, tm.n_extract_tiles, cwhy)) {
            return fail(cwhy);
        }
        ++tm.n_freivalds_calls;
        // (d) chained-operand binding — only when the source is also carried
        // (documented boundary: otherwise the operand rides the Freivalds
        // statement + target-bound digest; see header).
        auto chain_ok = [&](const RCGkrSampledOperandProv& ref, const std::vector<int8_t>& committed,
                            const char* label) -> bool {
            if (ref.is_leaf) return true;
            auto sit = by_index.find(static_cast<uint32_t>(ref.src_idx));
            if (sit == by_index.end()) return true; // source not carried: unbound (boundary)
            const std::vector<int8_t>& src = sit->second->extract_out;
            if (src.size() != static_cast<size_t>(ref.erows) * ref.ecols) { fail(std::string("v7fs:chain_dims:") + label); return false; }
            const std::vector<int8_t> expected =
                ref.transpose ? TransposeI8Local(src, ref.erows, ref.ecols) : src;
            if (expected != committed) { fail(std::string("v7fs:chain:") + label); return false; }
            return true;
        };
        if (!chain_ok(lp.a, e.A, "A")) return false;
        if (!chain_ok(lp.b, e.B, "B")) return false;
        // (a) tile-tree opening from the carried leaves (O(log N), no O(N) build).
        if (e.round >= carrier.round_roots.size()) return fail("v7fs:round_index");
        const uint64_t off_expect = LayerStreamOffset(carrier.episode, lp.kind, lp.layer);
        if (e.stream_offset != off_expect) return fail("v7fs:carrier_offset");
        const uint64_t len = e.extract_out.size();
        const uint32_t first_leaf = static_cast<uint32_t>(off_expect / t_leaf);
        const uint32_t last_leaf = static_cast<uint32_t>((off_expect + len - 1) / t_leaf);
        if (e.first_leaf != first_leaf) return fail("v7fs:carrier_first_leaf");
        const uint32_t n_leaves = last_leaf - first_leaf + 1;
        if (e.leaf_bytes.size() != n_leaves || e.leaf_proofs.size() != n_leaves) {
            return fail("v7fs:carrier_leaf_count");
        }
        for (uint32_t x = 0; x < n_leaves; ++x) {
            const uint32_t lf = first_leaf + x;
            std::string owhy;
            if (!CheckCoveringLeaf(e.leaf_bytes[x], lf, e.leaf_proofs[x], carrier.round_roots[e.round],
                                   t_leaf, off_expect, e.extract_out, owhy)) {
                return fail(owhy);
            }
            tm.n_merkle_hashes += e.leaf_proofs[x].siblings.size();
            ++tm.n_merkle_openings;
        }
        ++tm.n_layers_checked;
    }
    tm.perlayer_s = Secs(t_p);
    tm.ok = true;
    tm.total_s = Secs(t0);
    tm.note = "v7fs carrier: " + std::to_string(tm.n_layers_checked) + "/" +
              std::to_string(tm.n_units_total) + " layers checked from relayed openings";
    if (out_timing) *out_timing = tm;
    if (why) *why = tm.note;
    return true;
}

} // namespace matmul::v4::rc
