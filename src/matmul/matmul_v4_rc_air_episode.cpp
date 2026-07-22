// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_air_episode.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_gkr_air.h>
#include <span.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>

// Episode-level AIR constraint-quotient instantiation — implementation. See
// the header for the construction map and the honest residual list. The
// max composed constraint degree is kept at TWO by factoring the degree-4
// AirAcceptPoly through an auxiliary inner column (rejected = (1−b2)·inner —
// the exact factorization of the acceptance selector, cross-checked against
// AirAcceptPoly in the tests) and the degree-3 dequant through mu·(1+e0), so
// the quotient length is N−1 and n_coeffs = N (4× cheaper commitments than a
// naive degree-4 composition).

namespace matmul::v4::rc::air_episode {

namespace aq = air_quotient;
namespace gf = gkr_field;

using gf::Fp;

namespace {

using Clock = std::chrono::steady_clock;

double Secs(Clock::time_point t0)
{
    return std::chrono::duration<double>(Clock::now() - t0).count();
}

Fp3 F3u(uint64_t v) { return Fp3::FromFp(gf::FromU64(v)); }
Fp3 F3s(int64_t v) { return Fp3::FromFp(gf::FromSigned(v)); }

// ---------------------------------------------------------------------------
// Row layout (public function of the episode layout).
// ---------------------------------------------------------------------------
struct EpisodeRowLayout {
    uint64_t elem_total{0};
    uint64_t leaf_total{0};
    uint64_t total{0};
    std::vector<uint64_t> layer_base;  // element-region base per layer
    std::vector<uint64_t> leaf_base;   // ABSOLUTE base per leaf (≥ elem_total)
    uint32_t shard_rows{0};            // min(kEpisodeAirMaxShardRows, pow2(total))
    uint32_t n_shards{0};
};

bool BuildRowLayout(const EpisodeAirLayout& layout, EpisodeRowLayout& rl, std::string& why)
{
    rl = EpisodeRowLayout{};
    for (const EpisodeAirLayer& l : layout.layers) {
        if (l.m == 0 || l.n == 0 || (l.n % kRCMxBlockLen) != 0) {
            why = "layer dims not tile-aligned";
            return false;
        }
        rl.layer_base.push_back(rl.elem_total);
        rl.elem_total += static_cast<uint64_t>(l.m) * l.n;
    }
    for (const EpisodeAirLeaf& lf : layout.leaves) {
        if (lf.rows == 0 || lf.cols == 0 || (lf.rows % kRCMxBlockLen) != 0 ||
            (lf.cols % kRCMxBlockLen) != 0) {
            why = "leaf dims not 32-aligned";
            return false;
        }
        rl.leaf_base.push_back(rl.elem_total + rl.leaf_total);
        rl.leaf_total += static_cast<uint64_t>(lf.rows) * lf.cols;
    }
    rl.total = rl.elem_total + rl.leaf_total;
    if (rl.total == 0) {
        why = "empty episode layout";
        return false;
    }
    rl.shard_rows = kEpisodeAirMaxShardRows;
    if (rl.total < kEpisodeAirMaxShardRows) {
        rl.shard_rows = std::max<uint32_t>(2u, FriNextPow2(static_cast<uint32_t>(rl.total)));
    }
    if (layout.gemm.size() > rl.shard_rows) {
        why = "too many gemm claims for shard 0";
        return false;
    }
    const uint64_t ns = (rl.total + rl.shard_rows - 1) / rl.shard_rows;
    if (ns > (1u << 20)) {
        why = "episode too large for sharding";
        return false;
    }
    rl.n_shards = static_cast<uint32_t>(ns);
    return true;
}

// ---------------------------------------------------------------------------
// Native leaf-operand expansion (PLAIN SHA-256 mirror of the in-circuit
// VerifyMxExpandColumn XOF — same byte conventions, no constraint-checked
// compression traces; the canonical values feed PREPROCESSED columns).
// ---------------------------------------------------------------------------
constexpr uint8_t kMantissaStreamDomain = 0x6D; // 'm'
constexpr uint8_t kScaleStreamDomain = 0x65;    // 'e'

std::array<uint8_t, 32> SeedBytesLE(const uint256& seed)
{
    std::array<uint8_t, 32> out{};
    for (size_t i = 0; i < 32; ++i) out[i] = seed.data()[31 - i];
    return out;
}

std::array<uint8_t, 32> XofDigest(const std::array<uint8_t, 32>& seed_bytes, uint8_t domain,
                                  uint64_t block)
{
    std::array<uint8_t, 41> msg{};
    std::memcpy(msg.data(), seed_bytes.data(), 32);
    msg[32] = domain;
    WriteLE64(msg.data() + 33, block);
    std::array<uint8_t, 32> d{};
    CSHA256().Write(msg.data(), msg.size()).Finalize(d.data());
    return d;
}

struct LeafExpansion {
    std::vector<int8_t> val;   // dequantized output (== ExpandMxDequantInt8)
    std::vector<int8_t> mu;    // accepted mantissa per element
    std::vector<uint8_t> nib;  // accepted E2M1 nibble per element
    std::vector<uint8_t> e;    // scale code per element (0..3)
    uint64_t n_xof_digests{0}; // SHA-256 digests spent (mantissa + scale XOF)
};

bool NativeExpandLeaf(const uint256& seed, uint32_t rows, uint32_t cols,
                      const gkr_air::TableTM& tm, LeafExpansion& out, std::string& why)
{
    const size_t count = static_cast<size_t>(rows) * cols;
    const std::array<uint8_t, 32> seed_bytes = SeedBytesLE(seed);

    out.mu.clear();
    out.nib.clear();
    out.mu.reserve(count);
    out.nib.reserve(count);
    out.n_xof_digests = 0;
    uint64_t block = 0;
    while (out.mu.size() < count) {
        const std::array<uint8_t, 32> digest =
            XofDigest(seed_bytes, kMantissaStreamDomain, block);
        ++out.n_xof_digests;
        for (size_t i = 0; i < 32 && out.mu.size() < count; ++i) {
            const uint8_t nibs[2] = {static_cast<uint8_t>(digest[i] & 0x0F),
                                     static_cast<uint8_t>((digest[i] >> 4) & 0x0F)};
            for (uint8_t nib : nibs) {
                if (tm.acc[nib]) {
                    out.mu.push_back(tm.mu[nib]);
                    out.nib.push_back(nib);
                    if (out.mu.size() == count) break;
                }
            }
        }
        ++block;
        if (block > (count / 8 + 64)) {
            why = "mxexpand xof stalled";
            return false;
        }
    }

    const size_t scale_count = static_cast<size_t>(rows) * (cols / kRCMxBlockLen);
    std::vector<uint8_t> scale;
    scale.reserve(scale_count);
    block = 0;
    while (scale.size() < scale_count) {
        const std::array<uint8_t, 32> digest = XofDigest(seed_bytes, kScaleStreamDomain, block);
        ++out.n_xof_digests;
        for (size_t i = 0; i < 32 && scale.size() < scale_count; ++i) {
            for (int shift = 0; shift < 8 && scale.size() < scale_count; shift += 2) {
                scale.push_back(static_cast<uint8_t>((digest[i] >> shift) & 0x03));
            }
        }
        ++block;
    }

    const uint32_t nblk = cols / kRCMxBlockLen;
    out.val.assign(count, 0);
    out.e.assign(count, 0);
    for (uint32_t i = 0; i < rows; ++i) {
        for (uint32_t j = 0; j < cols; ++j) {
            const size_t idx = static_cast<size_t>(i) * cols + j;
            const uint8_t e = scale[static_cast<size_t>(i) * nblk + (j / kRCMxBlockLen)];
            out.e[idx] = e;
            out.val[idx] =
                static_cast<int8_t>(static_cast<int32_t>(out.mu[idx]) * (int32_t{1} << e));
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Public (verifier-regenerable) per-row data over the whole episode.
// ---------------------------------------------------------------------------
struct EpisodePublicData {
    EpisodeRowLayout rl;
    // sel: 0 = padding, 1 = element, 2 = element+fwd-residual, 3 = leaf.
    std::vector<uint8_t> sel;
    std::vector<uint8_t> scale_e;   // per-row scale code (0..3)
    std::vector<int8_t> leaf_val;   // canonical expansion (leaf region, relative)
    std::vector<int8_t> leaf_mu;    // (prover) canonical mantissa
    std::vector<uint8_t> leaf_nib;  // (prover) canonical nibble
    // SHA workload of this build (the cost Stage A removes from the verifier).
    uint64_t n_prf_calls{0};        // DeriveMatExpandMxScale invocations
    uint64_t n_xof_digests{0};      // leaf-XOF SHA-256 digests
};

bool BuildEpisodePublicData(const EpisodeAirLayout& layout, bool want_prover_data,
                            EpisodePublicData& pub, std::string& why)
{
    if (!BuildRowLayout(layout, pub.rl, why)) return false;
    const EpisodeRowLayout& rl = pub.rl;
    pub.sel.assign(rl.total, 0);
    pub.scale_e.assign(rl.total, 0);
    pub.leaf_val.assign(rl.leaf_total, 0);
    if (want_prover_data) {
        pub.leaf_mu.assign(rl.leaf_total, 0);
        pub.leaf_nib.assign(rl.leaf_total, 0);
    }

    // Element region: selectors + the PUBLIC per-tile Extract scale.
    for (size_t li = 0; li < layout.layers.size(); ++li) {
        const EpisodeAirLayer& l = layout.layers[li];
        const uint64_t base = rl.layer_base[li];
        const uint32_t n_blocks = l.n / kRCMxBlockLen;
        const uint8_t s = l.fwd_residual ? 2 : 1;
        for (uint32_t i = 0; i < l.m; ++i) {
            for (uint32_t bj = 0; bj < n_blocks; ++bj) {
                const uint8_t e = lt::DeriveMatExpandMxScale(l.extract_prf, i, bj);
                ++pub.n_prf_calls;
                const uint64_t off = base + static_cast<uint64_t>(i) * l.n +
                                     static_cast<uint64_t>(bj) * kRCMxBlockLen;
                std::memset(pub.sel.data() + off, s, kRCMxBlockLen);
                std::memset(pub.scale_e.data() + off, e, kRCMxBlockLen);
            }
        }
    }

    // Leaf region: selectors + canonical expansion (plain-SHA XOF).
    const gkr_air::TableTM tm;
    for (size_t lf = 0; lf < layout.leaves.size(); ++lf) {
        const EpisodeAirLeaf& leaf = layout.leaves[lf];
        LeafExpansion ex;
        if (!NativeExpandLeaf(leaf.seed, leaf.rows, leaf.cols, tm, ex, why)) return false;
        pub.n_xof_digests += ex.n_xof_digests;
        const uint64_t abs = rl.leaf_base[lf];
        const uint64_t rel = abs - rl.elem_total;
        const size_t count = ex.val.size();
        std::memset(pub.sel.data() + abs, 3, count);
        std::memcpy(pub.leaf_val.data() + rel, ex.val.data(), count);
        std::memcpy(pub.scale_e.data() + abs, ex.e.data(), count);
        if (want_prover_data) {
            std::memcpy(pub.leaf_mu.data() + rel, ex.mu.data(), count);
            std::memcpy(pub.leaf_nib.data() + rel, ex.nib.data(), count);
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Prover-side per-element sampler data (TraceTile over the carried witness).
// ---------------------------------------------------------------------------
struct EpisodeElemData {
    std::vector<uint8_t> nib;  // accepted (mixed) nibble per output element
    std::vector<int8_t> mu;    // T_M mantissa per output element
};

bool BuildProverElemData(const EpisodeAirLayout& layout, const EpisodeAirWitness& wit,
                         const EpisodeRowLayout& rl, EpisodeElemData& ed, std::string& why)
{
    ed.nib.assign(rl.elem_total, 0);
    ed.mu.assign(rl.elem_total, 0);
    for (size_t li = 0; li < layout.layers.size(); ++li) {
        const EpisodeAirLayer& l = layout.layers[li];
        const EpisodeAirLayerWitness& w = wit.layers[li];
        const size_t mn = static_cast<size_t>(l.m) * l.n;
        if (w.Y == nullptr || w.extract_in == nullptr || w.extract_out == nullptr ||
            w.Y->size() != mn || w.extract_in->size() != mn || w.extract_out->size() != mn) {
            why = "layer witness shape";
            return false;
        }
        if (l.fwd_residual && (w.A == nullptr || w.A->size() != mn)) {
            why = "fwd residual witness shape";
            return false;
        }
        const uint64_t base = rl.layer_base[li];
        const uint32_t n_blocks = l.n / kRCMxBlockLen;
        for (uint32_t i = 0; i < l.m; ++i) {
            for (uint32_t bj = 0; bj < n_blocks; ++bj) {
                gkr_air::TilePublic pub;
                pub.prf_key = l.extract_prf;
                pub.i = i;
                pub.bj = bj;
                std::array<int64_t, kRCMxBlockLen> in{};
                const size_t off = static_cast<size_t>(i) * l.n +
                                   static_cast<size_t>(bj) * kRCMxBlockLen;
                for (uint32_t t = 0; t < kRCMxBlockLen; ++t) in[t] = (*w.extract_in)[off + t];
                const gkr_air::TileWitness tw = gkr_air::TraceTile(pub, in);
                for (const auto& c : tw.cands) {
                    if (!c.acc) continue;
                    const uint64_t g = base + off + c.pos;
                    ed.nib[g] = c.mixed;
                    ed.mu[g] = c.mu;
                }
            }
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Shard constraint system (max composed degree 2 ⇒ quotient length N−1).
// ---------------------------------------------------------------------------
using CS = aq::AirConstraintSystem<Fp3>;

CS BuildEpisodeShardConstraints(uint32_t n_rows, const Fp3& gamma, const Fp3& alpha,
                                std::vector<std::pair<uint32_t, std::vector<Fp3>>> pre)
{
    CS cs;
    cs.n_rows = n_rows;
    cs.n_columns = kEpNumCols;
    cs.preprocessed = std::move(pre);
    cs.preprocessed_pin_ood = true;

    auto add = [&](const char* name, aq::AirKind kind, uint32_t deg,
                   std::function<Fp3(const std::vector<Fp3>&, const std::vector<Fp3>&)> ev) {
        aq::AirConstraint<Fp3> c;
        c.name = name;
        c.kind = kind;
        c.alg_degree = deg;
        c.eval = std::move(ev);
        cs.constraints.push_back(std::move(c));
    };
    const Fp3 one = Fp3::One();

    // Nibble-bit booleanity.
    for (uint32_t b = 0; b < 4; ++b) {
        const uint32_t col = kEpNb0 + b;
        add("ep.nb.bool", aq::AirKind::kEverywhere, 2,
            [col](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
                return gf::Mul(r[col], gf::Sub(r[col], Fp3::One()));
            });
    }
    // E2M1 acceptance — AirAcceptPoly factored through committed aux cells:
    //   nbAnd01 := b0·b1                                   (degree-2 definition)
    //   inner   := (1−b3)·b0 + b3·(1−b1) + b3·nbAnd01      (degree-2 definition)
    //   accept  ⇔ (1−b2)·inner = 0                          (degree-2 rule)
    // (rejected(n) = (1−b2)·inner with inner = b3 ? (1−b1+b0·b1) : b0 — the
    //  exact AirAcceptPoly factorization; cross-checked in the tests.)
    add("ep.accept.and01", aq::AirKind::kEverywhere, 2,
        [](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            return gf::Sub(r[kEpNbAnd01], gf::Mul(r[kEpNb0], r[kEpNb1]));
        });
    add("ep.accept.inner", aq::AirKind::kEverywhere, 2,
        [one](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            const Fp3 inner = gf::Add(
                gf::Mul(gf::Sub(one, r[kEpNb3]), r[kEpNb0]),
                gf::Add(gf::Mul(r[kEpNb3], gf::Sub(one, r[kEpNb1])),
                        gf::Mul(r[kEpNb3], r[kEpNbAnd01])));
            return gf::Sub(r[kEpRejInner], inner);
        });
    add("ep.accept", aq::AirKind::kEverywhere, 2,
        [one](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            return gf::Mul(gf::Sub(one, r[kEpNb2]), r[kEpRejInner]);
        });
    // Dequant val = mu·2^e = mu·(1+e0)(1+3·e1), split through muSc = mu·(1+e0).
    add("ep.dequant.musc", aq::AirKind::kEverywhere, 2,
        [one](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            return gf::Sub(r[kEpMuSc], gf::Mul(r[kEpMu], gf::Add(one, r[kEpScaleE0])));
        });
    add("ep.dequant", aq::AirKind::kEverywhere, 2,
        [one](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            const Fp3 s1 = gf::Add(one, gf::Mul(F3u(3), r[kEpScaleE1]));
            return gf::Sub(r[kEpVal], gf::Mul(r[kEpMuSc], s1));
        });
    // §5.7 extract_in binding: ein = Y (+ A on fwd-residual rows).
    add("ep.ein.bind", aq::AirKind::kEverywhere, 2,
        [](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            return gf::Sub(gf::Mul(r[kEpSelElem], gf::Sub(r[kEpEin], r[kEpY])),
                           gf::Mul(r[kEpSelFwd], r[kEpA]));
        });
    // Leaf-operand seed binding against the preprocessed canonical expansion.
    add("ep.leaf.seedbind", aq::AirKind::kEverywhere, 2,
        [](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            return gf::Mul(r[kEpSelLeaf], gf::Sub(r[kEpVal], r[kEpLeafExpect]));
        });
    // T_M LogUp membership (running-sum transition system).
    const Fp3 g2 = gf::Mul(gamma, gamma);
    add("ep.logup.phi", aq::AirKind::kEverywhere, 2,
        [gamma, g2, alpha](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            Fp3 w = gamma;  // acc coordinate is 1 on every active row
            for (uint32_t b = 0; b < 4; ++b) {
                w = gf::Add(w, gf::Mul(F3u(1ull << b), r[kEpNb0 + b]));
            }
            w = gf::Add(w, gf::Mul(g2, r[kEpMu]));
            return gf::Sub(gf::Mul(r[kEpPhi], gf::Sub(alpha, w)),
                           gf::Add(r[kEpSelElem], r[kEpSelLeaf]));
        });
    add("ep.logup.psi", aq::AirKind::kEverywhere, 2,
        [alpha](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            return gf::Sub(gf::Mul(r[kEpPsi], gf::Sub(alpha, r[kEpTfp])), r[kEpM]);
        });
    add("ep.logup.S.trans", aq::AirKind::kTransition, 1,
        [](const std::vector<Fp3>& r, const std::vector<Fp3>& n) {
            return gf::Sub(n[kEpS], gf::Add(r[kEpS], gf::Sub(r[kEpPhi], r[kEpPsi])));
        });
    add("ep.logup.S.first", aq::AirKind::kFirstRow, 1,
        [](const std::vector<Fp3>& r, const std::vector<Fp3>&) { return r[kEpS]; });
    add("ep.logup.S.last", aq::AirKind::kLastRow, 1,
        [](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            return gf::Add(r[kEpS], gf::Sub(r[kEpPhi], r[kEpPsi]));
        });
    // GEMM sumcheck endpoint gf = a·b over the public per-layer claims.
    add("ep.gemm.endpoint", aq::AirKind::kEverywhere, 2,
        [](const std::vector<Fp3>& r, const std::vector<Fp3>&) {
            return gf::Sub(r[kEpGemmGf], gf::Mul(r[kEpGemmA], r[kEpGemmB]));
        });
    return cs;
}

// ---------------------------------------------------------------------------
// Shard column assembly.
// ---------------------------------------------------------------------------

/** Public per-layer GEMM claim columns (kEpGemmGf/A/B) for shard s — cheap
 *  arithmetic from the proof-public claims, no SHA. Non-zero only where the
 *  claim rows land (shard 0 by the BuildRowLayout gate). */
std::array<std::vector<Fp3>, 3> ShardGemmColumns(const EpisodeAirLayout& layout, uint32_t N,
                                                 uint32_t s)
{
    const uint64_t row0 = static_cast<uint64_t>(s) * N;
    std::array<std::vector<Fp3>, 3> out{std::vector<Fp3>(N, Fp3::Zero()),
                                        std::vector<Fp3>(N, Fp3::Zero()),
                                        std::vector<Fp3>(N, Fp3::Zero())};
    for (size_t gi = 0; gi < layout.gemm.size(); ++gi) {
        if (gi < row0 || gi >= row0 + N) continue;
        const size_t r = gi - row0;
        out[0][r] = layout.gemm[gi].gf;
        out[1][r] = layout.gemm[gi].a;
        out[2][r] = layout.gemm[gi].b;
    }
    return out;
}

/** γ-independent preprocessed slices for shard s (columns 0..kEpPreRootCols−1). */
std::vector<std::pair<uint32_t, std::vector<Fp3>>> ShardPreprocessed(
    const EpisodeAirLayout& layout, const EpisodePublicData& pub, uint32_t s)
{
    const uint32_t N = pub.rl.shard_rows;
    const uint64_t row0 = static_cast<uint64_t>(s) * N;
    std::vector<std::pair<uint32_t, std::vector<Fp3>>> pre;
    for (uint32_t c : {kEpSelElem, kEpSelFwd, kEpSelLeaf, kEpScaleE0, kEpScaleE1, kEpLeafExpect,
                       kEpGemmGf, kEpGemmA, kEpGemmB}) {
        pre.emplace_back(c, std::vector<Fp3>(N, Fp3::Zero()));
    }
    auto& sel_elem = pre[0].second;
    auto& sel_fwd = pre[1].second;
    auto& sel_leaf = pre[2].second;
    auto& e0 = pre[3].second;
    auto& e1 = pre[4].second;
    auto& expect = pre[5].second;
    for (uint32_t r = 0; r < N; ++r) {
        const uint64_t g = row0 + r;
        if (g >= pub.rl.total) break;
        const uint8_t sv = pub.sel[g];
        if (sv == 1 || sv == 2) sel_elem[r] = Fp3::One();
        if (sv == 2) sel_fwd[r] = Fp3::One();
        if (sv == 3) {
            sel_leaf[r] = Fp3::One();
            expect[r] = F3s(pub.leaf_val[g - pub.rl.elem_total]);
        }
        const uint8_t e = pub.scale_e[g];
        if (e & 1u) e0[r] = Fp3::One();
        if (e & 2u) e1[r] = Fp3::One();
    }
    std::array<std::vector<Fp3>, 3> gemm = ShardGemmColumns(layout, N, s);
    pre[6].second = std::move(gemm[0]);
    pre[7].second = std::move(gemm[1]);
    pre[8].second = std::move(gemm[2]);
    return pre;
}

// ---------------------------------------------------------------------------
// Stage A: P_root — SHA256d Merkle aggregation of the per-shard preprocessed
// slice roots. Leaf s = tagged digest of shard s's kEpPreRootCols column
// roots; inner nodes use the Fri3 node hash; leaves padded to a power of two
// with the zero hash.
// ---------------------------------------------------------------------------

uint256 PreLeafDigest(uint32_t s, const std::vector<uint256>& roots)
{
    return aq::AirChallengeDigest(uint256{}, "ep_pre_leaf", roots, {s});
}

uint32_t PreTreeLeaves(uint32_t n_shards)
{
    return FriNextPow2(std::max<uint32_t>(1u, n_shards));
}

/** Full tree levels over the (zero-padded) leaf digests. */
std::vector<std::vector<uint256>> BuildPreTree(const std::vector<uint256>& leaves,
                                               uint32_t n_leaves)
{
    std::vector<std::vector<uint256>> levels;
    std::vector<uint256> level(n_leaves, uint256{});
    std::copy(leaves.begin(), leaves.end(), level.begin());
    levels.push_back(level);
    while (level.size() > 1) {
        std::vector<uint256> next;
        next.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            next.push_back(aq::AirFriBackend<Fp3>::NodeHash(level[i], level[i + 1]));
        }
        levels.push_back(next);
        level = std::move(next);
    }
    return levels;
}

std::vector<uint256> PreTreePath(const std::vector<std::vector<uint256>>& levels, uint32_t index)
{
    std::vector<uint256> siblings;
    uint32_t idx = index;
    for (size_t li = 0; li + 1 < levels.size(); ++li) {
        siblings.push_back(levels[li][idx ^ 1u]);
        idx >>= 1;
    }
    return siblings;
}

bool VerifyPreOpening(const uint256& leaf, uint32_t index, const std::vector<uint256>& siblings,
                      const uint256& p_root, uint32_t n_leaves)
{
    if (n_leaves == 0 || (n_leaves & (n_leaves - 1)) != 0 || index >= n_leaves) return false;
    uint32_t depth = 0;
    for (uint32_t t = n_leaves; t > 1; t >>= 1) ++depth;
    if (siblings.size() != depth) return false;
    uint256 node = leaf;
    uint32_t idx = index;
    for (const uint256& sib : siblings) {
        node = (idx & 1u) ? aq::AirFriBackend<Fp3>::NodeHash(sib, node)
                          : aq::AirFriBackend<Fp3>::NodeHash(node, sib);
        idx >>= 1;
    }
    return node == p_root;
}

/** Commit the preprocessed slices of an already-built EpisodePublicData
 *  (shared by the public producer and the prover). n_coeffs must be the
 *  shard commitment size (FriNextPow2(max(N, QuotientLen))). */
EpisodePreprocessedCommit CommitPreprocessedFromPub(const EpisodeAirLayout& layout,
                                                    const EpisodePublicData& pub,
                                                    uint32_t n_coeffs)
{
    EpisodePreprocessedCommit out;
    out.n_shards = pub.rl.n_shards;
    out.shard_roots.resize(out.n_shards);
    std::vector<uint256> leaves(out.n_shards);
    for (uint32_t s = 0; s < out.n_shards; ++s) {
        const auto pre = ShardPreprocessed(layout, pub, s);
        out.shard_roots[s].reserve(kEpPreRootCols);
        for (uint32_t c = 0; c < kEpPreRootCols; ++c) {
            out.shard_roots[s].push_back(
                aq::AirCommittedValuesRoot<Fp3>(pre[c].second, n_coeffs));
        }
        leaves[s] = PreLeafDigest(s, out.shard_roots[s]);
    }
    const uint32_t n_leaves = PreTreeLeaves(out.n_shards);
    const std::vector<std::vector<uint256>> levels = BuildPreTree(leaves, n_leaves);
    out.p_root = levels.back()[0];
    out.openings.resize(out.n_shards);
    for (uint32_t s = 0; s < out.n_shards; ++s) out.openings[s] = PreTreePath(levels, s);
    out.ok = true;
    return out;
}

/** Canonical T_M fingerprint table column for a given γ (rows ≥ 16 repeat
 *  row 0; the multiplicity column is zero there). */
std::vector<Fp3> TfpColumn(const gkr_air::TableTM& tm, const Fp3& gamma, uint32_t N)
{
    const Fp3 g2 = gf::Mul(gamma, gamma);
    std::vector<Fp3> t(N);
    for (uint32_t j = 0; j < N; ++j) {
        const uint32_t n = (j < 16) ? j : 0;
        t[j] = gf::Add(F3u(n), gf::Add(gf::Mul(gamma, F3u(tm.acc[n])),
                                       gf::Mul(g2, F3s(tm.mu[n]))));
    }
    return t;
}

/** Prover-side per-row scalar data of one shard (before the LogUp epoch). */
struct ShardAux {
    std::vector<uint8_t> active;  // selElem || selLeaf
    std::vector<uint8_t> nib;
    std::vector<int8_t> mu;
};

void FillShardWitnessColumns(const EpisodeAirLayout& layout, const EpisodePublicData& pub,
                             const EpisodeElemData& ed, const EpisodeAirWitness& wit,
                             uint32_t s, std::vector<std::vector<Fp3>>& cols, ShardAux& aux)
{
    const uint32_t N = pub.rl.shard_rows;
    const uint64_t row0 = static_cast<uint64_t>(s) * N;
    const EpisodeRowLayout& rl = pub.rl;
    aux.active.assign(N, 0);
    aux.nib.assign(N, 0);
    aux.mu.assign(N, 0);

    for (uint32_t r = 0; r < N; ++r) {
        const uint64_t g = row0 + r;
        if (g >= rl.total) break;
        const uint8_t sv = pub.sel[g];
        if (sv == 0) continue;
        aux.active[r] = 1;
        int8_t mu = 0;
        uint8_t nib = 0;
        if (sv == 1 || sv == 2) {
            // Element row: locate the layer (layer_base is sorted).
            const size_t li =
                static_cast<size_t>(std::upper_bound(rl.layer_base.begin(), rl.layer_base.end(), g) -
                                    rl.layer_base.begin()) - 1;
            const size_t idx = static_cast<size_t>(g - rl.layer_base[li]);
            const EpisodeAirLayerWitness& w = wit.layers[li];
            cols[kEpVal][r] = F3s((*w.extract_out)[idx]);
            cols[kEpY][r] = F3s((*w.Y)[idx]);
            cols[kEpEin][r] = F3s((*w.extract_in)[idx]);
            if (sv == 2) cols[kEpA][r] = F3s((*w.A)[idx]);
            nib = ed.nib[g];
            mu = ed.mu[g];
        } else {
            const size_t lf =
                static_cast<size_t>(std::upper_bound(rl.leaf_base.begin(), rl.leaf_base.end(), g) -
                                    rl.leaf_base.begin()) - 1;
            const size_t idx = static_cast<size_t>(g - rl.leaf_base[lf]);
            const uint64_t rel = g - rl.elem_total;
            cols[kEpVal][r] = F3s(wit.leaf_committed[lf][idx]);
            nib = pub.leaf_nib[rel];
            mu = pub.leaf_mu[rel];
        }
        aux.nib[r] = nib;
        aux.mu[r] = mu;
        cols[kEpMu][r] = F3s(mu);
        for (uint32_t b = 0; b < 4; ++b) {
            if ((nib >> b) & 1u) cols[kEpNb0 + b][r] = Fp3::One();
        }
        // Auxiliary degree-reduction cells (definitional; honest values).
        const uint8_t b0 = nib & 1u, b1 = (nib >> 1) & 1u, b3 = (nib >> 3) & 1u;
        cols[kEpNbAnd01][r] = F3u(b0 & b1);
        const uint8_t inner = static_cast<uint8_t>(b3 ? (1u - b1 + b1 * b0) : b0);
        cols[kEpRejInner][r] = F3u(inner);
        const uint8_t e = pub.scale_e[g];
        cols[kEpMuSc][r] = F3s(static_cast<int64_t>(mu) * ((e & 1u) ? 2 : 1));
    }
}

bool FillShardLogUp(const gkr_air::TableTM& tm, const Fp3& gamma, const Fp3& alpha,
                    uint32_t N, const ShardAux& aux, std::vector<std::vector<Fp3>>& cols,
                    bool force, std::string& why)
{
    const Fp3 g2 = gf::Mul(gamma, gamma);
    const std::vector<Fp3> tfp = TfpColumn(tm, gamma, N);
    cols[kEpTfp] = tfp;

    std::array<uint64_t, 16> mult{};
    for (uint32_t r = 0; r < N; ++r) {
        if (!aux.active[r]) continue;
        const Fp3 w = gf::Add(F3u(aux.nib[r]),
                              gf::Add(gamma, gf::Mul(g2, F3s(aux.mu[r]))));
        const Fp3 den = gf::Sub(alpha, w);
        if (gf::IsZero(den)) {
            if (!force) {
                why = "alpha collides with a witness key (fail closed)";
                return false;
            }
            continue;
        }
        cols[kEpPhi][r] = gf::Inv(den);
        mult[aux.nib[r] & 0x0F] += 1;
    }
    for (uint32_t j = 0; j < 16; ++j) {
        const Fp3 den = gf::Sub(alpha, tfp[j]);
        if (gf::IsZero(den)) {
            why = "alpha collides with a table key (fail closed)";
            return false;
        }
        cols[kEpM][j] = F3u(mult[j]);
        cols[kEpPsi][j] = gf::Mul(cols[kEpM][j], gf::Inv(den));
    }
    for (uint32_t r = 1; r < N; ++r) {
        cols[kEpS][r] = gf::Add(cols[kEpS][r - 1],
                                gf::Sub(cols[kEpPhi][r - 1], cols[kEpPsi][r - 1]));
    }
    return true;
}

/** Per-shard FS seed. Stage A: absorbs P_root, binding the preprocessed
 *  commitment into every shard's transcript. */
uint256 ShardSeed(const uint256& fs_seed, const uint256& p_root, uint32_t s, uint32_t n_shards)
{
    return aq::AirChallengeDigest(fs_seed, "ep_shard", {p_root}, {s, n_shards});
}

Fp3 ShardChallenge(const uint256& fs_seed, const uint256& p_root, const char* label,
                   const std::vector<uint256>& roots, uint32_t shard_rows, uint32_t s,
                   uint32_t n_shards)
{
    std::vector<uint256> all;
    all.reserve(roots.size() + 1);
    all.push_back(p_root);
    all.insert(all.end(), roots.begin(), roots.end());
    const uint256 d = aq::AirChallengeDigest(fs_seed, label, all,
                                             {shard_rows, s, n_shards});
    return aq::AirField<Fp3>::FromChallenge(d.data());
}

} // namespace

// ===========================================================================
// Stage-A producer (public API).
// ===========================================================================

EpisodePreprocessedCommit CommitEpisodePreprocessed(const EpisodeAirLayout& layout)
{
    EpisodePreprocessedCommit out;
    EpisodePublicData pub;
    if (!BuildEpisodePublicData(layout, /*want_prover_data=*/false, pub, out.note)) return out;
    const uint32_t N = pub.rl.shard_rows;
    const CS cs_probe = BuildEpisodeShardConstraints(N, Fp3::Zero(), Fp3::Zero(), {});
    const uint32_t n_coeffs = FriNextPow2(std::max(N, cs_probe.QuotientLen()));
    return CommitPreprocessedFromPub(layout, pub, n_coeffs);
}

// ===========================================================================
// Prover.
// ===========================================================================

EpisodeAirProveResult ProveEpisodeAirQuotient(const EpisodeAirLayout& layout,
                                              const EpisodeAirWitness& witness,
                                              const uint256& fs_seed,
                                              const EpisodeAirProveOptions& opt)
{
    EpisodeAirProveResult res;
    const auto t0 = Clock::now();

    if (witness.layers.size() != layout.layers.size() ||
        witness.leaf_committed.size() != layout.leaves.size()) {
        res.note = "witness/layout arity mismatch";
        return res;
    }
    for (size_t lf = 0; lf < layout.leaves.size(); ++lf) {
        const auto& l = layout.leaves[lf];
        if (witness.leaf_committed[lf].size() != static_cast<size_t>(l.rows) * l.cols) {
            res.note = "leaf committed shape";
            return res;
        }
    }

    EpisodePublicData pub;
    if (!BuildEpisodePublicData(layout, /*want_prover_data=*/true, pub, res.note)) return res;
    EpisodeElemData ed;
    if (!BuildProverElemData(layout, witness, pub.rl, ed, res.note)) return res;

    const gkr_air::TableTM tm;
    const uint32_t N = pub.rl.shard_rows;
    res.n_rows = pub.rl.total;
    res.n_shards = pub.rl.n_shards;

    // Stage A: commit the preprocessed columns ONCE per episode. P_root feeds
    // every shard's FS seed, so it must exist before any shard is proven.
    const CS cs_probe = BuildEpisodeShardConstraints(N, Fp3::Zero(), Fp3::Zero(), {});
    const uint32_t n_coeffs = FriNextPow2(std::max(N, cs_probe.QuotientLen()));
    EpisodePreprocessedCommit pc = CommitPreprocessedFromPub(layout, pub, n_coeffs);
    if (!pc.ok) {
        res.note = pc.note;
        return res;
    }
    res.proof.p_root = pc.p_root;
    res.proof.p_shard_roots = pc.shard_roots;
    res.proof.p_openings = std::move(pc.openings);
    const uint256& p_root = res.proof.p_root;

    aq::AirProveOptions aopt;
    aopt.force_commit_on_inexact = opt.force_commit_on_violation;
    aopt.quotient_len_override = opt.quotient_len_override;

    for (uint32_t s = 0; s < pub.rl.n_shards; ++s) {
        std::vector<std::vector<Fp3>> cols(kEpNumCols, std::vector<Fp3>(N, Fp3::Zero()));
        auto pre = ShardPreprocessed(layout, pub, s);
        for (const auto& [ci, values] : pre) cols[ci] = values;
        ShardAux aux;
        FillShardWitnessColumns(layout, pub, ed, witness, s, cols, aux);

        // Epoch-1 FS: γ, α from the committed epoch-1 column roots (+ P_root).
        // The preprocessed slice roots are already committed — reuse them.
        std::vector<uint256> epoch1_roots(kEpEpoch1Cols);
        for (uint32_t c = 0; c < kEpEpoch1Cols; ++c) {
            epoch1_roots[c] = (c < kEpPreRootCols)
                                  ? pc.shard_roots[s][c]
                                  : aq::AirCommittedValuesRoot<Fp3>(cols[c], n_coeffs);
        }
        const Fp3 gamma =
            ShardChallenge(fs_seed, p_root, "ep_gamma", epoch1_roots, N, s, pub.rl.n_shards);
        const Fp3 alpha =
            ShardChallenge(fs_seed, p_root, "ep_alpha", epoch1_roots, N, s, pub.rl.n_shards);
        if (!FillShardLogUp(tm, gamma, alpha, N, aux, cols, opt.force_commit_on_violation,
                            res.note)) {
            return res;
        }

        pre.emplace_back(static_cast<uint32_t>(kEpTfp), cols[kEpTfp]);
        CS cs = BuildEpisodeShardConstraints(N, gamma, alpha, std::move(pre));
        const aq::AirQuotientProveResult<Fp3> pr = aq::AirQuotientProve<Fp3>(
            cs, cols, ShardSeed(fs_seed, p_root, s, pub.rl.n_shards), aopt);
        if (!pr.ok) {
            res.note = "shard " + std::to_string(s) + ": " + pr.note;
            return res;
        }
        res.division_exact = res.division_exact && pr.division_exact;
        res.proof.shards.push_back(std::move(pr.proof));
    }

    res.ok = true;
    res.prove_s = Secs(t0);
    res.note = res.division_exact ? "exact division on every shard"
                                  : "FORCED commit with constraint violations";
    return res;
}

// ===========================================================================
// Verifier — O(Q) per shard; NO row scan of the per-row rules.
// ===========================================================================

bool VerifyEpisodeAirQuotient(const EpisodeAirLayout& layout, const EpisodeAirProof& proof,
                              const uint256& fs_seed, std::string* why,
                              EpisodeAirVerifyStats* stats)
{
    auto fail = [&](const std::string& w) {
        if (why) *why = w;
        return false;
    };
    const auto t_pre = Clock::now();
    EpisodePublicData pub;
    {
        std::string w;
        if (!BuildEpisodePublicData(layout, /*want_prover_data=*/false, pub, w)) return fail(w);
    }
    if (stats) {
        stats->preprocess_s = Secs(t_pre);
        stats->n_shards = pub.rl.n_shards;
        stats->n_rows = pub.rl.total;
    }
    if (proof.shards.size() != pub.rl.n_shards) return fail("shard count mismatch");

    const gkr_air::TableTM tm;
    const uint32_t N = pub.rl.shard_rows;
    const auto t_q = Clock::now();
    for (uint32_t s = 0; s < pub.rl.n_shards; ++s) {
        const auto& batch = proof.shards[s].batch;
        if (batch.columns.size() != kEpNumCols + 1) {
            return fail("shard " + std::to_string(s) + ": column count");
        }
        std::vector<uint256> epoch1_roots(kEpEpoch1Cols);
        for (uint32_t c = 0; c < kEpEpoch1Cols; ++c) epoch1_roots[c] = batch.columns[c].root;
        const Fp3 gamma =
            ShardChallenge(fs_seed, "ep_gamma", epoch1_roots, N, s, pub.rl.n_shards);
        const Fp3 alpha =
            ShardChallenge(fs_seed, "ep_alpha", epoch1_roots, N, s, pub.rl.n_shards);

        auto pre = ShardPreprocessed(layout, pub, s);
        pre.emplace_back(static_cast<uint32_t>(kEpTfp), TfpColumn(tm, gamma, N));
        const CS cs = BuildEpisodeShardConstraints(N, gamma, alpha, std::move(pre));
        std::string w;
        if (!aq::AirQuotientVerify<Fp3>(cs, proof.shards[s],
                                        ShardSeed(fs_seed, s, pub.rl.n_shards), &w)) {
            return fail("shard " + std::to_string(s) + ": " + w);
        }
    }
    if (stats) stats->quotient_s = Secs(t_q);
    if (why) *why = "episode AIR quotient ok";
    return true;
}

} // namespace matmul::v4::rc::air_episode
