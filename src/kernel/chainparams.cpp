// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_rc.h> // RCEpisodeParams factories (n_ctx hash-bound guardrail)
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <numeric>
#include <cstring>
#include <iterator>


using namespace util::hex_literals;

// Workaround MSVC bug triggering C7595 when calling consteval constructors in
// initializer lists.
// A fix may be on the way:
// https://developercommunity.visualstudio.com/t/consteval-conversion-function-fails/1579014
#if defined(_MSC_VER)
auto consteval_ctor(auto&& input) { return input; }
#else
#define consteval_ctor(input) (input)
#endif

static constexpr int32_t BTX_SHIELDED_SUNSET_HEIGHT{125'000};
static constexpr int32_t BTX_SHIELDED_POOL_CREDIT_DISABLE_HEIGHT{BTX_SHIELDED_SUNSET_HEIGHT};
static constexpr int32_t BTX_SHIELDED_DIRECT_SEND_PUBLIC_FLOW_DISABLE_HEIGHT{128'000};
// Future consensus-bundle activation point for post-sunset zero-output V2_SEND
// exact exits. Keep disabled until the release that coordinates this with the
// other shielded-exit consensus changes. When that height is chosen, set this
// constant for the production-like networks and keep it >= BTX_SHIELDED_SUNSET_HEIGHT.
static constexpr int32_t BTX_SHIELDED_V2_SEND_ZERO_OUTPUT_EXIT_ACTIVATION_HEIGHT{
    std::numeric_limits<int32_t>::max()};
static constexpr int32_t BTX_EMPTY_BLOCK_SUBSIDY_PENALTY_HEIGHT{130'000};
static constexpr int32_t BTX_V03210_HARDENING_HEIGHT{130'500};
static constexpr int32_t BTX_V03211_HARDENING_HEIGHT{132'000};
static constexpr int32_t BTX_SHIELDED_UNSHIELD_VELOCITY_END_HEIGHT{135'000};
static constexpr CAmount BTX_SHIELDED_UNSHIELD_VELOCITY_MIN_CAP{10'000 * COIN};
// Content-elimination hard fork (inscription/NFT/token meta-protocol removal).
// Keep the 0.33.2 consensus changes on one coordinated release flag day.
// PR #88 is integrated for review and regtest exercise only. Its historical
// spend/UTXO compatibility and remaining content channels are not yet cleared
// for a production flag day.
static constexpr int32_t BTX_CONTENT_ELIMINATION_HEIGHT{std::numeric_limits<int32_t>::max()};

// Future ENC_RC Profile-2 ASERT constants (design §5/§6). Epoch A activates
// Profile 1 only; every Profile-2/DRLT/coupled public height remains disabled.
// A later proof-authoritative Profile-2 release must provide its own
// independently reviewed height and activate this rescale atomically.
// Per-nonce work rises
// by the EXACT episode-MAC ratio datacenter/base, so the difficulty target must
// LOOSEN by that ratio at the activation height to hold the 90 s interval. After
// the fused-FFN redesign BOTH profiles use the fused FFN, so the base grew too.
// The datacenter b_seq is then raised (the free compute lever — see matmul_v4_rc.h)
// to restore the intended ~16× differential against the heavier fused base; the
// MAC counts factor exactly as 2^37·k:
//   datacenter = 2^37·16422 = 2 257 022 493 917 184  (b_seq=87552, L=24, rounds=8)
//   base       = 2^37·1027   =   141 149 805 215 744
// so the ratio is EXACTLY 16422/1027 = 15.990… (1027=13·79, 16422=2·3·7·17·23, coprime).
// Exact, not modeled — block interval is continuous across the cutover, and the
// ASERT-ratio guardrail below recomputes reduce(MAC_dc,MAC_base) and asserts it
// equals this constant, so the two can never drift when dims are retuned.
// On-silicon confirmation still wanted (effective value is the datacenter miner's
// real nonce/s, MFU-dependent, not the raw FLOP ratio). Takes effect together with
// a finite profile-2 activation height (coupled trio asserted below).
static constexpr int64_t kRCDatacenterAsertRescaleNum{16422};
static constexpr int64_t kRCDatacenterAsertRescaleDen{1027};

// EPOCH-A PROFILE-1 ONE-TIME ASERT POLICY COEFFICIENT — RECONFIRM THE
// LAUNCH-COHORT ENVELOPE ON THE EXACT FINAL BINARY BEFORE RELEASE.
//
// WHAT THIS NUMBER IS. It is the PRE-GATE NONCE-ATTEMPT-RATE RATIO
//     C = N / M
// where N is the v3 miner's raw nonce attempts per second (sigma is computed
// for EVERY nonce) and M is the Profile-1 RC episode rate per second.
//
// It is NOT the realized difficulty loosen k, NOT the post-gate digest-trial
// rate ratio R_eff/R_rc, and NOT the v3 matmul-only rate R_M. Those are
// different quantities and substituting one for another is not a rounding
// error -- see the hazard note below.
//
// DERIVATION. v3 needs both gates, Profile 1 keeps only the digest gate:
//     lambda_v3 = N * q * p        with q = 2^epsilon * p
//     lambda_rc = M * p_rc
// Continuity (lambda_rc = lambda_v3) gives p_rc = p * q * (N/M), which is
// exactly what DeriveMatMulEpochATransitionTarget computes. The realized
// loosen is the OUTCOME k = p_rc/p = q * C, not an input.
//
// MEASURED, same-silicon, two vendors
// (doc/evidence/asert-two-rig-calibration-2026-08-03):
//     CUDA sm_120 : N/M = 6.93e9  -> k ~ 119'783
//     Metal m4    : N/M = 1.15e9  -> k ~  19'900
// The 5.8x spread is a hardware-mix property. Installed at the CUDA figure
// because the loss function is asymmetric: under-loosening costs linearly in
// the error while over-loosening costs only logarithmically, so biasing toward
// the faster observed miner is the cheap direction.
//
// HAZARD, and the reason this comment is long. An earlier revision of this
// file installed a SATURATED uint32 value and described the field as a
// "throughput ratio", while the calibration evidence recommended installing k.
// Installing k (about 1.2e5) as C would yield a realized loosen of q*k ~ 2.1
// instead of the intended ~1.2e5 -- under-loosening by 1/q ~ 57'864x, which at
// a 90 s target is a first block expected in roughly 60 DAYS. The uint32
// saturation is also gone: the Epoch-A path does exact wide arithmetic and now
// reduces through ReduceRescaleRatioToU64, so the measured value is installed
// directly rather than clipped.
//
// matmul_unified_activation_tests pins a fixed vector at the calibration nBits
// asserting the realized k, so a future value of the wrong KIND fails a test
// rather than the chain.
// RATIFIED POLICY COEFFICIENT, not a reproduced measurement. Say so plainly here,
// because the previous comment implied this number came out of a campaign.
//
// The first assembled schema-4 corpus now exists:
// doc/evidence/epoch-a-asert-schema4-cuda-2026-08-04. Measured on the CUDA
// launch cohort at this freeze it derives 4'007'014'530 -- parent 331'891'937
// attempts/s over 5 samples, RC 12.073250614 s over 8 episodes, bound to exact
// binaries and revision. The value installed here is 1.730x that envelope.
//
// It is installed deliberately high because the error is asymmetric: too low
// risks slow or stalled blocks at the fork, too high yields temporarily fast
// blocks that ASERT corrects within an epoch. Two further reasons not to lower
// it to the measured figure:
//
//  - the historical campaign behind this constant measured ~215.36M attempts/s
//    and ~32.18 s per RC episode on a different device class, and this cohort's
//    own RC timing has appeared in two clusters (~12 s and ~32 s) across builds
//    on the same GPU with no resolved explanation. The installed value lies
//    between the coefficients those clusters imply;
//  - this exact constant is NOT reproducible from the retained historical
//    artifacts, which yield 6'898'853'852, and those artifacts are classified
//    historical and non-authorizing.
//
// So: the corpus establishes a measured lower bound and binds it to real
// evidence; this separate ratified coefficient deliberately sits above it.
// Recalibrate if the representative launch cohort changes.
static constexpr int64_t kRCEpochAAsertRescaleNum{6931159304};
static constexpr int64_t kRCEpochAAsertRescaleDen{1};

// Release-candidate value, but a technically live consensus instruction if
// this source is merged: mainnet will enforce Epoch A at this height. The
// consolidated v0.33.2 activation review must recompute it once against the
// live mainnet tip before the exact-final CUDA+Metal evidence build is frozen.
// Keep all three Epoch-A heights bound to this single constant so that a later
// update cannot create a digest-only v4/BMX4C interval.
static constexpr int32_t BTX_MATMUL_V47_EPOCH_A_HEIGHT{185'000};

// MatMul v4.2 / ENC-BMX4C construction invariants (spec §8.1/§8.2). No-op when
// the profile is unset (nMatMulBMX4CHeight == INT32_MAX = disabled); when a
// network sets a BMX4C activation height these MUST hold, so a
// misconfiguration fails loudly at node startup rather than at the fork.
//
// These use Assert() to express that every failure is fatal and to retain the
// project's structured internal-error diagnostic. Supported CMake builds
// already remove -DNDEBUG, and util/check.h rejects C++ builds that define it,
// so the earlier lowercase assert() expressions were evaluated in supported
// Release builds too. This conversion makes the intended primitive explicit;
// it does not imply that supported releases previously skipped these checks.
static void AssertBMX4CConstructionInvariants(const Consensus::Params& consensus, bool is_regtest)
{
    // Audit P1-1 (per-network relay invariant): the enforced block-size ceiling
    // is the per-network consensus value nMaxBlockSerializedSize, but the P2P
    // layer sizes its block-message buffer from the compile-time
    // MAX_BLOCK_SERIALIZED_SIZE (see net.cpp's MAX_BLOCK_MESSAGE_LENGTH
    // static_assert). If any network raised its consensus block ceiling above
    // that compile-time bound, a consensus-valid block on that network would
    // exceed MAX_BLOCK_MESSAGE_LENGTH and become un-relayable -- reintroducing the
    // P0.5 split/eclipse surface at the per-network level. Pin every network's
    // block ceiling to the compile-time bound here so a mismatch aborts startup
    // rather than surfacing as an un-downloadable block in production. (This runs
    // unconditionally, before the MatMul-specific checks, so it covers networks
    // with the MatMul upgrade disabled too.)
    Assert(consensus.nMaxBlockSerializedSize <= MAX_BLOCK_SERIALIZED_SIZE);

    // Audit F1 / v4.4 §4: HeaderPoW grind field is nNonce, but the bit-26
    // self-describing 182↔186 wire was WITHDRAWN (pre-activation peer split).
    // Wire stays 182, so public networks categorically keep HeaderPoW disabled;
    // Epoch A uses rcadmit policy plus authenticated chainwork instead.

    // Audit H2: the header-PoW discount is valid ONLY in 0..255 (or the
    // UINT32_MAX "disabled" sentinel). A value in [256, UINT32_MAX-1] would push
    // the throttle target to powLimit regardless of nBits, recreating the
    // fixed-cost C2 gate; reject it fatally here rather than clamp it silently.
    Assert(consensus.IsMatMulHeaderPoWDiscountValid());

    // Audit D1: the immutable MatMul-ASERT schedule parameters (rescale ratios,
    // branch ordering, collision-freedom) are validated HERE, at construction, so
    // a malformed set aborts node startup. Previously they were only checked
    // per-block inside MatMulAsert, which -- because it evaluates EVERY configured
    // fork's parameters on every ASERT block and failed OPEN to powLimit -- meant a
    // malformed even future-dated parameter set could weaken CURRENT difficulty the
    // moment the binary started. ValidateMatMulAsertParams is a pure function of
    // the params (the height argument is log context only), so validity here
    // implies validity at every height; the per-block call now fails CLOSED as a
    // pure defence-in-depth backstop.
    if (consensus.fMatMulPOW) {
        Assert(ValidateMatMulAsertParams(consensus, consensus.nMatMulAsertHeight));
    }

    // Audit DoS-F3: correct MatMul difficulty adjustment requires the MatMul-ASERT
    // activation height to EQUAL the fast-mine boundary -- ASERT must take over the
    // instant the fixed-difficulty fast-mining phase ends, with no gap or overlap
    // (pow.cpp treats nFastMineHeight as the anchor and nMatMulAsertHeight as the
    // ASERT epoch; a mismatch silently corrupts targeting at the transition). This
    // is enforced at runtime in init.cpp, but assert it at construction too so a
    // misconfigured network aborts at startup rather than at the fast->normal
    // boundary. Every shipped network sets both equal (50'000 on mainnet, 61'000 on
    // the public test nets, 0/2 on the mockable chains).
    Assert(consensus.nFastMineHeight == consensus.nMatMulAsertHeight);

    // Audit I1: the miner and verifier use the compile-time tile size
    // matmul::v4::kTileB (b); a consensus nMatMulV4TranscriptBlockSize that differs
    // from it would make EVERY v4 block invalid at the fork. Pin them equal
    // wherever v4 is configured (nMatMulV4TranscriptBlockSize is not yet a truly
    // parameterizable value -- the b=8/n=8192 profile is a future consensus change,
    // not a live parameter).
    // §0.3 / §4.3 PER-PROFILE dimension-invariant guard: for each configured
    // profile P live at some height, nMatMulV4Dimension at PRODUCTION scale MUST
    // reduce to exactly P.sketch_rank_m under P.tile_b (tile_b·m == n), and the
    // per-profile sketch byte count SketchCacheBytes() MUST equal 8·m². The
    // committed sketch rank, its 8·m² byte count, and the O(n²) verify DoS budget
    // are calibrated PER PROFILE for that rank at the PRODUCTION dimension.
    // (Under v4.4 ENC-DR those 8·m² bytes live only in the non-consensus sketch
    // cache, never in the block; the pin still fixes the recompute/verify shape.)
    // Nothing else pins the dimension
    // to the compile-time tile, so raising nMatMulV4Dimension (allowed by the
    // 4096..8192 accept window) without a lockstep per-profile tile_b change
    // would SILENTLY yield a different-shaped committed object with no profile
    // bump / golden regeneration. §0.3 requires m to STAY FIXED with b tracking
    // n (b -> 8 at n -> 8192 for C; b -> 4 for D). Small test dimensions (regtest
    // n=256, -regtestmatmulv4dimension overrides) are below production scale and
    // exempt: their committed object is fixed by the exact-match check, not
    // calibrated against mainnet goldens. Expressed via the per-profile
    // MatMulProfileParams (design §4.1/§4.2) so C pins (b=4 -> m=1024 -> 8 MiB)
    // and D pins (b=2 -> m=2048 -> 32 MiB) INDEPENDENTLY.
    const auto assert_profile_dimension_pin =
        [&consensus](const Consensus::MatMulProfileParams& p) {
            Assert(p.tile_b > 0);
            // (Note: no assert on SketchCacheBytes()==8·m² — that merely restates
            // the method's own definition. The meaningful pins are the dimension
            // ties below, which tie the byte count to n transitively via m.)
            Assert(consensus.nMatMulV4Dimension % p.tile_b == 0);
            if (consensus.nMatMulV4Dimension >= p.tile_b * p.sketch_rank_m) {
                Assert(consensus.nMatMulV4Dimension / p.tile_b == p.sketch_rank_m);
            }
        };

    if (consensus.nMatMulV4Height != std::numeric_limits<int32_t>::max()) {
        Assert(consensus.nMatMulV4TranscriptBlockSize == matmul::v4::kTileB);
        // Base profile (ENC-S8 / ENC-BMX4C): pin its own (b=4, m=1024, 8 MiB)
        // triple via the per-profile params. At nMatMulV4Height the live profile
        // is S8 or C (both the base shape) in every valid config; a v4-only
        // misconfig is caught by the strict-unified invariant below.
        assert_profile_dimension_pin(
            consensus.GetMatMulProfileParams(consensus.nMatMulV4Height));
    }

    // AUDIT P0.2 (STRICT UNIFIED ACTIVATION): the MatMul upgrade activates on ONE
    // flag day, v3 -> v4.2/ENC-BMX4C directly, with NO reachable ENC-S8 interval on
    // ANY network. So the ONLY valid configs are (i) the whole upgrade disabled, or
    // (ii) v4 and ENC-BMX4C at the SAME height. A v4-only config (bmx4c disabled
    // while v4 is set) would open a permanent ENC-S8 window, and a staged bmx4c > v4
    // config would open a transient one -- both forbidden. Checked BEFORE the
    // disabled-early-return so a v4-only config cannot slip through.
    Assert((consensus.nMatMulV4Height == std::numeric_limits<int32_t>::max() &&
            consensus.nMatMulBMX4CHeight == std::numeric_limits<int32_t>::max()) ||
           (consensus.nMatMulV4Height == consensus.nMatMulBMX4CHeight));

    if (consensus.nMatMulBMX4CHeight == std::numeric_limits<int32_t>::max()) return;
    // At this point ENC-BMX4C is enabled, so (by the strict-unified invariant above)
    // v4 and ENC-BMX4C share one height: the single-activation flag day. ENC-S8 is
    // never live; the live profile at and above the fork is ENC-BMX4C. Exactly one
    // profile is live at any height -- no dual-profile window, no ENC-S8 interval.
    Assert(consensus.nMatMulBMX4CHeight == consensus.nMatMulV4Height);
    // The base-2^6 remainder-top combine must totally decompose every P/Q entry
    // across the whole accepted-dimension window: 288 * MaxDim <= 2^23 - 1.
    Assert(static_cast<int64_t>(Consensus::BMX4C_PROJECTION_BOUND_PER_N) *
               consensus.nMatMulV4MaxDimension <=
           Consensus::BMX4C_COMBINE_INPUT_BOUND);
    // The accepted (exact) dimension must be a multiple of the E8M0 block length
    // (block scales run along the contraction dim in blocks of 32).
    Assert((consensus.nMatMulV4Dimension % Consensus::BMX4C_SCALE_BLOCK_LENGTH) == 0);
    // Audit ASERT-F1: the one-time ASERT rescale ratio must be strictly positive.
    // ValidateMatMulAsertParams enforces this at runtime (failing closed to
    // the hardest representable target), but that only surfaces AT the fork
    // height; assert it at startup
    // too so a non-positive misconfiguration aborts the node immediately. Only
    // positivity is checked -- a LARGE ratio can be a legitimate calibration
    // (Num/Den is the measured v3 parent nonce-attempt rate divided by the
    // Profile-1 episode rate, which can be large), and ASERT
    // self-corrects any residual within one half-life, so no arbitrary range cap.
    Assert(consensus.nMatMulBMX4CAsertRescaleNum > 0);
    Assert(consensus.nMatMulBMX4CAsertRescaleDen > 0);

    // v4.4 ENC-DR carriage fail-close (tension-resolution §4.5): the legacy
    // FLAT_SKETCH_INBLOCK carriage survives ONLY as a regtest differential-
    // testing switch. A public network must never be constructible with the
    // replay carriage selected — the ENC-DR digest-only rule is the single live
    // consensus carriage everywhere v4 activates.
    Assert(!consensus.fMatMulV4FlatSketchReplay || is_regtest);

    // v4.4 ENC-DR DR-34 FAIL-CLOSED ACTIVATION GATE (normative spec §5, DR-34).
    // A public network (regtest exempt) with a LIVE (non-INT32_MAX) v4 height
    // requires the no-inversion/L0 source authorization bit. FALSE aborts node
    // startup; TRUE permits the tuple but does not itself prove the external
    // measurement or ratification record. This is the same fail-closed
    // mechanism as the retired relay-ready flag, retargeted to the release
    // decision. (Reachable here only
    // when v4 is live — we are past the bmx4c==INT32_MAX early return above — but
    // the height clause keeps the assert correct independent of placement.)
    Assert(is_regtest ||
           consensus.nMatMulV4Height == std::numeric_limits<int32_t>::max() ||
           Consensus::BTX_MATMUL_NO_INVERSION_GATE_RATIFIED);

    // HeaderPoW's grind nonce is not serialized in the fixed 182-byte header.
    // Enabling it on a public network would make a locally mined header depend
    // on state that peers deserialize as zero. Keep it categorically disabled
    // on public networks. Epoch A instead requires the exact atomic
    // v4==BMX4C==RC Profile-1 tuple below and zero unauthenticated chainwork
    // credit before ExactReplay; Poseidon2 rcadmit supplies the P2P admission
    // policy around that consensus rule.
    Assert(is_regtest || !consensus.IsMatMulHeaderPoWEnabled());

    // v4.4-LT Rank-1 (ENC-DR-LT, doc/btx-matmul-v4.4-lt-normative-spec.md).
    // No-op while nMatMulDRLTHeight == INT32_MAX (every public network today).
    // When a network ever sets it live, public nets must activate as ONE
    // unified v4.4-LT profile (v4 == BMX4C == DRLT, seal-as-PoW on). Staged
    // heights (DRLT later than BMX4C, or seal off) remain allowed only on
    // explicitly isolated regtest fixtures.
    if (consensus.nMatMulDRLTHeight != std::numeric_limits<int32_t>::max()) {
        Assert(consensus.nMatMulBMX4CHeight != std::numeric_limits<int32_t>::max());
        Assert(consensus.nMatMulDRLTHeight >= consensus.nMatMulBMX4CHeight);
        if (!is_regtest) {
            // Public-network launch contract: one immutable ENC_BMX4C_LT profile.
            Assert(consensus.nMatMulV4Height == consensus.nMatMulBMX4CHeight);
            Assert(consensus.nMatMulBMX4CHeight == consensus.nMatMulDRLTHeight);
            Assert(consensus.fMatMulLTSealAsPoW);
        }
        // Miner-local MatExpand window Q* is restricted to {128,256,512} (Rank-1
        // Phase A schedule; seal-as-PoW is Phase B). The deep-m tile is fixed
        // at b=2 for Phase A (m = n/2, storage-free under ENC-DR). A
        // misconfigured value here would silently commit a different
        // (unspecified) object, so fail loud at startup rather than at the fork.
        Assert(consensus.nMatMulConsensusQStar == 128 ||
               consensus.nMatMulConsensusQStar == 256 ||
               consensus.nMatMulConsensusQStar == 512);
        Assert(consensus.nMatMulLTTranscriptBlockSize == 2);
        Assert(consensus.nMatMulDRLTAsertRescaleNum > 0);
        Assert(consensus.nMatMulDRLTAsertRescaleDen > 0);
        // Pin the live profile shape (same assert_profile_dimension_pin used for
        // ENC-BMX4C): deep-m tile b=2 and sketch rank m = n/b at production n.
        // Raising nMatMulV4Dimension without a lockstep LT rank bump would
        // silently commit a different ENC-DR object.
        {
            const Consensus::MatMulProfileParams lt_profile =
                consensus.GetMatMulProfileParams(consensus.nMatMulDRLTHeight);
            Assert(lt_profile.profile == Consensus::MatMulEncodingProfile::ENC_BMX4C_LT);
            Assert(lt_profile.tile_b == consensus.nMatMulLTTranscriptBlockSize);
            assert_profile_dimension_pin(lt_profile);
        }
        // Same DR-34-style fail-closed activation coupling as the v4/BMX4C
        // gates above: a public network must not carry a live LT height
        // without the same recorded no-inversion + ratification gate (LT is a
        // deepening of the same hardness floor, not an independent one).
        Assert(is_regtest || Consensus::BTX_MATMUL_NO_INVERSION_GATE_RATIFIED);
    }
    // v4.4-LT Q* Phase B (seal-as-PoW). The mode toggle is only meaningful when
    // the LT profile is itself live; a network that flips it without a live LT
    // height is misconfigured (the toggle would be silently inert, masking an
    // ops error). On public networks it additionally rides the SAME
    // no-inversion + ratification gate as LT activation -- seal-as-PoW is a
    // consensus-object redefinition, not a free knob.
    if (consensus.fMatMulLTSealAsPoW) {
        Assert(consensus.nMatMulDRLTHeight != std::numeric_limits<int32_t>::max());
        Assert(consensus.nMatMulConsensusQStar == 128 ||
               consensus.nMatMulConsensusQStar == 256 ||
               consensus.nMatMulConsensusQStar == 512);
        Assert(is_regtest || Consensus::BTX_MATMUL_NO_INVERSION_GATE_RATIFIED);
        // Seal-as-PoW carries the lottery object in the DIGEST_RECOMPUTE profile;
        // flat-sketch-replay forces the legacy FLAT_SKETCH_INBLOCK profile. With both
        // set the miner produces a window-seal digest while the validator takes the
        // in-block product-commitment branch and rejects every seal block
        // (reject-all). They are mutually exclusive even on regtest.
        Assert(!consensus.fMatMulV4FlatSketchReplay);
    }

    // ENC_RC / Resident Curriculum (doc/btx-matmul-v4.7-transition-roadmap.md).
    // MatMul v4.7 Epoch A selects Profile 1 with ExactReplay as consensus
    // authority. Profile 2 remains a future proof-authoritative datacenter
    // shape; its Freivalds sampled carrier is optional relay/precheck state,
    // never consensus authority. The three coupled pieces (profile 2 +
    // finite height + ~16× (16422/1027) ASERT) must activate TOGETHER. Epoch A
    // instead installs the independently calibrated Profile-1 tuple and both
    // source authorization bits. Public test networks remain fail-closed at the
    // disabled sentinel. Regtest may set a finite height + toy dims for CI,
    // where the coupled ASERT is asserted.
    Assert(!consensus.fMatMulRCUseToyDims || is_regtest);
    Assert(consensus.nMatMulRCAsertRescaleNum > 0);
    Assert(consensus.nMatMulRCAsertRescaleDen > 0);
    // ENC_RC episode profile selector (design §6.1(A)): 1 = epoch-0 base,
    // 2 = datacenter. Any other value is a misconfiguration — fail closed.
    Assert(consensus.nMatMulRCProfile == 1 || consensus.nMatMulRCProfile == 2);
    // HARDWARE-ALIGNMENT GUARDRAIL (aicompute-alignment-review.md §4, the weakest
    // link): the datacenter profile must NEVER grow the attention context n_ctx
    // above the epoch-0 base. Attention arithmetic intensity is d_head (≈48× below
    // the FFN's 1.5·d_model), so a larger n_ctx tips the episode HASH-BOUND and
    // favors SHA-ASICs over AI accelerators. Fail closed (defense-in-depth beside
    // the factory-level assert in MakeDatacenterRCEpisodeParams).
    Assert(matmul::v4::rc::MakeDatacenterRCEpisodeParams().n_ctx <=
           matmul::v4::rc::DefaultConsensusRCEpisodeParams().n_ctx);
    // COUPLED TRIO: whenever the datacenter profile is ACTIVE (profile 2 AND a
    // finite RC height) the one-time ASERT rescale MUST be the EXACT datacenter/base
    // episode-MAC ratio 16422/1027 (~16× loosen) — the difficulty re-anchor cannot
    // be silently omitted when the ~16×-heavier episode goes live, and cannot be
    // applied without the datacenter dims.
    if (consensus.nMatMulRCProfile == 2 &&
        consensus.nMatMulRCHeight != std::numeric_limits<int32_t>::max()) {
        Assert(consensus.nMatMulRCAsertRescaleNum == kRCDatacenterAsertRescaleNum);
        Assert(consensus.nMatMulRCAsertRescaleDen == kRCDatacenterAsertRescaleDen);
    }
    // Profile 1 changes the lottery shape. Epoch A does not merely make each nonce more
    // expensive, it changes the SHAPE of the lottery: pre-fork a block needs
    // BOTH the pre-hash gate (sigma <= target << epsilon, epsilon = 18 on
    // mainnet from height 50'000) AND the digest gate, so P(block per nonce)
    // = 2^epsilon * p^2. At v4 heights the pre-hash gate is retired outright
    // (validation.cpp, "the pre-hash lottery gate is retired at v4 heights"),
    // leaving P = p. A rescale derived only from per-nonce THROUGHPUT
    // (attempts/s before over attempts/s after) omits the 2^epsilon * p factor
    // entirely and is wrong by that factor. The correct one-time loosen is
    //     k = 2^epsilon * p(H_A-1) * (R_v3 / R_rc).
    // MatMulAsert now derives that factor from live parent nBits with a 512-bit
    // intermediate. These fields carry only the measured throughput ratio.
    // ASERT-RATIO CONSISTENCY guardrail: the datacenter one-time ASERT rescale
    // constant MUST equal the EXACT reduced datacenter/base episode-MAC ratio, so
    // it can never silently drift from the real per-block work uplift when the
    // episode dims are retuned (e.g. scaling b_seq/d_ff up for a larger datacenter
    // differential). DERIVED, not trusted: recompute the ratio from the canonical
    // params and fail construction on any mismatch. TotalRCEpisodeMacs is the O(1)
    // MAC-count formula (not an actual episode run), so this is cheap at startup.
    {
        const uint64_t mac_dc = matmul::v4::rc::TotalRCEpisodeMacs(
            matmul::v4::rc::MakeDatacenterRCEpisodeParams());
        const uint64_t mac_base = matmul::v4::rc::TotalRCEpisodeMacs(
            matmul::v4::rc::DefaultConsensusRCEpisodeParams());
        Assert(mac_base != 0 && mac_dc != 0);
        const uint64_t g = std::gcd(mac_dc, mac_base);
        Assert(g != 0);
        Assert(static_cast<uint64_t>(kRCDatacenterAsertRescaleNum) == mac_dc / g);
        Assert(static_cast<uint64_t>(kRCDatacenterAsertRescaleDen) == mac_base / g);
    }
    // PROFILE-1 WORK ANCHOR, DERIVED NOT TRUSTED (the same pattern, applied to
    // Epoch A). The per-block MAC ratio between the RC Profile-1 episode and the
    // v3 parent is a closed-form function of consensus params, so recompute it
    // rather than trusting a literal: it then cannot silently go stale when
    // nMatMulDimension, nMatMulNoiseRank or the RC episode dims are retuned,
    // which is exactly how a bad calibration would slip through.
    //
    // v3 per-nonce MACs = the n^3 GEMM plus the rank-r noise outer products.
    // This is the ANCHOR, not the rescale: the runtime derivation additionally
    // needs the same-silicon MFU ratio between the two workloads (still
    // unmeasured -- see nMatMulRCAsertRescaleNum) and is reduced by the
    // two-stage 1/(1+gamma) factor. Neither is checkable here; what IS checkable
    // is that the ratio stays representable after reduction, since an
    // unrepresentable one cannot be applied at all.
    //
    // Only meaningful on a public network at production dimensions: regtest and
    // toy-dim builds deliberately shrink the v3 GEMM, which makes the ratio
    // enormous and unrepresentable without saying anything about the mainnet
    // activation path this guards.
    if (!is_regtest && !consensus.fMatMulRCUseToyDims) {
        const uint64_t mac_rc_p1 = matmul::v4::rc::TotalRCEpisodeMacs(
            matmul::v4::rc::DefaultConsensusRCEpisodeParams());
        const uint64_t n = consensus.nMatMulDimension;
        const uint64_t r = consensus.nMatMulNoiseRank;
        const uint64_t mac_v3 = 2 * n * n * n + 4 * n * n * r;
        Assert(mac_rc_p1 != 0 && mac_v3 != 0);
        const uint64_t g1 = std::gcd(mac_rc_p1, mac_v3);
        Assert(g1 != 0);
        Assert((mac_rc_p1 / g1) <= std::numeric_limits<uint32_t>::max());
        Assert((mac_v3 / g1) <= std::numeric_limits<uint32_t>::max());
    }
    // EPSILON BINDING. A Profile-1 calibration is only meaningful at the
    // pre-hash epsilon that will actually be live at the activation height. If
    // nMatMulPreHashEpsilonBitsUpgradeHeight moves, any staged ratio is stale.
    // Inert while the height is INT32_MAX; asserted the moment it is not.
    if (consensus.nMatMulRCHeight != std::numeric_limits<int32_t>::max() &&
        !is_regtest) {
        // Epoch A derives its transition target from the parent block, so bind
        // the calibration to the epsilon live at H_A-1 rather than H_A. An
        // epsilon transition at H_A itself would otherwise pass construction
        // while using evidence measured for a different parent predicate.
        Assert(consensus.nMatMulRCHeight > 0);
        Assert(consensus.GetMatMulPreHashEpsilonBitsForHeight(
                   consensus.nMatMulRCHeight - 1) ==
               consensus.nMatMulPreHashEpsilonBitsUpgrade);
    }
    if (!is_regtest) {
        // A public build is valid in exactly one of two states:
        //   (a) v4/BMX4C/RC all disabled, or
        //   (b) the source-authorized, activation-armed atomic Epoch-A tuple.
        // This prevents a vulnerable digest-only v4 interval before
        // ExactReplay, keeps the withdrawn HeaderPoW path off, and prevents
        // Profile 2 or unfinished proof authority from inheriting Epoch A.
        const int32_t disabled{std::numeric_limits<int32_t>::max()};
        const bool epoch_a_disabled{
            consensus.nMatMulV4Height == disabled &&
            consensus.nMatMulBMX4CHeight == disabled &&
            consensus.nMatMulRCHeight == disabled};
        const bool epoch_a_active{
            consensus.IsMatMulV47EpochAActivationTuple() &&
            Consensus::BTX_MATMUL_NO_INVERSION_GATE_RATIFIED &&
            Consensus::BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED};
        Assert(epoch_a_disabled || epoch_a_active);
        Assert(consensus.nMatMulRCProfile == 1);
        Assert(!consensus.fMatMulRCUseToyDims);
        // The calibrated Epoch-A coefficient belongs to a network whose
        // Profile-1 height is LIVE. A public network whose RC height is still
        // disabled must stay neutral: its rescale is inert, and the calibrated
        // value is deliberately larger than uint32, which
        // ValidateMatMulAsertParams only accepts through the wide Epoch-A path
        // that a disabled network does not take. Pinning every public net to
        // the calibrated constant therefore made testnet and signet
        // unconstructible.
        if (epoch_a_active) {
            Assert(consensus.nMatMulRCAsertRescaleNum == kRCEpochAAsertRescaleNum);
            Assert(consensus.nMatMulRCAsertRescaleDen == kRCEpochAAsertRescaleDen);
        } else {
            Assert(consensus.nMatMulRCAsertRescaleNum ==
                   consensus.nMatMulRCAsertRescaleDen);
        }
    }
    if (consensus.nMatMulRCHeight != std::numeric_limits<int32_t>::max()) {
        Assert(consensus.nMatMulV4Height != std::numeric_limits<int32_t>::max());
        Assert(consensus.nMatMulRCHeight >= consensus.nMatMulV4Height);
        Assert(is_regtest || Consensus::BTX_MATMUL_NO_INVERSION_GATE_RATIFIED);
        Assert(is_regtest ||
               Consensus::BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED);
    }
    // ENC_RC_COUPLED (Stage C coupled puzzle): public nets stay fail-closed at
    // INT32_MAX. Regtest may set a finite height + toy dims for end-to-end CI.
    // Ordering: when RC is also configured, Coupled must follow RC (>=) so the
    // profile succession matches ASERT re-anchor order. Public rescale stays 1/1.
    Assert(!consensus.fMatMulRCCoupledUseToyDims || is_regtest);
    Assert(consensus.nMatMulRCCoupledAsertRescaleNum > 0);
    Assert(consensus.nMatMulRCCoupledAsertRescaleDen > 0);
    if (!is_regtest) {
        Assert(consensus.nMatMulRCCoupledHeight == std::numeric_limits<int32_t>::max());
        Assert(!consensus.fMatMulRCCoupledUseToyDims);
        // V3 production is the public / coupled default: a finite coupled height
        // alone selects V3 (no hidden override). Height stays INT32_MAX above, so
        // this only fixes WHAT would activate, not that anything activates now.
        Assert(consensus.nMatMulRCCoupledProfile == 3);
        Assert(consensus.nMatMulRCCoupledAsertRescaleNum == 1);
        Assert(consensus.nMatMulRCCoupledAsertRescaleDen == 1);
    }
    if (consensus.nMatMulRCCoupledHeight != std::numeric_limits<int32_t>::max()) {
        Assert(consensus.nMatMulV4Height != std::numeric_limits<int32_t>::max());
        Assert(consensus.nMatMulRCHeight != std::numeric_limits<int32_t>::max());
        Assert(consensus.nMatMulRCCoupledHeight >= consensus.nMatMulV4Height);
        // The coupled successor is additive, not a standalone workload: its
        // lottery and Stage-3 statement bind a genuine episode leg too.
        Assert(consensus.nMatMulRCCoupledHeight >= consensus.nMatMulRCHeight);
        Assert(is_regtest || Consensus::BTX_MATMUL_NO_INVERSION_GATE_RATIFIED);
    }
    // §R.7 scheduled-scaling tables must be non-zero once filled by constructors.
    // (FillDefaultRCGrowthTables is called before this assert on every network.)
    Assert(consensus.nRCScaleEpochBlocks > 0);
    Assert(consensus.nRCBrakeDeltaPct >= 0 && consensus.nRCBrakeDeltaPct <= 100);
    Assert(consensus.nRCScaleHardCapResBytes > 0);
    Assert(consensus.nRCScaleHardCapCapBytes > 0);
    Assert(consensus.nRCGrowthResTableQ16[0] > 0);
    Assert(consensus.nRCGrowthCapTableQ16[0] > 0);
}

static CBlock CreateGenesisBlock(const char* pszTimestamp,
                                 const CScript& genesisOutputScript,
                                 uint32_t nTime,
                                 uint32_t nNonce,
                                 uint64_t nNonce64,
                                 uint32_t nBits,
                                 int32_t nVersion,
                                 const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nNonce64 = nNonce64;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateBTXGenesisBlock(uint32_t nTime,
                                    uint32_t nNonce,
                                    uint64_t nNonce64,
                                    uint32_t nBits,
                                    int32_t nVersion,
                                    const CAmount& genesisReward,
                                    uint16_t matmul_dim,
                                    const uint256& matmul_digest)
{
    const char* pszTimestamp = "BTX 19/Mar/2026 SMILE v2 Post-Quantum Shielded Transactions";
    // Unspendable P2MR commitment:
    // merkle_root = SHA256("BTX P2MR Genesis - Quantum Safe Since Block 0")
    const auto genesis_script_bytes{ParseHex("5220afa45d6891836c7314dded4dbd0e7aacde3de0d7fa9a12aeac06e2296c794226")};
    const CScript genesisOutputScript{genesis_script_bytes.begin(), genesis_script_bytes.end()};
    CBlock genesis = CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nNonce64, nBits, nVersion, genesisReward);
    genesis.matmul_dim = matmul_dim;
    // Deterministic genesis seeds derived for prevhash=0 and height=0.
    genesis.seed_a = uint256{"a8a82ec830e8346550cad66c4cf43985dddd6a056d4bed2a5dcace445fa924ab"};
    genesis.seed_b = uint256{"f9aaa742cdbfb26be3d22d743b548740ff0a9e00f9cc977c1fb03df85fdf978d"};
    genesis.matmul_digest = matmul_digest;
    return genesis;
}

static CBlock CreateShieldedV2DevGenesisBlock(uint32_t nTime,
                                              uint32_t nNonce,
                                              uint64_t nNonce64,
                                              uint32_t nBits,
                                              int32_t nVersion,
                                              const CAmount& genesisReward,
                                              uint16_t matmul_dim,
                                              const uint256& matmul_digest)
{
    const char* pszTimestamp = "BTX 14/Mar/2026 shieldedv2dev genesis";
    const auto genesis_script_bytes{ParseHex("5220afa45d6891836c7314dded4dbd0e7aacde3de0d7fa9a12aeac06e2296c794226")};
    const CScript genesisOutputScript{genesis_script_bytes.begin(), genesis_script_bytes.end()};
    CBlock genesis = CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nNonce64, nBits, nVersion, genesisReward);
    genesis.matmul_dim = matmul_dim;
    genesis.seed_a = uint256{"a8a82ec830e8346550cad66c4cf43985dddd6a056d4bed2a5dcace445fa924ab"};
    genesis.seed_b = uint256{"f9aaa742cdbfb26be3d22d743b548740ff0a9e00f9cc977c1fb03df85fdf978d"};
    genesis.matmul_digest = matmul_digest;
    return genesis;
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 525000;
        consensus.script_flag_exceptions.clear(); // New chain has no exceptions
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        // MatMul powLimit calibrated for fast-phase SLA targeting ~0.25s blocks
        // on current Apple Silicon throughput (n=512), while retaining compact
        // headroom above genesis nBits so bootstrap scaling is not clamped out.
        // 2026-03-08 retune: eased from 0x205aa936 to 0x2066c154 based on live
        // throughput telemetry (~3.53 bps, ~0.283s over a 30s run) to target
        // the configured fast-phase SLA (~0.25s mean) on this host profile.
        consensus.powLimit = uint256{"66c1540000000000000000000000000000000000000000000000000000000000"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 90;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = false;
        consensus.fKAWPOW = false;
        consensus.fSkipKAWPOWValidation = false;
        consensus.fReducedDataLimits = true;
        consensus.fEnforceP2MROnlyOutputs = true;
        consensus.nKAWPOWHeight = std::numeric_limits<int>::max();
        consensus.fMatMulPOW = true;
        consensus.nMatMulDimension = 512;
        consensus.nMatMulTranscriptBlockSize = 16;
        consensus.nMatMulNoiseRank = 8;
        consensus.nMatMulValidationWindow = 1000;
        consensus.nMatMulPhase2FailBanThreshold = 1;
        consensus.fMatMulStrictPunishment = false;
        consensus.nMatMulSnapshotInterval = 10'000;
        // Freivalds' O(n^2) probabilistic verification (k=2 rounds, error < 2^-62).
        consensus.fMatMulFreivaldsEnabled = true;
        consensus.nMatMulFreivaldsRounds = 2;
        // The static "require payload" flag stays false, but the Freivalds product
        // payload is already CONSENSUS-REQUIRED at and above nMatMulProductDigestHeight
        // (61'000) via IsMatMulProductPayloadRequired(); the flag is only a legacy
        // global override for networks that require it from genesis. Because the C'
        // product payload is a trailing CBlock appendage that BIP152 compact blocks
        // cannot carry, compact-block serving is intentionally disabled for blocks at
        // these heights (a reconstructed payload-less block would fail validation) --
        // see ProcessGetBlockData in net_processing.cpp. There is no scheduled upgrade
        // that re-enables compact serving for these v3 heights. (v4.4 ENC-DR blocks
        // carry no payload at all, so this constraint is a v3-history artifact.)
        consensus.fMatMulRequireProductPayload = false;
        consensus.nMatMulFreivaldsBindingHeight = 61'000;
        consensus.nMatMulProductDigestHeight = 61'000;
        // Epoch A performs one atomic v4 = BMX4C = RC Profile-1 transition at
        // the finite height installed below. DRLT/LT and coupled Profile-2 are
        // later, separately reviewed transitions and remain disabled here.
        // Keeping their heights at INT32_MAX is consensus-significant: neither
        // the LT seal nor Stage-3/proof authority may leak into Epoch A.
        consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulConsensusQStar = 256;
        consensus.nMatMulLTTranscriptBlockSize = 2;
        consensus.nMatMulDRLTAsertRescaleNum = 1;
        consensus.nMatMulDRLTAsertRescaleDen = 1;
        // Q* Phase B seal-as-PoW: implemented but OFF and inert because DRLT
        // remains disabled above.
        consensus.fMatMulLTSealAsPoW = false;
        // MatMul v4.7 Epoch A selects Profile 1 from Consensus::Params.
        // Profile 2 and Stage-3 proof authority remain separate transitions.
        //
        // MatMul v4.7 Epoch-A release-candidate activation height.
        //
        // H_A = 185'000. Chosen against the live mainnet tip 178'841, i.e.
        // 6'159 blocks of runway (about 154 hours at the 90-second target).
        // Sized on measured spacing rather than the
        // 90 s target: the realized interval is 89 s over the last 4'032
        // blocks and 85 s over the last 144. Using the faster recent figure
        // is the conservative direction here -- it makes the initial runway
        // about 145.4 h at 85 s and 152.3 h at 89 s, safely above 96 hours.
        //
        // The previous constant 182'283 was sized against tip 178'283 and had
        // decayed to ~93 h of runway by the time the tree was ready. Recompute
        // this against the live tip if the merge slips again -- the runway is
        // measured from the tip when the constant is chosen, not from the
        // merge, and it only shrinks while the PR sits.
        //
        // IsMatMulV47EpochAActivationTuple() requires v4, BMX4C and RC to share
        // one height, with DRLT and the coupled height disabled and profile 1,
        // so all three are set together here. AssertBMX4CConstructionInvariants
        // additionally refuses a neutral rescale at a live Profile-1 height,
        // which is why the calibration above is installed in this same commit.
        consensus.nMatMulV4Height = BTX_MATMUL_V47_EPOCH_A_HEIGHT;
        consensus.nMatMulBMX4CHeight = BTX_MATMUL_V47_EPOCH_A_HEIGHT;
        consensus.nMatMulRCHeight = BTX_MATMUL_V47_EPOCH_A_HEIGHT;
        consensus.nMatMulRCAsertRescaleNum = kRCEpochAAsertRescaleNum;
        consensus.nMatMulRCAsertRescaleDen = kRCEpochAAsertRescaleDen;
        consensus.nMaxReorgDepth = 12;
        consensus.nReorgProtectionStartHeight = 61'000;
        consensus.nEmptyBlockSubsidyPenaltyHeight = BTX_EMPTY_BLOCK_SUBSIDY_PENALTY_HEIGHT;
        consensus.nEmptyBlockSubsidyStrictPenaltyHeight = BTX_V03210_HARDENING_HEIGHT;
        consensus.nEmptyBlockSubsidyPenaltyEndHeight = BTX_V03211_HARDENING_HEIGHT;
        consensus.nPowTargetSpacingFastMs = 250;
        // Fast-phase bootstrap scale for heights [0, nFastMineHeight). Effective
        // ease is bounded by powLimit; keep this >1 so fast bootstrap can
        // converge to the configured floor.
        consensus.nFastMineDifficultyScale = 6;
        consensus.nPowTargetSpacingNormal = 90;
        // Mainnet launched with the MatMul bootstrap window ending at 50,000.
        // Keep that historical PoW schedule frozen; later hardening work at
        // 61,000 must not rewrite already-mined header difficulty history.
        consensus.nFastMineHeight = 50'000;
        // DGW is NOT used for MatMul mining. These heights are disabled.
        // ASERT governs all difficulty adjustment from nFastMineHeight onward.
        // Do not re-enable DGW -- see pow.cpp design invariant comments.
        consensus.nDgwAsymmetricClampHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwEasingBoostHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwWindowAlignmentHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwSlewGuardHeight = std::numeric_limits<int32_t>::max();
        // ASERT activates at nFastMineHeight. This MUST equal nFastMineHeight.
        consensus.nMatMulAsertHeight = 50'000;
        consensus.nMatMulAsertHalfLife = 3'600;
        consensus.nMatMulAsertBootstrapFactor = 180;
        // No retune or half-life upgrade needed — fresh chain starts with
        // the target 3,600s half-life directly.
        consensus.nMatMulAsertRetuneHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetuneHardeningFactor = 1;
        consensus.nMatMulAsertRetune2Height = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetune2TargetNum = 1;
        consensus.nMatMulAsertRetune2TargetDen = 1;
        consensus.nMatMulAsertHalfLifeUpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertHalfLifeUpgrade = 3'600;
        // Height 118,482 is approximately six hours from the observed public
        // tip near 118,242 at the 90-second target spacing, while bounding
        // future-dated timestamp shocks to one ASERT half-life.
        consensus.nMatMulMaxFutureMtpDriftHeight = 118'482;
        consensus.nMatMulMaxFutureMtpDrift = 3'600;
        // a5 fix: flag-day activation of the timewarp/drift bound reconciliation. Mainnet is
        // already past the only drift-cap activation boundary (118,482), so no inversion can
        // occur here and the reconciliation is behaviorally inert -- it is scheduled at the
        // shared height-125,000 hardening flag day for rollout consistency and to protect any future
        // network that activates the drift cap at a non-genesis height.
        consensus.nMatMulTimewarpReconcileHeight = 125'000;
        // Hardened pre-hash epsilon (18 bits) has been active on mainnet since
        // the historical ASERT transition at 50,000.
        consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = 50'000;
        consensus.nMatMulPreHashEpsilonBitsUpgrade = 18;
        // E1 hardening: after the shielded sunset boundary, MatMul seeds are
        // bound to the mutable header so miners cannot reuse one fixed A/B
        // instance across nonce attempts.
        consensus.nMatMulNonceSeedHeight = 125'000;
        // v0.32.10 hardening: bind MatMul seeds to the actual parent MTP so
        // templates cannot be prebuilt against one parent and replayed across
        // alternate withheld parents.
        consensus.nMatMulParentMtpSeedHeight = BTX_V03210_HARDENING_HEIGHT;
        consensus.nMaxBlockWeight = 24'000'000;
        consensus.nMaxBlockSerializedSize = 24'000'000;
        consensus.nMaxBlockSigOpsCost = 480'000;
        consensus.nDefaultBlockMaxWeight = 24'000'000;
        consensus.nDefaultMempoolMaxSizeMB = 2048;
        consensus.nMaxShieldedTxSize = 6'500'000;
        consensus.nMaxShieldedRingSize = 32;
        consensus.nShieldedMerkleTreeDepth = 32;
        consensus.nShieldedPoolActivationHeight = 0;
        consensus.nShieldedTxBindingActivationHeight = 61'000;
        consensus.nShieldedBridgeTagActivationHeight = 61'000;
        consensus.nShieldedSmileRiceCodecDisableHeight = 61'000;
        consensus.nShieldedMatRiCTDisableHeight = 61'000;
        consensus.nShieldedSpendPathRecoveryActivationHeight = 88'000;
        consensus.nShieldedPQ128UpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nShieldedPoolCreditDisableHeight = BTX_SHIELDED_POOL_CREDIT_DISABLE_HEIGHT;
        consensus.nShieldedSunsetHeight = BTX_SHIELDED_SUNSET_HEIGHT;
        consensus.nShieldedDirectSendPublicFlowDisableHeight = BTX_SHIELDED_DIRECT_SEND_PUBLIC_FLOW_DISABLE_HEIGHT;
        consensus.nContentEliminationHeight = BTX_CONTENT_ELIMINATION_HEIGHT;
        consensus.nShieldedV2SendZeroOutputExitActivationHeight =
            BTX_SHIELDED_V2_SEND_ZERO_OUTPUT_EXIT_ACTIVATION_HEIGHT;
        consensus.nShieldedRecoveryExitActivationHeight = BTX_SHIELDED_SUNSET_HEIGHT;
        // v0.32.0-v0.32.12: shielded unshield (z->t) velocity cap from the 125,000
        // sunset through block 134,999. The v0.32.11 minimum-cap floor still starts at
        // 132,000, and v0.32.12 ends the quota at 135,000 after the recovery window has
        // matured so remaining legacy exits are no longer rate-limited.
        consensus.nShieldedUnshieldVelocityActivationHeight = BTX_SHIELDED_SUNSET_HEIGHT;
        consensus.nShieldedUnshieldVelocityEndHeight = BTX_SHIELDED_UNSHIELD_VELOCITY_END_HEIGHT;
        consensus.nShieldedUnshieldVelocityMinCapHeight = BTX_V03211_HARDENING_HEIGHT;
        consensus.nShieldedUnshieldVelocityMinCap = BTX_SHIELDED_UNSHIELD_VELOCITY_MIN_CAP;
        consensus.nShieldedSettlementAnchorMaturity = 6;
        consensus.nMLDSADisableHeight = std::numeric_limits<int32_t>::max();
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        // Mainnet anchor refreshed on 2026-08-04 at height 179'000 from a
        // synced archival node so stale history below the current public
        // release floor is rejected quickly.
        // Refreshed to the work at height 186000, the new checkpoint anchor.
        consensus.nMinimumChainWork = uint256{"00000000000000000000000000000000000000000000000000030b4f85e66df7"};
        // Assume signatures valid up to the same anchored block to speed sync.
        consensus.defaultAssumeValid = uint256{"0a51fccfd75d2051e94be1a8cc5abff8b86ac53d0cc134680f286fe769aa2129"};

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xb7;
        pchMessageStart[1] = 0x54;
        pchMessageStart[2] = 0x58;
        pchMessageStart[3] = 0x01;
        nDefaultPort = 19335;
        nPruneAfterHeight = 100000;
        // Measured from the 2026-08-01 mainnet archive near height 176'600:
        // ~117 GB of blocks plus chain/shielded state, rounded up so users see
        // a conservative disk estimate before sync begins.
        m_assumed_blockchain_size = 120;
        m_assumed_chain_state_size = 1;

        genesis = CreateBTXGenesisBlock(
            1773878400,  // Mar 19, 2026 00:00:00 UTC — SMILE v2 chain restart
            0,
            1,
            0x20147ae1,
            1,
            consensus.nInitialSubsidy,
            static_cast<uint16_t>(consensus.nMatMulDimension),
            uint256{"07226e4fdc368a067ef904b9fdddf9763e2782fda4e695788240077805643edd"});
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"75a998a39d2d6e25a9ca7de2cc659309c4105839c06cd435ba2b1aabf0fa4601"});
        assert(genesis.hashMerkleRoot == uint256{"94ae75cb0cd5f08b9447306ae914635d1c36d1a43d330daf596957e91cee002a"});
        // Audit W-2 / ASERT-F1: run the ENC-BMX4C construction invariants on every
        // network (no-op while BMX4C is unset here -- nMatMulBMX4CHeight ==
        // INT32_MAX -- so any future activation on this network cannot set only
        // the height without the fork-ordering/dimension/rescale guards).
        Consensus::FillDefaultRCGrowthTables(consensus);
        AssertBMX4CConstructionInvariants(consensus, /*is_regtest=*/false);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,25);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,50);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,153);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "btx";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        // Live bootstrap DNS seeds for mainnet peer discovery. Keep these as
        // DNS names, not hard-coded IPs, so archive-node rotation does not
        // require a binary update.
        vSeeds.clear();
        vSeeds.emplace_back("node.btx.dev.");
        vSeeds.emplace_back("node.btxchain.org.");
        vSeeds.emplace_back("node.btx.tools.");

        // Fixed seeds mirror the public BTX infrastructure endpoints so nodes
        // can still bootstrap if DNS seed lookups are unavailable.
        vFixedSeeds = std::vector<uint8_t>{std::begin(chainparams_seed_main), std::end(chainparams_seed_main)};

        checkpointData = {
            {
                {0, uint256{"75a998a39d2d6e25a9ca7de2cc659309c4105839c06cd435ba2b1aabf0fa4601"}},
                {179000, uint256{"2dd1d545b1b5e76c28b4414ebe0c22b1ba9d3ebd88662fbd1b9e4d0cf6693933"}},
                // MatMul v4.7 Epoch-A activation. Non-upgraded nodes extend a
                // legacy chain past this height; checkpointing it rejects them
                // explicitly at the first header instead of surfacing a cryptic
                // work-transition error, and stops fresh syncs from being led
                // onto a pre-fork chain by a legacy majority.
                {185000, uint256{"f03a7af21d20f67a5efecfb8b0b3e5e1b91efa208b385419470c59450f2afb8b"}},
                // Post-activation anchor. A competing branch diverges from the
                // canonical chain at ~185544, above the 185000 checkpoint, and
                // is ~800 blocks long. nMaxReorgDepth (12) already stops any
                // running node being reorged onto it, but that rule says
                // nothing about a node syncing from scratch, which simply
                // follows the heaviest valid chain it is offered. Without an
                // anchor above the divergence a fresh sync could settle on the
                // competing branch. Checkpointing 186000 rejects anything
                // forking below it, closing that window; the height is ~300
                // blocks behind the tip, far beyond nMaxReorgDepth, so it
                // cannot pin a block that might still legitimately reorg.
                {186000, uint256{"0a51fccfd75d2051e94be1a8cc5abff8b86ac53d0cc134680f286fe769aa2129"}},
            }
        };
        m_assumeutxo_data = {
            {
                // main assumeutxo snapshot at height 55'000
                .height = 55'000,
                .hash_serialized = AssumeutxoHash{uint256{"3fdff3b95b68ae2d40ef949e41d9e39fe68591f7fcc4cbfbc46c04f58030dda5"}},
                .m_chain_tx_count = 56'457,
                .blockhash = consteval_ctor(uint256{"db5e6530e55606be66aa78fe3f711e9dc4406ee4b26dde2ed819103c37d97d63"}),
            },
            {
                // main assumeutxo snapshot at height 60'760
                .height = 60'760,
                .hash_serialized = AssumeutxoHash{uint256{"e05de35057bbb3b8fa3834c9a2b557b8d54328b2100c06396a0741ab06c98e2a"}},
                .m_chain_tx_count = 66'205,
                .blockhash = consteval_ctor(uint256{"6528ebf50342363b63c17afd851a28307bc2c0fac596373ca9f59c30726d169c"}),
            },
            {
                // main assumeutxo snapshot at height 64'900
                .height = 64'900,
                .hash_serialized = AssumeutxoHash{uint256{"696f6ae3bcfed21881647be3871bf9574eb02fc10b7082677cc29a9b98529459"}},
                .m_chain_tx_count = 73'257,
                .blockhash = consteval_ctor(uint256{"6e5ebacea9f8168371f7c0255e7314aefa69516224675aa326166dbbf39b85f0"}),
            },
            {
                // main assumeutxo snapshot at height 71'260
                .height = 71'260,
                .hash_serialized = AssumeutxoHash{uint256{"46c2582d63ebb1aaf3865f0541e39287c59970ce890253c426b65911eb87e5fa"}},
                .m_chain_tx_count = 83'531,
                .blockhash = consteval_ctor(uint256{"993ddd9ccd08820ad4df089de6a444ffacc788b1b3b9015657d60e353fbad924"}),
            },
            {
                // main assumeutxo snapshot at height 71'435
                .height = 71'435,
                .hash_serialized = AssumeutxoHash{uint256{"9739e6a5891433d542617d28ae71131d976fe60d51a06af87db49f4a0c5a68d6"}},
                .m_chain_tx_count = 83'851,
                .blockhash = consteval_ctor(uint256{"46f81957ac0d40c57eef01810f4da3abb8e8a2c67ebb9fd88f36b1cc5a8e7be0"}),
            },
            {
                // main assumeutxo snapshot at height 85'850
                .height = 85'850,
                .hash_serialized = AssumeutxoHash{uint256{"c0dc455137b4e30554ec91570e198d9c80b1e934f41bece43040e133c8ba9328"}},
                .m_chain_tx_count = 101'463,
                .blockhash = consteval_ctor(uint256{"bbb36b59df48e364dcf32e8ca13f3e5a89fdc16c483fa26779c43da5feb4d40c"}),
            },
            {
                // main assumeutxo snapshot at height 105'550
                .height = 105'550,
                .hash_serialized = AssumeutxoHash{uint256{"20465f460f43e3f1ed4baf237cd52564d6a6f8e4ae3961237dbd60be7bfc1865"}},
                .m_chain_tx_count = 126'978,
                .blockhash = consteval_ctor(uint256{"3245a5e7debf69da9589fb0bc7bfd88fec32575c6f9a3a5d687dc38251a88fc7"}),
            },
            {
                // main assumeutxo snapshot at height 106'875
                .height = 106'875,
                .hash_serialized = AssumeutxoHash{uint256{"662b8b2a2d17654002b0532658ac560f1aa59e35e21738b986eb78212871250b"}},
                .m_chain_tx_count = 128'730,
                .blockhash = consteval_ctor(uint256{"88a7b534ff66a863d45813668d9e53010a257af18b2d73154ec31a873bd36534"}),
            },
            {
                // main assumeutxo snapshot at height 118'225
                .height = 118'225,
                .hash_serialized = AssumeutxoHash{uint256{"69810930f3c4102c10bde6a5380059f6b9b59fc5a0f28c0805576c04a95cd8e1"}},
                .m_chain_tx_count = 144'179,
                .blockhash = consteval_ctor(uint256{"f4dfb86209f2f4f2c9ccfb960368cc334afea065916a82f38698f6391118cd8e"}),
            },
            {
                // main assumeutxo snapshot at height 120'900
                .height = 120'900,
                .hash_serialized = AssumeutxoHash{uint256{"73c62a680afefae9a861131938947831becc774513bd788cc4f93cc42aa06f55"}},
                .m_chain_tx_count = 147'449,
                .blockhash = consteval_ctor(uint256{"24744e8793137d0a6639a90c066b78e7edb6722ad7007cdac0911ae171ead611"}),
            },
            {
                // main assumeutxo snapshot at height 123'225
                .height = 123'225,
                .hash_serialized = AssumeutxoHash{uint256{"153ed4ddf0957251bd450f25f8b10956c3cb47d382ecbc7692e04da1a878b2b8"}},
                .m_chain_tx_count = 150'104,
                .blockhash = consteval_ctor(uint256{"bee000e92d6b64ceb6ad9a3759fb38c1d6752713240e76bde3617f073b9cbe74"}),
            },
            {
                // main assumeutxo snapshot at height 126'800
                .height = 126'800,
                .hash_serialized = AssumeutxoHash{uint256{"240d2b278972ad96afa9c5e26f1f846b2a60a4a9aea4aa8f0a57baa0108db6ae"}},
                .m_chain_tx_count = 155'621,
                .blockhash = consteval_ctor(uint256{"fb6dcf553916244d09ea1cf1f0c0dfc714f232ac17c94f8d0a73d21a75de9e34"}),
            },
            {
                // main assumeutxo snapshot at height 128'605
                .height = 128'605,
                .hash_serialized = AssumeutxoHash{uint256{"2cfa629907fbc18f3edc1dbb8b33fda651ad3655fb88a9dffe7a67ead580a102"}},
                .m_chain_tx_count = 158'299,
                .blockhash = consteval_ctor(uint256{"d95c8b565fefcda79efe47acad98648b0a24899f22facba9eedeb02c8bffd4d2"}),
                .shielded_state_commitment = uint256{"827f8bf52ddf6de1e780a0917179dac715abeb428580744505dc30fbd6be5f9d"},
            },
            {
                // main assumeutxo snapshot at height 130'089
                .height = 130'089,
                .hash_serialized = AssumeutxoHash{uint256{"8c0b10247fe9a6a95a28744b7d80b96f1647db71bbc8cc5ba67f766ecd667310"}},
                .m_chain_tx_count = 161'703,
                .blockhash = consteval_ctor(uint256{"e3820082934a2b239142896d9d1f72fd23cd8930105073d792048a04f95bf3ba"}),
                .shielded_state_commitment = uint256{"7b9fce2384229984f916cdab106d6d29c2b38e206ff1045eb82b882d6adf28b2"},
            },
            {
                // main assumeutxo snapshot at height 130'501 (snapshot v9)
                .height = 130'501,
                .hash_serialized = AssumeutxoHash{uint256{"a86a235db93442efa1138b2756dac0ecbb3642965a72044af898bd3e4d3d417b"}},
                .m_chain_tx_count = 162'361,
                .blockhash = consteval_ctor(uint256{"1304900157e110b987ed7aab72d5d00d87046866a6fd80b3992721e3fd48f851"}),
                .shielded_state_commitment = uint256{"be3840420a5081b209567c31124a291d43290e9f8842dd5f47dc306ae05a68a1"},
            },
            {
                // main assumeutxo snapshot at height 132'142 (snapshot v9)
                .height = 132'142,
                .hash_serialized = AssumeutxoHash{uint256{"b8d8e09ed5a87ef2395013f4f9d7a2e1e45ae207c30ca6f9e349187926f8afdf"}},
                .m_chain_tx_count = 169'351,
                .blockhash = consteval_ctor(uint256{"6622f5f045e13160716e743255dd77684284c68d1feeab02844a8f5cb467ce3f"}),
                .shielded_state_commitment = uint256{"5d215cf4ed8cb9fbaddd2321cc996e0b754da0cfbd6055514a3cca78f7aa2792"},
            },
            {
                // main assumeutxo snapshot at height 132'173 (snapshot v9)
                .height = 132'173,
                .hash_serialized = AssumeutxoHash{uint256{"088b124e34af88441ce485deb0418d92c090983253956cb6c7c0d8249a747be2"}},
                .m_chain_tx_count = 169'410,
                .blockhash = consteval_ctor(uint256{"010aad22cd3c10caf33c049b08c34c46c86ec812c74ec5962a477916850ffb5b"}),
                .shielded_state_commitment = uint256{"5d215cf4ed8cb9fbaddd2321cc996e0b754da0cfbd6055514a3cca78f7aa2792"},
            },
            {
                // main assumeutxo snapshot at height 132'209 (snapshot v9)
                .height = 132'209,
                .hash_serialized = AssumeutxoHash{uint256{"56139bf25e3749650ec9f5608b417b0842fb99775b61b7433cfdee1768e40a0e"}},
                .m_chain_tx_count = 169'454,
                .blockhash = consteval_ctor(uint256{"9e6776ee8c5e8dceefcb108b429838be8bda3d66a6553d8b4c8cef613840c940"}),
                .shielded_state_commitment = uint256{"5d215cf4ed8cb9fbaddd2321cc996e0b754da0cfbd6055514a3cca78f7aa2792"},
            },
            {
                // main assumeutxo snapshot at height 155'700 (snapshot v9)
                .height = 155'700,
                .hash_serialized = AssumeutxoHash{uint256{"177c88216b700618cee432a3ca4f7c30c79fa3733666553484c5a22e283b777f"}},
                .m_chain_tx_count = 213'654,
                .blockhash = consteval_ctor(uint256{"b5ea1fb02d12e1cfa4bbc5ccc4946ca026ad4a5f270b99a0816aa95853306c3d"}),
                .shielded_state_commitment = uint256{"d8abf2d33319a2030c34c68dd50cfda10ececdd95f5a85bdbe05d44b334fbe9d"},
            },
            {
                // main assumeutxo snapshot at height 176'600 (snapshot v9)
                .height = 176'600,
                .hash_serialized = AssumeutxoHash{uint256{"d2bee157092f877553d0651d79922eb97293161d7515147421fe63102048ff93"}},
                .m_chain_tx_count = 271'654,
                .blockhash = consteval_ctor(uint256{"d5ba7a35a8a61b89de1b0289a6655551909f0491193ddd7620aebbea37a3beaa"}),
                .shielded_state_commitment = uint256{"c0f3bde58e1138367a6cd2b0131975de8fad9c90a991f88a42e9397d742b77ce"},
            },
            {
                // main assumeutxo snapshot at height 179'000 (snapshot v9)
                .height = 179'000,
                .hash_serialized = AssumeutxoHash{uint256{"eaefa544df815ca35037024923166be89232884faa541d8a40c57481be30857c"}},
                .m_chain_tx_count = 274'878,
                .blockhash = consteval_ctor(uint256{"2dd1d545b1b5e76c28b4414ebe0c22b1ba9d3ebd88662fbd1b9e4d0cf6693933"}),
                .shielded_state_commitment = uint256{"74a131a91f71cb7e488c1826eb3d5676802a586bddb8082b33356568d7def0b5"},
            },
            {
                // main assumeutxo snapshot at height 189'307 (snapshot v9)
                .height = 189'307,
                .hash_serialized = AssumeutxoHash{uint256{"48da3da953130984036435da93847ebe7d1a20fc5464d789b07f49b79178e074"}},
                .m_chain_tx_count = 287'404,
                .blockhash = consteval_ctor(uint256{"bd8c44a30103613a34ac271b7cfffb4334b70aae9c41cf12831d98a98313e6c8"}),
                .shielded_state_commitment = uint256{"94343b766b39c0ea2d92d83323f77b5ccc5e775d99b34b01f5fa6400f2354541"},
            },
        };
        chainTxData = ChainTxData{
            .nTime = 1785786086,
            .tx_count = 274878,
            .dTxRate = 0.015165177474,
        };
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 525000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        // MatMul powLimit calibrated assuming T_attempt ~0.6ms per solve attempt (n=256)
        // targeting ~0.25s fast-phase blocks on single modern GPU reference hardware.
        consensus.powLimit = uint256{"027525460aa64c2f837b4a2339c0ebedfa43fe5c91d14e3bcd35a858793dd970"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 90;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = false;
        consensus.fKAWPOW = false;
        consensus.fSkipKAWPOWValidation = false;
        consensus.fReducedDataLimits = true;
        consensus.fEnforceP2MROnlyOutputs = true;
        consensus.nKAWPOWHeight = std::numeric_limits<int>::max();
        consensus.fMatMulPOW = true;
        consensus.nMatMulDimension = 256;
        consensus.nMatMulTranscriptBlockSize = 8;
        consensus.nMatMulNoiseRank = 4;
        consensus.nMatMulValidationWindow = 500;
        consensus.nMatMulPhase2FailBanThreshold = std::numeric_limits<uint32_t>::max();
        consensus.fMatMulStrictPunishment = false;
        consensus.nMatMulSnapshotInterval = 10'000;
        consensus.fMatMulFreivaldsEnabled = true;
        consensus.nMatMulFreivaldsRounds = 2;
        consensus.fMatMulRequireProductPayload = true;
        consensus.nMatMulFreivaldsBindingHeight = 61'000;
        consensus.nMatMulProductDigestHeight = 61'000;
        // MatMul v4 (doc/btx-matmul-v4-design-spec.md): enabled on testnet only,
        // for testing.
        //
        // AUDIT UA-1 (activation policy): the MatMul upgrade is a UNIFIED direct
        // v3 -> v4.2/ENC-BMX4C transition -- there is NO public ENC-S8 (v4.1)
        // interval, so nMatMulV4Height and nMatMulBMX4CHeight must be EQUAL on
        // every activated public network. The prior staged 200,000 -> 250,000
        // testnet schedule is WITHDRAWN. Until every activation gate passes
        // (C1 authenticated chainwork, safe header nonce/wire, calibrated
        // v3->v4.2 rescale, size coherence, proof relay/storage, per-device
        // backend qualification, cross-platform evidence), public testnet stays
        // DISABLED. When testnet activation is eventually approved, assign the
        // SAME height to both fields (nMatMulV4Height == nMatMulBMX4CHeight ==
        // H_TESTNET) and re-derive the single BMX4-C ASERT rescale from measured
        // marginal nonce/s (spec §8.4, ACTIVATION Gate C); do NOT reinstate a
        // staged v4.1 phase. The v4 rescale stays inert 1/1 (the BMX4-C rescale
        // carries the whole calibrated transition).
        consensus.nMatMulV4Height = std::numeric_limits<int32_t>::max();
        consensus.nMatMulV4Dimension = 4096;
        // Accepted-dimension bounds (spec §G.2): production testnet uses the
        // 4096..8192 window; the exact dimension (4096) is still enforced
        // separately in ContextualCheckBlockHeader.
        consensus.nMatMulV4MinDimension = 4096;
        consensus.nMatMulV4MaxDimension = 8192;
        consensus.nMatMulV4FreivaldsRounds = 3;
        consensus.nMatMulV4TranscriptBlockSize = 4; // v4.1 batched-sketch profile (spec §K.2b): m = n/4, 8 MiB payload at n=4096
        // DoS verify budgets above the v4 fork (spec §I.5). Audit DoS re-pricing:
        // the original 16/4 caps were sized for the O(n^2) Freivalds check, but
        // v4.4 ENC-DR now admits the O(n^3) sketch RECOMPUTE (~seconds per verify),
        // so lower them CONSERVATIVELY to 4/min global and 2/min per peer pending
        // the release-blocking bench. Honest block production is << 1/min, so even
        // 4/min leaves ample headroom; a future benchmark may raise these.
        consensus.nMatMulV4GlobalVerifyBudgetPerMin = 4;
        consensus.nMatMulV4PeerVerifyBudgetPerMin = 2;
        // No empirical v3->v4 throughput benchmark exists yet for testnet
        // reference hardware, so leave the one-time ASERT rescale at 1/1
        // ("no rescale"); testnet is fPowAllowMinDifficultyBlocks, so a
        // miscalibrated rescale does not risk a liveness stall the way it
        // would on mainnet (spec §I.4).
        consensus.nMatMulV4AsertRescaleNum = 1;
        consensus.nMatMulV4AsertRescaleDen = 1;
        // MatMul v4.2 / ENC-BMX4C encoding-profile hard fork
        // (doc/btx-matmul-v4.2-bmx4c-spec.md §7-§8). AUDIT UA-1: DISABLED on
        // public testnet (== nMatMulV4Height above), withdrawing the staged
        // 250,000 placeholder. At the eventual unified activation height this
        // MUST equal nMatMulV4Height, and the single calibrated v3->ENC-BMX4C
        // work-unit transition is applied HERE (via the BMX4-C rescale below),
        // not at any separate v4.1 date. The ENC-BMX4C marginal unit differs
        // from v3's, so on a network with pre-fork history the rescale MUST be
        // re-derived from measurement before it is set to anything other than
        // 1/1 -- which is why activation stays disabled until Gate C completes.
        consensus.nMatMulBMX4CHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulBMX4CAsertRescaleNum = 1;
        consensus.nMatMulBMX4CAsertRescaleDen = 1;
        // v4.4-LT Rank-1 (MatExpand + deep-m + Q*): STAGED / inert until GO/NO-GO.
        consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulConsensusQStar = 256;
        consensus.nMatMulLTTranscriptBlockSize = 2;
        consensus.nMatMulDRLTAsertRescaleNum = 1;
        consensus.nMatMulDRLTAsertRescaleDen = 1;
        // Q* Phase B seal-as-PoW: implemented but OFF (inert; DRLT is INT32_MAX).
        consensus.fMatMulLTSealAsPoW = false;
        // Stage measured Epoch-A Profile-1 RC ASERT while public RC height stays
        // disabled (same calibration as mainnet).
        consensus.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulRCProfile = 1;
        consensus.nMatMulRCAsertRescaleNum = 1;  // inert: RC height disabled on this network
        consensus.nMatMulRCAsertRescaleDen = 1;
        consensus.nMaxReorgDepth = 12;
        consensus.nReorgProtectionStartHeight = 61'000;
        consensus.nEmptyBlockSubsidyPenaltyHeight = BTX_EMPTY_BLOCK_SUBSIDY_PENALTY_HEIGHT;
        consensus.nEmptyBlockSubsidyStrictPenaltyHeight = BTX_V03210_HARDENING_HEIGHT;
        consensus.nEmptyBlockSubsidyPenaltyEndHeight = BTX_V03211_HARDENING_HEIGHT;
        consensus.nPowTargetSpacingFastMs = 250;
        consensus.nFastMineDifficultyScale = 4;
        consensus.nPowTargetSpacingNormal = 90;
        consensus.nFastMineHeight = 61'000;
        // DGW is NOT used for MatMul mining -- ASERT only. See pow.cpp.
        consensus.nDgwAsymmetricClampHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwEasingBoostHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwWindowAlignmentHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwSlewGuardHeight = std::numeric_limits<int32_t>::max();
        // ASERT activates at nFastMineHeight. This MUST equal nFastMineHeight.
        consensus.nMatMulAsertHeight = 61'000;
        consensus.nMatMulAsertHalfLife = 3'600;
        consensus.nMatMulAsertBootstrapFactor = 180;
        // No retune or half-life upgrade needed — fresh chain starts with
        // the target 3,600s half-life directly.
        consensus.nMatMulAsertRetuneHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetuneHardeningFactor = 1;
        consensus.nMatMulAsertRetune2Height = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetune2TargetNum = 1;
        consensus.nMatMulAsertRetune2TargetDen = 1;
        consensus.nMatMulAsertHalfLifeUpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertHalfLifeUpgrade = 3'600;
        // Hardened pre-hash epsilon (18 bits) active from ASERT activation.
        consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = 61'000;
        consensus.nMatMulPreHashEpsilonBitsUpgrade = 18;
        consensus.nMatMulNonceSeedHeight = 125'000;
        consensus.nMatMulParentMtpSeedHeight = BTX_V03210_HARDENING_HEIGHT;
        consensus.nMaxBlockWeight = 24'000'000;
        consensus.nMaxBlockSerializedSize = 24'000'000;
        consensus.nMaxBlockSigOpsCost = 480'000;
        consensus.nDefaultBlockMaxWeight = 24'000'000;
        consensus.nDefaultMempoolMaxSizeMB = 2048;
        consensus.nMaxShieldedTxSize = 6'500'000;
        consensus.nMaxShieldedRingSize = 32;
        consensus.nShieldedMerkleTreeDepth = 32;
        consensus.nShieldedPoolActivationHeight = 0;
        consensus.nShieldedTxBindingActivationHeight = 61'000;
        consensus.nShieldedBridgeTagActivationHeight = 61'000;
        consensus.nShieldedSmileRiceCodecDisableHeight = 61'000;
        consensus.nShieldedMatRiCTDisableHeight = 61'000;
        consensus.nShieldedSpendPathRecoveryActivationHeight = 88'000;
        consensus.nShieldedPQ128UpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nShieldedPoolCreditDisableHeight = BTX_SHIELDED_POOL_CREDIT_DISABLE_HEIGHT;
        consensus.nShieldedSunsetHeight = BTX_SHIELDED_SUNSET_HEIGHT;
        consensus.nShieldedDirectSendPublicFlowDisableHeight = BTX_SHIELDED_DIRECT_SEND_PUBLIC_FLOW_DISABLE_HEIGHT;
        consensus.nContentEliminationHeight = BTX_CONTENT_ELIMINATION_HEIGHT;
        consensus.nShieldedV2SendZeroOutputExitActivationHeight =
            BTX_SHIELDED_V2_SEND_ZERO_OUTPUT_EXIT_ACTIVATION_HEIGHT;
        consensus.nShieldedRecoveryExitActivationHeight = BTX_SHIELDED_SUNSET_HEIGHT;
        // v0.32.0-v0.32.12: shielded unshield (z->t) velocity cap from the 125,000
        // sunset through block 134,999. The v0.32.11 minimum-cap floor still starts at
        // 132,000, and v0.32.12 ends the quota at 135,000 after the recovery window has
        // matured so remaining legacy exits are no longer rate-limited.
        consensus.nShieldedUnshieldVelocityActivationHeight = BTX_SHIELDED_SUNSET_HEIGHT;
        consensus.nShieldedUnshieldVelocityEndHeight = BTX_SHIELDED_UNSHIELD_VELOCITY_END_HEIGHT;
        consensus.nShieldedUnshieldVelocityMinCapHeight = BTX_V03211_HARDENING_HEIGHT;
        consensus.nShieldedUnshieldVelocityMinCap = BTX_SHIELDED_UNSHIELD_VELOCITY_MIN_CAP;
        consensus.nShieldedSettlementAnchorMaturity = 6;
        consensus.nMLDSADisableHeight = std::numeric_limits<int32_t>::max();
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // Bootstrap floor: disabled (zero) for young chain; update once the
        // chain has matured and a representative cumulative work is known.
        consensus.nMinimumChainWork = uint256{};
        // Assume signatures valid up to genesis (updated post-launch).
        consensus.defaultAssumeValid = uint256{"f2bc3fb2eca6aa6059c4d0178b56efe038d46aa440d406905ef752179aa0e1a4"};

        pchMessageStart[0] = 0xb7;
        pchMessageStart[1] = 0x54;
        pchMessageStart[2] = 0x58;
        pchMessageStart[3] = 0x02;
        nDefaultPort = 29335;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateBTXGenesisBlock(
            1773878400,  // Mar 19, 2026 — SMILE v2 chain restart
            0,
            238,
            0x20027525,
            1,
            consensus.nInitialSubsidy,
            static_cast<uint16_t>(consensus.nMatMulDimension),
            uint256{"00230371b05217711a10cf44983c2ffc3d82da06369fd0e640b6d20c033e38da"});
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"f2bc3fb2eca6aa6059c4d0178b56efe038d46aa440d406905ef752179aa0e1a4"});
        assert(genesis.hashMerkleRoot == uint256{"94ae75cb0cd5f08b9447306ae914635d1c36d1a43d330daf596957e91cee002a"});
        Consensus::FillDefaultRCGrowthTables(consensus);
        AssertBMX4CConstructionInvariants(consensus, /*is_regtest=*/false);

        // Testnet DNS seeds mirror mainnet domains; fixed seeds provide fallback.
        vSeeds.clear();
        vSeeds.emplace_back("testnet.btxchain.org.");
        vSeeds.emplace_back("testnet.btx.dev.");
        vSeeds.emplace_back("testnet.btx.tools.");
        vFixedSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tbtx";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        m_assumeutxo_data = {};

        chainTxData = ChainTxData{
            .nTime = 0,
            .tx_count = 0,
            .dTxRate = 0,
        };
    }
};

/**
 * Testnet (v4): public test network which is reset from time to time.
 */
class CTestNet4Params : public CChainParams {
public:
    CTestNet4Params() {
        m_chain_type = ChainType::TESTNET4;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 525000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        // MatMul powLimit calibrated assuming T_attempt ~0.6ms per solve attempt (n=256)
        // targeting ~0.25s fast-phase blocks on single modern GPU reference hardware.
        consensus.powLimit = uint256{"027525460aa64c2f837b4a2339c0ebedfa43fe5c91d14e3bcd35a858793dd970"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 90;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = false;
        consensus.fKAWPOW = false;
        consensus.fSkipKAWPOWValidation = false;
        consensus.fReducedDataLimits = true;
        consensus.fEnforceP2MROnlyOutputs = true;
        consensus.nKAWPOWHeight = std::numeric_limits<int>::max();
        consensus.fMatMulPOW = true;
        consensus.nMatMulDimension = 256;
        consensus.nMatMulTranscriptBlockSize = 8;
        consensus.nMatMulNoiseRank = 4;
        consensus.nMatMulValidationWindow = 500;
        consensus.nMatMulPhase2FailBanThreshold = std::numeric_limits<uint32_t>::max();
        consensus.fMatMulStrictPunishment = false;
        consensus.nMatMulSnapshotInterval = 10'000;
        consensus.fMatMulFreivaldsEnabled = true;
        consensus.nMatMulFreivaldsRounds = 2;
        consensus.fMatMulRequireProductPayload = true;
        consensus.nMatMulFreivaldsBindingHeight = 61'000;
        consensus.nMatMulProductDigestHeight = 61'000;
        consensus.nMaxReorgDepth = 12;
        consensus.nReorgProtectionStartHeight = 61'000;
        consensus.nEmptyBlockSubsidyPenaltyHeight = BTX_EMPTY_BLOCK_SUBSIDY_PENALTY_HEIGHT;
        consensus.nEmptyBlockSubsidyStrictPenaltyHeight = BTX_V03210_HARDENING_HEIGHT;
        consensus.nEmptyBlockSubsidyPenaltyEndHeight = BTX_V03211_HARDENING_HEIGHT;
        consensus.nPowTargetSpacingFastMs = 250;
        consensus.nFastMineDifficultyScale = 4;
        consensus.nPowTargetSpacingNormal = 90;
        consensus.nFastMineHeight = 61'000;
        // DGW is NOT used for MatMul mining -- ASERT only. See pow.cpp.
        consensus.nDgwAsymmetricClampHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwEasingBoostHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwWindowAlignmentHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwSlewGuardHeight = std::numeric_limits<int32_t>::max();
        // ASERT activates at nFastMineHeight. This MUST equal nFastMineHeight.
        consensus.nMatMulAsertHeight = 61'000;
        consensus.nMatMulAsertHalfLife = 3'600;
        consensus.nMatMulAsertBootstrapFactor = 180;
        // No retune or half-life upgrade needed — fresh chain starts with
        // the target 3,600s half-life directly.
        consensus.nMatMulAsertRetuneHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetuneHardeningFactor = 1;
        consensus.nMatMulAsertRetune2Height = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetune2TargetNum = 1;
        consensus.nMatMulAsertRetune2TargetDen = 1;
        consensus.nMatMulAsertHalfLifeUpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertHalfLifeUpgrade = 3'600;
        // Hardened pre-hash epsilon (18 bits) active from ASERT activation.
        consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = 61'000;
        consensus.nMatMulPreHashEpsilonBitsUpgrade = 18;
        consensus.nMatMulNonceSeedHeight = 125'000;
        consensus.nMatMulParentMtpSeedHeight = BTX_V03210_HARDENING_HEIGHT;
        consensus.nMaxBlockWeight = 24'000'000;
        consensus.nMaxBlockSerializedSize = 24'000'000;
        consensus.nMaxBlockSigOpsCost = 480'000;
        consensus.nDefaultBlockMaxWeight = 24'000'000;
        consensus.nDefaultMempoolMaxSizeMB = 2048;
        consensus.nMaxShieldedTxSize = 6'500'000;
        consensus.nMaxShieldedRingSize = 32;
        consensus.nShieldedMerkleTreeDepth = 32;
        consensus.nShieldedPoolActivationHeight = 0;
        consensus.nShieldedTxBindingActivationHeight = 61'000;
        consensus.nShieldedBridgeTagActivationHeight = 61'000;
        consensus.nShieldedSmileRiceCodecDisableHeight = 61'000;
        consensus.nShieldedMatRiCTDisableHeight = 61'000;
        consensus.nShieldedSpendPathRecoveryActivationHeight = 88'000;
        consensus.nShieldedPQ128UpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nShieldedPoolCreditDisableHeight = BTX_SHIELDED_POOL_CREDIT_DISABLE_HEIGHT;
        consensus.nShieldedSunsetHeight = BTX_SHIELDED_SUNSET_HEIGHT;
        consensus.nShieldedDirectSendPublicFlowDisableHeight = BTX_SHIELDED_DIRECT_SEND_PUBLIC_FLOW_DISABLE_HEIGHT;
        consensus.nContentEliminationHeight = BTX_CONTENT_ELIMINATION_HEIGHT;
        consensus.nShieldedV2SendZeroOutputExitActivationHeight =
            BTX_SHIELDED_V2_SEND_ZERO_OUTPUT_EXIT_ACTIVATION_HEIGHT;
        consensus.nShieldedRecoveryExitActivationHeight = BTX_SHIELDED_SUNSET_HEIGHT;
        // v0.32.0-v0.32.12: shielded unshield (z->t) velocity cap from the 125,000
        // sunset through block 134,999. The v0.32.11 minimum-cap floor still starts at
        // 132,000, and v0.32.12 ends the quota at 135,000 after the recovery window has
        // matured so remaining legacy exits are no longer rate-limited.
        consensus.nShieldedUnshieldVelocityActivationHeight = BTX_SHIELDED_SUNSET_HEIGHT;
        consensus.nShieldedUnshieldVelocityEndHeight = BTX_SHIELDED_UNSHIELD_VELOCITY_END_HEIGHT;
        consensus.nShieldedUnshieldVelocityMinCapHeight = BTX_V03211_HARDENING_HEIGHT;
        consensus.nShieldedUnshieldVelocityMinCap = BTX_SHIELDED_UNSHIELD_VELOCITY_MIN_CAP;
        consensus.nShieldedSettlementAnchorMaturity = 6;
        consensus.nMLDSADisableHeight = std::numeric_limits<int32_t>::max();
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // Bootstrap floor: disabled (zero) for young chain; update once the
        // chain has matured and a representative cumulative work is known.
        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{"f2bc3fb2eca6aa6059c4d0178b56efe038d46aa440d406905ef752179aa0e1a4"};

        pchMessageStart[0] = 0x1c;
        pchMessageStart[1] = 0x16;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x28;
        nDefaultPort = 48333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateBTXGenesisBlock(
            1773878400,  // Mar 19, 2026 — SMILE v2 chain restart
            0,
            238,
            0x20027525,
            1,
            consensus.nInitialSubsidy,
            static_cast<uint16_t>(consensus.nMatMulDimension),
            uint256{"00230371b05217711a10cf44983c2ffc3d82da06369fd0e640b6d20c033e38da"});
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"f2bc3fb2eca6aa6059c4d0178b56efe038d46aa440d406905ef752179aa0e1a4"});
        assert(genesis.hashMerkleRoot == uint256{"94ae75cb0cd5f08b9447306ae914635d1c36d1a43d330daf596957e91cee002a"});
        // Audit W-2 / ASERT-F1: BMX4C construction invariants (no-op while unset).
        consensus.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulRCProfile = 1;
        consensus.nMatMulRCAsertRescaleNum = 1;  // inert: RC height disabled on this network
        consensus.nMatMulRCAsertRescaleDen = 1;
        Consensus::FillDefaultRCGrowthTables(consensus);
        AssertBMX4CConstructionInvariants(consensus, /*is_regtest=*/false);

        vSeeds.clear();
        vSeeds.emplace_back("testnet4.btxchain.org.");
        vSeeds.emplace_back("testnet4.btx.dev.");
        vSeeds.emplace_back("testnet4.btx.tools.");
        vFixedSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tbtx4";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        m_assumeutxo_data = {};

        chainTxData = ChainTxData{
            .nTime = 0,
            .tx_count = 0,
            .dTxRate = 0,
        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vFixedSeeds.clear();
        vSeeds.clear();

        if (!options.challenge) {
            // BTX does not operate a default signet.  When no custom
            // --signetchallenge is provided, use a trivial OP_TRUE
            // challenge so that tests and tooling can instantiate signet
            // params without crashing.  This creates an isolated signet
            // that cannot connect to any real network.
            //
            // Note: this constructor is also called from ChainTypeFromMagic()
            // during startup for message-magic detection, so we only log a
            // warning when -signet was explicitly selected (options.seeds is
            // populated or the caller is creating params for actual use).
            bin = {0x51};
        } else {
            bin = *options.challenge;
            LogPrintf("Signet with challenge %s\n", HexStr(bin));
        }

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;
        chainTxData = ChainTxData{
            0,
            0,
            0,
        };

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 525000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = options.pow_target_spacing;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = false;
        consensus.fKAWPOW = false;
        consensus.fSkipKAWPOWValidation = false;
        consensus.fReducedDataLimits = true;
        consensus.fEnforceP2MROnlyOutputs = true;
        consensus.nKAWPOWHeight = std::numeric_limits<int>::max();
        consensus.fMatMulPOW = true;
        consensus.nMatMulDimension = 256;
        consensus.nMatMulTranscriptBlockSize = 8;
        consensus.nMatMulNoiseRank = 4;
        consensus.nMatMulValidationWindow = 500;
        consensus.nMatMulPhase2FailBanThreshold = std::numeric_limits<uint32_t>::max();
        consensus.fMatMulStrictPunishment = false;
        consensus.nMatMulSnapshotInterval = 10'000;
        consensus.fMatMulFreivaldsEnabled = true;
        consensus.nMatMulFreivaldsRounds = 2;
        consensus.fMatMulRequireProductPayload = true;
        consensus.nMatMulFreivaldsBindingHeight = 61'000;
        consensus.nMatMulProductDigestHeight = 61'000;
        consensus.nMaxReorgDepth = 12;
        consensus.nReorgProtectionStartHeight = 61'000;
        consensus.nEmptyBlockSubsidyPenaltyHeight = BTX_EMPTY_BLOCK_SUBSIDY_PENALTY_HEIGHT;
        consensus.nEmptyBlockSubsidyStrictPenaltyHeight = BTX_V03210_HARDENING_HEIGHT;
        consensus.nEmptyBlockSubsidyPenaltyEndHeight = BTX_V03211_HARDENING_HEIGHT;
        consensus.nPowTargetSpacingFastMs = 250;
        consensus.nFastMineDifficultyScale = 4;
        consensus.nPowTargetSpacingNormal = 90;
        consensus.nFastMineHeight = 61'000;
        // DGW is NOT used for MatMul mining -- ASERT only. See pow.cpp.
        consensus.nDgwAsymmetricClampHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwEasingBoostHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwWindowAlignmentHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwSlewGuardHeight = std::numeric_limits<int32_t>::max();
        // ASERT activates at nFastMineHeight. This MUST equal nFastMineHeight.
        consensus.nMatMulAsertHeight = 61'000;
        consensus.nMatMulAsertHalfLife = 3'600;
        consensus.nMatMulAsertBootstrapFactor = 180;
        // No retune or half-life upgrade needed — fresh chain starts with
        // the target 3,600s half-life directly.
        consensus.nMatMulAsertRetuneHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetuneHardeningFactor = 1;
        consensus.nMatMulAsertRetune2Height = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertRetune2TargetNum = 1;
        consensus.nMatMulAsertRetune2TargetDen = 1;
        consensus.nMatMulAsertHalfLifeUpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertHalfLifeUpgrade = 3'600;
        // Hardened pre-hash epsilon (18 bits) active from ASERT activation.
        consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = 61'000;
        consensus.nMatMulPreHashEpsilonBitsUpgrade = 18;
        consensus.nMatMulNonceSeedHeight = 125'000;
        consensus.nMatMulParentMtpSeedHeight = BTX_V03210_HARDENING_HEIGHT;
        consensus.nMaxBlockWeight = 24'000'000;
        consensus.nMaxBlockSerializedSize = 24'000'000;
        consensus.nMaxBlockSigOpsCost = 480'000;
        consensus.nDefaultBlockMaxWeight = 24'000'000;
        consensus.nDefaultMempoolMaxSizeMB = 2048;
        consensus.nMaxShieldedTxSize = 6'500'000;
        consensus.nMaxShieldedRingSize = 32;
        consensus.nShieldedMerkleTreeDepth = 32;
        consensus.nShieldedPoolActivationHeight = 0;
        consensus.nShieldedTxBindingActivationHeight = 61'000;
        consensus.nShieldedBridgeTagActivationHeight = 61'000;
        consensus.nShieldedSmileRiceCodecDisableHeight = 61'000;
        consensus.nShieldedMatRiCTDisableHeight = 61'000;
        consensus.nShieldedSpendPathRecoveryActivationHeight = 88'000;
        consensus.nShieldedPQ128UpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nShieldedPoolCreditDisableHeight = BTX_SHIELDED_POOL_CREDIT_DISABLE_HEIGHT;
        consensus.nShieldedSunsetHeight = BTX_SHIELDED_SUNSET_HEIGHT;
        consensus.nShieldedDirectSendPublicFlowDisableHeight = BTX_SHIELDED_DIRECT_SEND_PUBLIC_FLOW_DISABLE_HEIGHT;
        consensus.nContentEliminationHeight = BTX_CONTENT_ELIMINATION_HEIGHT;
        consensus.nShieldedV2SendZeroOutputExitActivationHeight =
            BTX_SHIELDED_V2_SEND_ZERO_OUTPUT_EXIT_ACTIVATION_HEIGHT;
        consensus.nShieldedRecoveryExitActivationHeight = BTX_SHIELDED_SUNSET_HEIGHT;
        // v0.32.0-v0.32.12: shielded unshield (z->t) velocity cap from the 125,000
        // sunset through block 134,999. The v0.32.11 minimum-cap floor still starts at
        // 132,000, and v0.32.12 ends the quota at 135,000 after the recovery window has
        // matured so remaining legacy exits are no longer rate-limited.
        consensus.nShieldedUnshieldVelocityActivationHeight = BTX_SHIELDED_SUNSET_HEIGHT;
        consensus.nShieldedUnshieldVelocityEndHeight = BTX_SHIELDED_UNSHIELD_VELOCITY_END_HEIGHT;
        consensus.nShieldedUnshieldVelocityMinCapHeight = BTX_V03211_HARDENING_HEIGHT;
        consensus.nShieldedUnshieldVelocityMinCap = BTX_SHIELDED_UNSHIELD_VELOCITY_MIN_CAP;
        consensus.nShieldedSettlementAnchorMaturity = 6;
        consensus.nMLDSADisableHeight = std::numeric_limits<int32_t>::max();
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"027525460aa64c2f837b4a2339c0ebedfa43fe5c91d14e3bcd35a858793dd970"};
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 38333;
        nPruneAfterHeight = 1000;

        // Reuse the testnet genesis block for signet.
        genesis = CreateBTXGenesisBlock(
            1773878400,  // Mar 19, 2026 — SMILE v2 chain restart
            0,
            238,
            0x20027525,
            1,
            consensus.nInitialSubsidy,
            static_cast<uint16_t>(consensus.nMatMulDimension),
            uint256{"00230371b05217711a10cf44983c2ffc3d82da06369fd0e640b6d20c033e38da"});
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"f2bc3fb2eca6aa6059c4d0178b56efe038d46aa440d406905ef752179aa0e1a4"});
        assert(genesis.hashMerkleRoot == uint256{"94ae75cb0cd5f08b9447306ae914635d1c36d1a43d330daf596957e91cee002a"});

        m_assumeutxo_data = {};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tbtx";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        // Audit review Finding 2: signet enables MatMul PoW (fMatMulPOW = true),
        // so it must enforce the same construction invariants as the other MatMul
        // networks -- H2 header-PoW discount range, D1 ASERT-schedule validity,
        // I1 tile size, and the BMX4C profile checks. (No-op today: signet leaves
        // v4/bmx4c disabled and the discount at the UINT32_MAX default.)
        consensus.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulRCProfile = 1;
        consensus.nMatMulRCAsertRescaleNum = 1;  // inert: RC height disabled on this network
        consensus.nMatMulRCAsertRescaleDen = 1;
        Consensus::FillDefaultRCGrowthTables(consensus);
        AssertBMX4CConstructionInvariants(consensus, /*is_regtest=*/false);
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = 0; // Always active unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = 90;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = opts.enforce_bip94;
        consensus.fPowNoRetargeting = true;
        consensus.fKAWPOW = false;
        consensus.fSkipKAWPOWValidation = !opts.matmul_strict;
        consensus.fReducedDataLimits = true;
        consensus.fEnforceP2MROnlyOutputs = false;
        consensus.nKAWPOWHeight = std::numeric_limits<int>::max();
        consensus.fMatMulPOW = true;
        consensus.fSkipMatMulValidation = !opts.matmul_strict;
        consensus.nMatMulDimension = 64;
        consensus.nMatMulTranscriptBlockSize = 8;
        consensus.nMatMulNoiseRank = 4;
        consensus.nMatMulValidationWindow = 10;
        consensus.nMatMulPhase2FailBanThreshold = std::numeric_limits<uint32_t>::max();
        consensus.fMatMulStrictPunishment = false;
        consensus.nMatMulSnapshotInterval = 10'000;
        consensus.fMatMulFreivaldsEnabled = true;
        consensus.nMatMulFreivaldsRounds = 2;
        consensus.fMatMulRequireProductPayload = true;
        consensus.nMatMulFreivaldsBindingHeight = 0;
        consensus.nMatMulProductDigestHeight = 0;
        consensus.nMatMulPreHashEpsilonBits = 0; // Disable pre-hash filter for fast regtest mining
        consensus.nMatMulPreHashEpsilonBitsUpgrade = consensus.nMatMulPreHashEpsilonBits;
        consensus.nMatMulGlobalVerifyBudgetPerMin = std::numeric_limits<uint32_t>::max(); // No global budget limit in regtest
        // MatMul v4 (doc/btx-matmul-v4-design-spec.md): enabled on regtest at a
        // low, non-genesis height so tests can mine both sides of the fork
        // (matches the spec's own regtest recommendation, §G.2, which also
        // gives regtest n=256). n is kept small relative to the production
        // default of 4096 (a real dense INT8 GEMM at n=4096 is ~6.9e10
        // ops/attempt, far too slow for a nonce-search loop on regtest/CI
        // reference hardware), and deliberately DIFFERENT from the v3
        // regtest dimension (64, set above) rather than reusing it: Phase1
        // (CheckMatMulProofOfWork_Phase1) is context-free and cannot see
        // height, so it accepts either the v3 or the v4 dimension whenever
        // both are configured. Keeping them numerically distinct means a
        // pre-fork block can never be Phase1-ambiguous with a post-fork
        // dimension; the exact height-gated dimension is still authoritative
        // at ContextualCheckBlockHeader/ContextualCheckBlock. R=2 (below the
        // R=3 production normative) is reserved for regtest per spec §0.7/§G.2.
        consensus.nMatMulV4Height = 100;
        consensus.nMatMulV4Dimension = 256;
        // Accepted-dimension bounds (spec §G.2): regtest uses the wide 64..1024
        // window (n=256 sits inside it) so bounds-rejection paths can be
        // exercised without recompiling; the exact dimension (256) is still
        // enforced separately in ContextualCheckBlockHeader.
        consensus.nMatMulV4MinDimension = 64;
        consensus.nMatMulV4MaxDimension = 1024;
        consensus.nMatMulV4FreivaldsRounds = 2;
        consensus.nMatMulV4TranscriptBlockSize = 4; // v4.1 batched-sketch profile (spec §K.2b): m = n/4, 8 MiB payload at n=4096
        // Regtest must mine both fork sides fast; do not throttle v4 verify
        // (mirrors the v3 "no global budget limit in regtest" choice above).
        consensus.nMatMulV4GlobalVerifyBudgetPerMin = std::numeric_limits<uint32_t>::max();
        consensus.nMatMulV4PeerVerifyBudgetPerMin = std::numeric_limits<uint32_t>::max();
        consensus.nMatMulV4AsertRescaleNum = 1;
        consensus.nMatMulV4AsertRescaleDen = 1;
        // MatMul v4.2 / ENC-BMX4C (spec §7-§8): STRICT UNIFIED ACTIVATION (audit
        // P0.2) -- ENC-BMX4C activates at the SAME height as v4 (100), so regtest
        // mirrors production's single flag day (v3 -> v4.2/ENC-BMX4C directly) with
        // NO reachable ENC-S8 interval. The former staged 150 (an ENC-S8 window in
        // [100,150)) is withdrawn; -regtestbmx4cheight now sets BOTH heights
        // atomically (see below). The one-time ASERT rescale stays at 1/1 (regtest
        // has no pre-fork throughput history; fPowNoRetargeting /
        // fPowAllowMinDifficultyBlocks make a placeholder ratio safe here).
        consensus.nMatMulBMX4CHeight = 100;
        consensus.nMatMulBMX4CAsertRescaleNum = 1;
        consensus.nMatMulBMX4CAsertRescaleDen = 1;
        // Rank-1 LT + Phase B seal-as-PoW: LIVE on regtest at the unified v4/BMX4C
        // height (100) so functional tests exercise fat Q* seals immediately.
        // Override still available via -regtestdrltheight / -regtestmatmulltsealaspow.
        consensus.nMatMulDRLTHeight = 100;
        consensus.nMatMulConsensusQStar = 256;
        consensus.nMatMulLTTranscriptBlockSize = 2;
        consensus.nMatMulDRLTAsertRescaleNum = 1;
        consensus.nMatMulDRLTAsertRescaleDen = 1;
        consensus.fMatMulLTSealAsPoW = true;
        // LT tip-verify budgets: unthrottled on regtest (mirrors v4), so
        // -regtestdrltheight / seal-as-PoW functional tests are not paced.
        consensus.nMatMulLTMaxPendingVerifications = std::numeric_limits<uint32_t>::max();
        consensus.nMatMulLTGlobalVerifyBudgetPerMin = std::numeric_limits<uint32_t>::max();
        consensus.nMatMulLTPeerVerifyBudgetPerMin = std::numeric_limits<uint32_t>::max();
        // MatMul v4.7 Epoch A is the default regtest transition: Profile 1
        // ExactReplay activates at 101, one height after the v4/BMX4C/DRLT
        // fixture. Toy dimensions keep ordinary CI practical while exercising
        // the same authority switch. The unfinished ENC_RC_COUPLED/Stage-3 path
        // remains disabled by default and can still be activated explicitly by
        // -regtestrccoupledheight or -regtestrcunifiedheight for proof regression
        // tests. Public RC and coupled heights both remain INT32_MAX.
        consensus.nMatMulRCHeight = 101;
        consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();
        consensus.fMatMulRCUseToyDims = true;
        consensus.fMatMulRCCoupledUseToyDims = true;
        consensus.nPowTargetSpacingFastMs = 250;
        consensus.nFastMineDifficultyScale = 4;
        consensus.nPowTargetSpacingNormal = 90;
        consensus.nFastMineHeight = 0;
        // DGW is NOT used for MatMul mining -- ASERT only. See pow.cpp.
        consensus.nDgwAsymmetricClampHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwEasingBoostHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwWindowAlignmentHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwSlewGuardHeight = std::numeric_limits<int32_t>::max();
        // ASERT activates at nFastMineHeight (0 for regtest = immediate).
        consensus.nMatMulAsertHeight = 0;
        consensus.nMatMulAsertHalfLife = 14'400;
        if (opts.matmul_dgw) {
            consensus.fPowNoRetargeting = false;
            consensus.fPowAllowMinDifficultyBlocks = false;
            // Keep a short fast phase so tests can mine both phases and still
            // exercise ASERT retargeting at practical regtest speed.
            consensus.nFastMineHeight = 2;
            consensus.nMatMulAsertHeight = 2;
        }
        if (opts.matmul_binding_height.has_value()) {
            consensus.nMatMulFreivaldsBindingHeight = *opts.matmul_binding_height;
        }
        if (opts.matmul_product_digest_height.has_value()) {
            consensus.nMatMulProductDigestHeight = *opts.matmul_product_digest_height;
        }
        if (opts.matmul_require_product_payload.has_value()) {
            consensus.fMatMulRequireProductPayload = *opts.matmul_require_product_payload;
        }
        if (opts.matmul_dimension.has_value()) {
            consensus.nMatMulDimension = *opts.matmul_dimension;
        }
        if (opts.matmul_v4_height.has_value()) {
            consensus.nMatMulV4Height = *opts.matmul_v4_height;
        }
        if (opts.matmul_v4_dimension.has_value()) {
            consensus.nMatMulV4Dimension = *opts.matmul_v4_dimension;
        }
        // Regtest-only: raise the accepted-dimension ceiling so a functional test can
        // exercise a PRODUCTION-scale dimension (e.g. 4096 ⇒ D m=2048 ⇒ a real 32 MiB
        // segregated proof, the Stage-2d chunking/v2 path). 4096 is a legitimate MAINNET
        // dimension (CMainParams sets nMatMulV4MaxDimension = 8192), so this only lifts
        // regtest's default 1024 cap; the §8.1 combine-input bound
        // (BMX4C_PROJECTION_BOUND_PER_N * MaxDimension <= BMX4C_COMBINE_INPUT_BOUND) is
        // re-asserted in AssertBMX4CConstructionInvariants and still holds well past 4096.
        if (opts.matmul_v4_max_dimension.has_value()) {
            consensus.nMatMulV4MaxDimension = *opts.matmul_v4_max_dimension;
        }
        if (opts.matmul_bmx4c_height.has_value()) {
            consensus.nMatMulBMX4CHeight = *opts.matmul_bmx4c_height;
        }
        // AUDIT P0.2 (strict unified): the v4 and ENC-BMX4C heights must be equal.
        // A LONE -regtestmatmulv4height / -regtestbmx4cheight sets the OTHER to the
        // same height so a single override stays unified; supplying BOTH with
        // DIFFERENT values falls through to the strict-unified startup assert in
        // AssertBMX4CConstructionInvariants and fails loud (no staged ENC-S8 window).
        if (opts.matmul_v4_height.has_value() && !opts.matmul_bmx4c_height.has_value()) {
            consensus.nMatMulBMX4CHeight = consensus.nMatMulV4Height;
        }
        if (opts.matmul_bmx4c_height.has_value() && !opts.matmul_v4_height.has_value()) {
            consensus.nMatMulV4Height = consensus.nMatMulBMX4CHeight;
        }
        // v4.4-LT Rank-1: regtest-only height override so functional tests can
        // move the default height while public-network activation stays inert.
        // Applied AFTER the BMX4C unification above so a LONE -regtestdrltheight
        // (no explicit -regtestbmx4cheight) lands on top of whichever BMX4C
        // height is already final (100 by default, or the overridden value).
        if (opts.matmul_drlt_height.has_value()) {
            consensus.nMatMulDRLTHeight = *opts.matmul_drlt_height;
        }
        // ENC_RC / ENC_RC_COUPLED: regtest-only height + toy-dim overrides so
        // functional tests can exercise mine → relay → ExactReplay without
        // changing any public-network schedule. Applied AFTER
        // DRLT so a lone -regtestrcheight lands on top of the unified
        // v4/BMX4C/DRLT schedule. Toy dims are REQUIRED for CI-scale mining
        // (consensus n_ctx is not runnable in functional tests).
        // Legacy PR89 single-switch regression control: one height turns on
        // episode + coupled together. Applied FIRST so the granular
        // per-component overrides below can still refine a single component in a
        // regression test. The coupled profile default is already 3 (V3), so the
        // unified switch needs no profile override. This argument never changes
        // public parameters; Epoch-A mainnet uses its separately fixed Profile-1
        // height and keeps the coupled/Profile-2 height disabled.
        if (opts.matmul_rc_unified_height.has_value()) {
            consensus.nMatMulRCHeight = *opts.matmul_rc_unified_height;
            consensus.nMatMulRCCoupledHeight = *opts.matmul_rc_unified_height;
        }
        if (opts.matmul_rc_height.has_value()) {
            consensus.nMatMulRCHeight = *opts.matmul_rc_height;
        }
        if (opts.matmul_rc_coupled_height.has_value()) {
            consensus.nMatMulRCCoupledHeight = *opts.matmul_rc_coupled_height;
        }
        if (opts.matmul_rc_use_toy_dims.has_value()) {
            consensus.fMatMulRCUseToyDims = *opts.matmul_rc_use_toy_dims;
        }
        if (opts.matmul_rc_coupled_use_toy_dims.has_value()) {
            consensus.fMatMulRCCoupledUseToyDims = *opts.matmul_rc_coupled_use_toy_dims;
        }
        if (opts.matmul_rc_coupled_profile.has_value()) {
            consensus.nMatMulRCCoupledProfile = *opts.matmul_rc_coupled_profile;
        }
        // ENC_RC episode profile selector: regtest defaults to the MatMul v4.7
        // Epoch-A Profile 1 workload and may explicitly select the future
        // datacenter Profile 2 for regression testing. Stage-3 succinct authority
        // remains independently compile-time disabled. Invalid values fail closed.
        if (opts.matmul_rc_profile.has_value()) {
            consensus.nMatMulRCProfile = *opts.matmul_rc_profile;
        }
        // COUPLED ASERT: when the datacenter profile (2) is live at a finite RC
        // height on regtest, apply the exact 16422/1027 (~16×) one-time loosen together with
        // it (design §5) — mirrors the mainnet deploy where profile 2 + finite
        // height + 16422/1027 ASERT activate as one. Satisfies the coupled-trio invariant
        // in AssertBMX4CConstructionInvariants. (Behaviorally moot on CI toy dims
        // but keeps the activation shape faithful.)
        if (consensus.nMatMulRCProfile == 2 &&
            consensus.nMatMulRCHeight != std::numeric_limits<int32_t>::max()) {
            consensus.nMatMulRCAsertRescaleNum = kRCDatacenterAsertRescaleNum;
            consensus.nMatMulRCAsertRescaleDen = kRCDatacenterAsertRescaleDen;
        }
        // When RC (or coupled) is live on regtest, unthrottle tip-verify budgets
        // so -regtestrc* functional tests are not paced (mirrors LT above).
        if (consensus.nMatMulRCHeight != std::numeric_limits<int32_t>::max() ||
            consensus.nMatMulRCCoupledHeight != std::numeric_limits<int32_t>::max()) {
            consensus.nMatMulRCMaxPendingVerifications = std::numeric_limits<uint32_t>::max();
            consensus.nMatMulRCGlobalVerifyBudgetPerMin = std::numeric_limits<uint32_t>::max();
            consensus.nMatMulRCPeerVerifyBudgetPerMin = std::numeric_limits<uint32_t>::max();
        }
        // Test-only EncDr / RC pending-cap overrides. RC is applied after the
        // unthrottle above so a functional test can still exhaust the cap
        // without enlarging production defaults.
        if (opts.matmul_max_pending_verifications.has_value()) {
            consensus.nMatMulMaxPendingVerifications =
                *opts.matmul_max_pending_verifications;
        }
        if (opts.matmul_rc_max_pending_verifications.has_value()) {
            consensus.nMatMulRCMaxPendingVerifications =
                *opts.matmul_rc_max_pending_verifications;
        }
        // v4.4-LT Q* Phase B: explicit regtest override in either direction.
        // Regtest defaults to seal mode, while =0 retains a Phase-A fixture.
        // Enabling remains meaningful only together with a live DRLT height.
        if (opts.matmul_lt_seal_as_pow.has_value()) {
            consensus.fMatMulLTSealAsPoW = *opts.matmul_lt_seal_as_pow;
        }
        if (opts.matmul_lt_max_pending_verifications.has_value()) {
            consensus.nMatMulLTMaxPendingVerifications =
                *opts.matmul_lt_max_pending_verifications;
        }
        if (opts.matmul_flat_sketch_replay) {
            // v4.4 ENC-DR regtest-only differential switch: re-select the legacy
            // FLAT_SKETCH_INBLOCK carriage so golden-vector replay tests can
            // exercise the retired in-block path against the recompute path
            // (tension-resolution §5-2). Permitted here because this is the
            // REGTEST chain; public networks fail closed in
            // AssertBMX4CConstructionInvariants.
            consensus.fMatMulV4FlatSketchReplay = true;
        }
        // Audit dead-code deletion: the nMatMulProofPruneDepth field and its
        // -regtestmatmulproofprunedepth apply block were removed (dead since v4.4
        // ENC-DR -- no consensus/validation reader; the deleted segregated-proof
        // store left it inert). The arg registration in chainparamsbase.cpp
        // survives as a harmless unread no-op for arg compatibility.
        // MatMul v4.2-D assumevalid buried-proof trust min-age (design §3.5-2). The
        // production default is the 2-week equivalent-time DoS guard; at regtest's
        // 90 s spacing that is ~13 000 blocks, so the override lets a functional test
        // exercise the trust boundary after burying a D block by only a few blocks.
        // The trust still requires an assumed-valid ancestor with >= MinimumChainWork
        // of AUTHENTICATED work, so this regtest knob never weakens a real network.
        if (opts.matmul_proof_assumevalid_min_age.has_value()) {
            consensus.nMatMulProofAssumeValidMinAge = *opts.matmul_proof_assumevalid_min_age;
        }
        // Spec §G.2/§G.4: the v4 dimension must divide evenly by the sketch
        // tile size and stay within the accepted-dimension bounds enforced in
        // ContextualCheckBlockHeader, so a bad -regtestmatmulv4dimension fails
        // loudly at startup rather than silently rejecting every mined block.
        if (consensus.nMatMulV4TranscriptBlockSize == 0 ||
            consensus.nMatMulV4Dimension % consensus.nMatMulV4TranscriptBlockSize != 0) {
            throw std::runtime_error(strprintf(
                "Invalid regtest MatMul v4 shape: dimension %u must be divisible by tile size %u.",
                consensus.nMatMulV4Dimension,
                consensus.nMatMulV4TranscriptBlockSize));
        }
        if (consensus.nMatMulV4Dimension < consensus.nMatMulV4MinDimension ||
            consensus.nMatMulV4Dimension > consensus.nMatMulV4MaxDimension) {
            throw std::runtime_error(strprintf(
                "Invalid regtest MatMul v4 dimension %u: outside [%u, %u].",
                consensus.nMatMulV4Dimension,
                consensus.nMatMulV4MinDimension,
                consensus.nMatMulV4MaxDimension));
        }
        // MatMul v4.2 / ENC-BMX4C construction invariants, re-checked after the
        // regtest -regtest* overrides (v4 height/dim and BMX4C height) so a bad
        // combination (e.g. a BMX4C height at/below the overridden v4 height)
        // fails loudly at startup. No-op when BMX4C is disabled.
        Consensus::FillDefaultRCGrowthTables(consensus);
        AssertBMX4CConstructionInvariants(consensus, /*is_regtest=*/true);
        if (opts.matmul_transcript_block_size.has_value()) {
            consensus.nMatMulTranscriptBlockSize = *opts.matmul_transcript_block_size;
        }
        if (opts.matmul_noise_rank.has_value()) {
            consensus.nMatMulNoiseRank = *opts.matmul_noise_rank;
        }
        if (consensus.nMatMulTranscriptBlockSize == 0 ||
            consensus.nMatMulDimension % consensus.nMatMulTranscriptBlockSize != 0) {
            throw std::runtime_error(strprintf(
                "Invalid regtest MatMul shape: dimension %u must be divisible by transcript block size %u.",
                consensus.nMatMulDimension,
                consensus.nMatMulTranscriptBlockSize));
        }
        if (opts.matmul_asert_half_life.has_value()) {
            consensus.nMatMulAsertHalfLife = *opts.matmul_asert_half_life;
        }
        if (opts.matmul_asert_half_life_upgrade_height.has_value()) {
            consensus.nMatMulAsertHalfLifeUpgradeHeight = *opts.matmul_asert_half_life_upgrade_height;
            consensus.nMatMulAsertHalfLifeUpgrade = *opts.matmul_asert_half_life_upgrade;
        }
        if (opts.matmul_pre_hash_epsilon_bits_upgrade_height.has_value()) {
            consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = *opts.matmul_pre_hash_epsilon_bits_upgrade_height;
            consensus.nMatMulPreHashEpsilonBitsUpgrade = *opts.matmul_pre_hash_epsilon_bits_upgrade;
        }
        if (opts.matmul_nonce_seed_height.has_value()) {
            consensus.nMatMulNonceSeedHeight = *opts.matmul_nonce_seed_height;
        }
        if (opts.matmul_parent_mtp_seed_height.has_value()) {
            consensus.nMatMulParentMtpSeedHeight = *opts.matmul_parent_mtp_seed_height;
        }
        // AUDIT D1 (review Finding 1): the -regtestmatmulaserthalflife* overrides
        // above are applied AFTER AssertBMX4CConstructionInvariants ran at line
        // ~1357, so the immutable ASERT schedule must be RE-validated here against
        // its now-final values. Without this a regtest node launched with e.g.
        // -regtestmatmulaserthalflifeupgradeheight=0 would pass construction yet
        // fail-closed (halt) at every block at runtime -- exactly the "fails at
        // runtime, not startup" hole D1 is meant to eliminate.
        assert(!consensus.fMatMulPOW ||
               ValidateMatMulAsertParams(consensus, consensus.nMatMulAsertHeight));
        consensus.nMaxBlockWeight = 24'000'000;
        consensus.nMaxBlockSerializedSize = 24'000'000;
        consensus.nMaxBlockSigOpsCost = 480'000;
        consensus.nDefaultBlockMaxWeight = 24'000'000;
        consensus.nDefaultMempoolMaxSizeMB = 2048;
        consensus.nMaxShieldedTxSize = 6'500'000;
        consensus.nMaxShieldedRingSize = 32;
        consensus.nShieldedMerkleTreeDepth = 32;
        consensus.nShieldedPoolActivationHeight = 0;
        consensus.nShieldedTxBindingActivationHeight =
            opts.shielded_tx_binding_activation_height.value_or(0);  // Activate at genesis for instant regtest
        consensus.nShieldedBridgeTagActivationHeight =
            opts.shielded_bridge_tag_activation_height.value_or(0);  // Activate at genesis for instant regtest
        consensus.nShieldedSmileRiceCodecDisableHeight =
            opts.shielded_smile_rice_codec_disable_height.value_or(0);  // Activate at genesis for instant regtest
        consensus.nShieldedMatRiCTDisableHeight =
            opts.shielded_matrict_disable_height.value_or(0);  // Activate at genesis for instant regtest
        consensus.nShieldedSpendPathRecoveryActivationHeight =
            opts.shielded_spend_path_recovery_activation_height.value_or(0);  // Activate at genesis for instant regtest
        consensus.nShieldedC002ActivationHeight =
            opts.shielded_c002_activation_height.value_or(consensus.nShieldedC002ActivationHeight);
        // v0.32.0 velocity cap: inert on regtest by default (so existing shielded tests are unaffected);
        // a functional test lowers it via -regtestshieldedunshieldvelocityactivationheight to exercise it.
        consensus.nShieldedUnshieldVelocityActivationHeight =
            opts.shielded_unshield_velocity_activation_height.value_or(std::numeric_limits<int32_t>::max());
        consensus.nShieldedUnshieldVelocityEndHeight =
            opts.shielded_unshield_velocity_end_height.value_or(std::numeric_limits<int32_t>::max());
        consensus.nShieldedUnshieldVelocityMinCapHeight =
            opts.shielded_unshield_velocity_min_cap_height.value_or(std::numeric_limits<int32_t>::max());
        consensus.nShieldedUnshieldVelocityMinCap =
            opts.shielded_unshield_velocity_min_cap.value_or(0);
        consensus.nShieldedPQ128UpgradeHeight =
            opts.shielded_pq128_upgrade_height.value_or(std::numeric_limits<int32_t>::max());
        consensus.nShieldedPoolCreditDisableHeight =
            opts.shielded_pool_credit_disable_height.value_or(std::numeric_limits<int32_t>::max());
        consensus.nShieldedSunsetHeight =
            opts.shielded_sunset_height.value_or(std::numeric_limits<int32_t>::max());
        consensus.nShieldedDirectSendPublicFlowDisableHeight =
            opts.shielded_direct_send_public_flow_disable_height.value_or(std::numeric_limits<int32_t>::max());
        consensus.nContentEliminationHeight =
            opts.content_elimination_height.value_or(std::numeric_limits<int32_t>::max());
        consensus.nShieldedV2SendZeroOutputExitActivationHeight =
            opts.shielded_v2_send_zero_output_exit_activation_height.value_or(std::numeric_limits<int32_t>::max());
        consensus.nShieldedRecoveryExitActivationHeight =
            opts.shielded_recovery_exit_activation_height.value_or(std::numeric_limits<int32_t>::max());
        consensus.nShieldedRecoveryExitFrozenRoot =
            opts.shielded_recovery_exit_frozen_root.value_or(uint256{});
        if (opts.reorg_protection_start_height.has_value()) {
            consensus.nReorgProtectionStartHeight = *opts.reorg_protection_start_height;
            consensus.nMaxReorgDepth = 12;
        }
        if (opts.empty_block_subsidy_penalty_height.has_value()) {
            consensus.nEmptyBlockSubsidyPenaltyHeight = *opts.empty_block_subsidy_penalty_height;
        }
        if (opts.empty_block_subsidy_penalty_end_height.has_value()) {
            consensus.nEmptyBlockSubsidyPenaltyEndHeight = *opts.empty_block_subsidy_penalty_end_height;
        }
        consensus.nShieldedSettlementAnchorMaturity = 6;
        consensus.nMLDSADisableHeight = opts.mldsa_disable_height.value_or(std::numeric_limits<int32_t>::max());
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        constexpr MessageStartChars default_message_start{0xfa, 0xbf, 0xb5, 0xda};
        constexpr uint16_t default_port{18444};
        constexpr uint32_t default_genesis_time{1296688602};
        constexpr uint32_t default_genesis_nonce{2};
        constexpr uint32_t default_genesis_bits{0x207fffff};
        constexpr int32_t default_genesis_version{1};

        pchMessageStart = opts.message_start.value_or(default_message_start);
        nDefaultPort = opts.default_port.value_or(default_port);
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        const uint32_t genesis_time = opts.genesis_time.value_or(default_genesis_time);
        const uint32_t genesis_nonce = opts.genesis_nonce.value_or(default_genesis_nonce);
        const uint32_t genesis_bits = opts.genesis_bits.value_or(default_genesis_bits);
        const int32_t genesis_version = opts.genesis_version.value_or(default_genesis_version);

        const bool custom_genesis =
            opts.genesis_time.has_value() ||
            opts.genesis_nonce.has_value() ||
            opts.genesis_bits.has_value() ||
            opts.genesis_version.has_value();
        // The functional harness always selects the Phase-A seal with
        // -regtestmatmulltsealaspow=0. The checked-in height-299 snapshot was
        // generated for that deterministic harness chain, and the height-61,010
        // fast-start fixture is explicitly mockable/height-bound. The default
        // height-110 snapshot belongs to the Phase-B chain and is removed below.
        // Any additional consensus override still makes custom_consensus true
        // and clears all canned metadata; snapshot content hashes remain fully
        // validated.
        const bool functional_harness_seal_override =
            opts.matmul_lt_seal_as_pow.has_value() && !*opts.matmul_lt_seal_as_pow;
        const bool custom_consensus =
            custom_genesis ||
            !opts.activation_heights.empty() ||
            !opts.version_bits_parameters.empty() ||
            opts.enforce_bip94 ||
            opts.matmul_dgw ||
            opts.matmul_binding_height.has_value() ||
            opts.matmul_product_digest_height.has_value() ||
            opts.matmul_require_product_payload.has_value() ||
            opts.matmul_dimension.has_value() ||
            opts.matmul_transcript_block_size.has_value() ||
            opts.matmul_noise_rank.has_value() ||
            opts.matmul_asert_half_life.has_value() ||
            opts.matmul_asert_half_life_upgrade_height.has_value() ||
            opts.matmul_asert_half_life_upgrade.has_value() ||
            opts.matmul_pre_hash_epsilon_bits_upgrade_height.has_value() ||
            opts.matmul_pre_hash_epsilon_bits_upgrade.has_value() ||
            opts.matmul_nonce_seed_height.has_value() ||
            opts.matmul_parent_mtp_seed_height.has_value() ||
            opts.matmul_v4_height.has_value() ||
            opts.matmul_v4_dimension.has_value() ||
            opts.matmul_v4_max_dimension.has_value() ||
            opts.matmul_bmx4c_height.has_value() ||
            opts.matmul_drlt_height.has_value() ||
            opts.matmul_rc_unified_height.has_value() ||
            opts.matmul_rc_height.has_value() ||
            opts.matmul_rc_coupled_height.has_value() ||
            opts.matmul_rc_use_toy_dims.has_value() ||
            opts.matmul_rc_coupled_use_toy_dims.has_value() ||
            opts.matmul_rc_coupled_profile.has_value() ||
            opts.matmul_rc_profile.has_value() ||
            (opts.matmul_lt_seal_as_pow.has_value() && !functional_harness_seal_override) ||
            opts.matmul_lt_max_pending_verifications.has_value() ||
            opts.matmul_max_pending_verifications.has_value() ||
            opts.matmul_rc_max_pending_verifications.has_value() ||
            opts.matmul_flat_sketch_replay ||
            opts.matmul_proof_assumevalid_min_age.has_value() ||
            opts.shielded_tx_binding_activation_height.has_value() ||
            opts.shielded_bridge_tag_activation_height.has_value() ||
            opts.shielded_smile_rice_codec_disable_height.has_value() ||
            opts.shielded_matrict_disable_height.has_value() ||
            opts.shielded_spend_path_recovery_activation_height.has_value() ||
            opts.shielded_c002_activation_height.has_value() ||
            opts.shielded_unshield_velocity_activation_height.has_value() ||
            opts.shielded_unshield_velocity_end_height.has_value() ||
            opts.shielded_unshield_velocity_min_cap_height.has_value() ||
            opts.shielded_unshield_velocity_min_cap.has_value() ||
            opts.shielded_pq128_upgrade_height.has_value() ||
            opts.shielded_pool_credit_disable_height.has_value() ||
            opts.shielded_sunset_height.has_value() ||
            opts.shielded_direct_send_public_flow_disable_height.has_value() ||
            opts.shielded_v2_send_zero_output_exit_activation_height.has_value() ||
            opts.content_elimination_height.has_value() ||
            opts.shielded_recovery_exit_activation_height.has_value() ||
            opts.shielded_recovery_exit_frozen_root.has_value() ||
            opts.reorg_protection_start_height.has_value() ||
            opts.empty_block_subsidy_penalty_height.has_value() ||
            opts.empty_block_subsidy_penalty_end_height.has_value() ||
            opts.mldsa_disable_height.has_value();

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        genesis = CreateBTXGenesisBlock(
            genesis_time,
            genesis_nonce,
            genesis_nonce,
            genesis_bits,
            genesis_version,
            consensus.nInitialSubsidy,
            static_cast<uint16_t>(consensus.nMatMulDimension),
            custom_genesis
                ? uint256{}
                : uint256{"7ff451fb9e39ebaa8447435600978167d9cb8b9ee1d6933eb5e1ad84d05a2a37"});
        consensus.hashGenesisBlock = genesis.GetHash();
        if (!custom_genesis && !opts.matmul_dimension.has_value()) {
            assert(consensus.hashGenesisBlock == uint256{"521ad0951ed299e9c56aeb7db8188972772067560351b8e55adf71dbed532360"});
        }
        assert(genesis.hashMerkleRoot == uint256{"94ae75cb0cd5f08b9447306ae914635d1c36d1a43d330daf596957e91cee002a"});

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        if (!custom_consensus) {
            m_assumeutxo_data = {
                {
                    // Deterministic TestChain100Setup Phase-A functional-harness
                    // snapshot metadata at height 110.
                    .height = 110,
                    .hash_serialized = AssumeutxoHash{uint256{"c35580bfd4f6c2ab69a8b1ac446962e5aacb164dc13e237867bd2170b91d7c98"}},
                    .m_chain_tx_count = 111,
                    .blockhash = consteval_ctor(uint256{"b610281aaeb8d64d4739e848a47c0a6ae226a0e26e29e5a3d735825e34cc2e65"}),
                },
                {
                    // Deterministic TestChain100Setup + BTX-compatible
                    // Phase-A feature_assumeutxo extension using RAW_P2PKH
                    // wallet flows.
                    .height = 299,
                    .hash_serialized = AssumeutxoHash{uint256{"2e5dcf9f04328141c721b5615a32dc265da783050ba7bd3e436a48b5a2013ae1"}},
                    .m_chain_tx_count = 300,
                    .blockhash = consteval_ctor(uint256{"7202d1341554184806cfb25c74ee0aa41f680c42ea9fdb965685962b8e8e148b"}),
                },
                {
                    // Post-shielded-activation regtest snapshot for btx-p2p
                    // fast-start testing. IsMockableChain() allows height-only
                    // matching, and validation treats all-zero blockhash /
                    // hash_serialized as a mockable-chain wildcard so any
                    // regtest snapshot at this height can be used.
                    .height = 61'010,
                    .hash_serialized = AssumeutxoHash{uint256{"0000000000000000000000000000000000000000000000000000000000000000"}},
                    .m_chain_tx_count = 61'011,
                    .blockhash = consteval_ctor(uint256{"0000000000000000000000000000000000000000000000000000000000000000"}),
                },
            };
            if (functional_harness_seal_override) {
                std::erase_if(m_assumeutxo_data, [](const auto& snapshot) {
                    return snapshot.height == 110;
                });
            }
        } else {
            // Consensus-altering regtest overrides invalidate canned snapshot metadata.
            m_assumeutxo_data.clear();
        }

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "btxrt";
    }
};

class CShieldedV2DevParams : public CChainParams
{
public:
    CShieldedV2DevParams()
    {
        m_chain_type = ChainType::SHIELDEDV2DEV;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60;
        consensus.nPowTargetSpacing = 90;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = true;
        consensus.fKAWPOW = false;
        consensus.fSkipKAWPOWValidation = true;
        consensus.fReducedDataLimits = true;
        consensus.fEnforceP2MROnlyOutputs = false;
        consensus.nKAWPOWHeight = std::numeric_limits<int>::max();
        consensus.fMatMulPOW = true;
        consensus.fSkipMatMulValidation = true;
        consensus.nMatMulDimension = 64;
        consensus.nMatMulTranscriptBlockSize = 8;
        consensus.nMatMulNoiseRank = 4;
        consensus.nMatMulValidationWindow = 10;
        consensus.nMatMulPhase2FailBanThreshold = std::numeric_limits<uint32_t>::max();
        consensus.fMatMulStrictPunishment = false;
        consensus.nMatMulSnapshotInterval = 10'000;
        consensus.fMatMulFreivaldsEnabled = true;
        consensus.nMatMulFreivaldsRounds = 2;
        consensus.fMatMulRequireProductPayload = true;
        consensus.nMatMulFreivaldsBindingHeight = 0;
        consensus.nMatMulProductDigestHeight = 0;
        consensus.nMatMulPreHashEpsilonBits = 0;
        consensus.nMatMulPreHashEpsilonBitsUpgrade = consensus.nMatMulPreHashEpsilonBits;
        consensus.nMatMulGlobalVerifyBudgetPerMin = std::numeric_limits<uint32_t>::max();
        consensus.nPowTargetSpacingFastMs = 250;
        consensus.nFastMineDifficultyScale = 4;
        consensus.nPowTargetSpacingNormal = 90;
        consensus.nFastMineHeight = 0;
        consensus.nDgwAsymmetricClampHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwEasingBoostHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwWindowAlignmentHeight = std::numeric_limits<int32_t>::max();
        consensus.nDgwSlewGuardHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulAsertHeight = 0;
        consensus.nMatMulAsertHalfLife = 14'400;
        consensus.nMaxBlockWeight = 24'000'000;
        consensus.nMaxBlockSerializedSize = 24'000'000;
        consensus.nMaxBlockSigOpsCost = 480'000;
        consensus.nDefaultBlockMaxWeight = 24'000'000;
        consensus.nDefaultMempoolMaxSizeMB = 2048;
        consensus.nMaxShieldedTxSize = 6'500'000;
        consensus.nMaxShieldedRingSize = 32;
        consensus.nShieldedMerkleTreeDepth = 32;
        consensus.nShieldedPoolActivationHeight = 0;
        consensus.nShieldedTxBindingActivationHeight = 61'000;
        consensus.nShieldedBridgeTagActivationHeight = 61'000;
        consensus.nShieldedSmileRiceCodecDisableHeight = 61'000;
        consensus.nShieldedMatRiCTDisableHeight = 61'000;
        consensus.nShieldedSpendPathRecoveryActivationHeight = 88'000;
        consensus.nShieldedPQ128UpgradeHeight = std::numeric_limits<int32_t>::max();
        consensus.nShieldedPoolCreditDisableHeight = BTX_SHIELDED_POOL_CREDIT_DISABLE_HEIGHT;
        consensus.nShieldedSunsetHeight = BTX_SHIELDED_SUNSET_HEIGHT;
        consensus.nShieldedDirectSendPublicFlowDisableHeight = BTX_SHIELDED_DIRECT_SEND_PUBLIC_FLOW_DISABLE_HEIGHT;
        consensus.nContentEliminationHeight = BTX_CONTENT_ELIMINATION_HEIGHT;
        consensus.nShieldedV2SendZeroOutputExitActivationHeight =
            BTX_SHIELDED_V2_SEND_ZERO_OUTPUT_EXIT_ACTIVATION_HEIGHT;
        consensus.nShieldedRecoveryExitActivationHeight = BTX_SHIELDED_SUNSET_HEIGHT;
        // v0.32.0-v0.32.12: shielded unshield (z->t) velocity cap from the 125,000
        // sunset through block 134,999. The v0.32.11 minimum-cap floor still starts at
        // 132,000, and v0.32.12 ends the quota at 135,000 after the recovery window has
        // matured so remaining legacy exits are no longer rate-limited.
        consensus.nShieldedUnshieldVelocityActivationHeight = BTX_SHIELDED_SUNSET_HEIGHT;
        consensus.nShieldedUnshieldVelocityEndHeight = BTX_SHIELDED_UNSHIELD_VELOCITY_END_HEIGHT;
        consensus.nShieldedUnshieldVelocityMinCapHeight = BTX_V03211_HARDENING_HEIGHT;
        consensus.nShieldedUnshieldVelocityMinCap = BTX_SHIELDED_UNSHIELD_VELOCITY_MIN_CAP;
        consensus.nShieldedSettlementAnchorMaturity = 6;
        consensus.nMLDSADisableHeight = std::numeric_limits<int32_t>::max();
        consensus.nRuleChangeActivationThreshold = 108;
        consensus.nMinerConfirmationWindow = 144;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart = MessageStartChars{0xe2, 0xb7, 0xda, 0x7a};
        nDefaultPort = 19444;
        nPruneAfterHeight = 100;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        constexpr uint32_t genesis_time{1773446400};
        constexpr uint32_t genesis_nonce{0};
        constexpr uint32_t genesis_bits{0x207fffff};
        constexpr int32_t genesis_version{1};
        constexpr uint64_t genesis_nonce64{0};

        genesis = CreateShieldedV2DevGenesisBlock(
            genesis_time,
            genesis_nonce,
            genesis_nonce64,
            genesis_bits,
            genesis_version,
            consensus.nInitialSubsidy,
            static_cast<uint16_t>(consensus.nMatMulDimension),
            uint256{});
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"4ed72f2a7db044ff555197cddde63b1f50b74d750674316f75c3571ade9c80a3"});

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.emplace_back("shieldedv2dev.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        m_assumeutxo_data.clear();

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "btxv2";

        // Audit review Finding 2: the shielded-v2 dev network enables MatMul PoW,
        // so enforce the same construction invariants (H2 discount range, D1 ASERT
        // schedule validity, I1 tile size, BMX4C profile) as the other MatMul
        // networks. No-op today (v4/bmx4c disabled, discount at default).
        consensus.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
        consensus.nMatMulRCProfile = 1;
        consensus.nMatMulRCAsertRescaleNum = 1;  // inert: RC height disabled on this network
        consensus.nMatMulRCAsertRescaleDen = 1;
        Consensus::FillDefaultRCGrowthTables(consensus);
        AssertBMX4CConstructionInvariants(consensus, /*is_regtest=*/false);
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet4()
{
    return std::make_unique<const CTestNet4Params>();
}

std::unique_ptr<const CChainParams> CChainParams::ShieldedV2Dev()
{
    return std::make_unique<const CShieldedV2DevParams>();
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet_msg = CChainParams::TestNet()->MessageStart();
    const auto testnet4_msg = CChainParams::TestNet4()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();
    const auto shieldedv2dev_msg = CChainParams::ShieldedV2Dev()->MessageStart();
    const auto signet_msg = CChainParams::SigNet({})->MessageStart();

    if (std::ranges::equal(message, mainnet_msg)) {
        return ChainType::MAIN;
    } else if (std::ranges::equal(message, testnet_msg)) {
        return ChainType::TESTNET;
    } else if (std::ranges::equal(message, testnet4_msg)) {
        return ChainType::TESTNET4;
    } else if (std::ranges::equal(message, regtest_msg)) {
        return ChainType::REGTEST;
    } else if (std::ranges::equal(message, shieldedv2dev_msg)) {
        return ChainType::SHIELDEDV2DEV;
    } else if (std::ranges::equal(message, signet_msg)) {
        return ChainType::SIGNET;
    }
    return std::nullopt;
}
