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
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
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

// MatMul v4.2 / ENC-BMX4C construction invariants (spec §8.1/§8.2). No-op when
// the profile is unset (nMatMulBMX4CHeight == INT32_MAX = disabled, e.g.
// mainnet); when a network sets a BMX4C activation height these MUST hold, so a
// misconfiguration fails loudly at node startup rather than at the fork.
static void AssertBMX4CConstructionInvariants(const Consensus::Params& consensus)
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
    assert(consensus.nMaxBlockSerializedSize <= MAX_BLOCK_SERIALIZED_SIZE);

    // Audit F1 (wave-3): the header-PoW spam gate is enabled by a non-zero
    // nMatMulHeaderPoWBits, but it grinds the legacy `nNonce` which is not yet on
    // the header wire -- enabling it before that wire change (and the miner grind)
    // lands is a reject-all mining halt. Fail LOUD at startup instead: the gate
    // may only be enabled once nNonce is on the wire.
    assert(CBlockHeader::BTX_HEADER_NONCE_ON_WIRE || !consensus.IsMatMulHeaderPoWEnabled());

    // Audit H2: the header-PoW discount is valid ONLY in 0..255 (or the
    // UINT32_MAX "disabled" sentinel). A value in [256, UINT32_MAX-1] would push
    // the throttle target to powLimit regardless of nBits, recreating the
    // fixed-cost C2 gate; reject it fatally here rather than clamp it silently.
    assert(consensus.IsMatMulHeaderPoWDiscountValid());

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
        assert(ValidateMatMulAsertParams(consensus, consensus.nMatMulAsertHeight));
    }

    // Audit I1: the miner and verifier use the compile-time tile size
    // matmul::v4::kTileB (b); a consensus nMatMulV4TranscriptBlockSize that differs
    // from it would make EVERY v4 block invalid at the fork. Pin them equal
    // wherever v4 is configured (nMatMulV4TranscriptBlockSize is not yet a truly
    // parameterizable value -- the b=8/n=8192 profile is a future consensus change,
    // not a live parameter).
    // §0.3 / §4.3 PER-PROFILE dimension-invariant guard: for each configured
    // profile P live at some height, nMatMulV4Dimension at PRODUCTION scale MUST
    // reduce to exactly P.sketch_rank_m under P.tile_b (tile_b·m == n), and
    // P.sketch_payload_bytes MUST equal 8·m². The committed sketch rank, its
    // 8·m² payload, and the O(n²) verify DoS budget are calibrated PER PROFILE
    // for that rank at the PRODUCTION dimension. Nothing else pins the dimension
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
            assert(p.tile_b > 0);
            assert(p.sketch_payload_bytes ==
                   uint64_t{8} * p.sketch_rank_m * p.sketch_rank_m);
            assert(consensus.nMatMulV4Dimension % p.tile_b == 0);
            if (consensus.nMatMulV4Dimension >= p.tile_b * p.sketch_rank_m) {
                assert(consensus.nMatMulV4Dimension / p.tile_b == p.sketch_rank_m);
            }
        };

    if (consensus.nMatMulV4Height != std::numeric_limits<int32_t>::max()) {
        assert(consensus.nMatMulV4TranscriptBlockSize == matmul::v4::kTileB);
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
    assert((consensus.nMatMulV4Height == std::numeric_limits<int32_t>::max() &&
            consensus.nMatMulBMX4CHeight == std::numeric_limits<int32_t>::max()) ||
           (consensus.nMatMulV4Height == consensus.nMatMulBMX4CHeight));

    if (consensus.nMatMulBMX4CHeight == std::numeric_limits<int32_t>::max()) return;
    // At this point ENC-BMX4C is enabled, so (by the strict-unified invariant above)
    // v4 and ENC-BMX4C share one height: the single-activation flag day. ENC-S8 is
    // never live; the live profile at and above the fork is ENC-BMX4C. Exactly one
    // profile is live at any height -- no dual-profile window, no ENC-S8 interval.
    assert(consensus.nMatMulBMX4CHeight == consensus.nMatMulV4Height);
    // The base-2^6 remainder-top combine must totally decompose every P/Q entry
    // across the whole accepted-dimension window: 288 * MaxDim <= 2^23 - 1.
    assert(static_cast<int64_t>(Consensus::BMX4C_PROJECTION_BOUND_PER_N) *
               consensus.nMatMulV4MaxDimension <=
           Consensus::BMX4C_COMBINE_INPUT_BOUND);
    // The accepted (exact) dimension must be a multiple of the E8M0 block length
    // (block scales run along the contraction dim in blocks of 32).
    assert((consensus.nMatMulV4Dimension % Consensus::BMX4C_SCALE_BLOCK_LENGTH) == 0);
    // Audit ASERT-F1: the one-time ASERT rescale ratio must be strictly positive.
    // ValidateMatMulAsertParams enforces this at runtime (failing closed to
    // powLimit), but that only surfaces AT the fork height; assert it at startup
    // too so a non-positive misconfiguration aborts the node immediately. Only
    // positivity is checked -- a LARGE ratio can be a legitimate calibration
    // (Num/Den is the GPU-vs-CPU throughput ratio, which can be large), and ASERT
    // self-corrects any residual within one half-life, so no arbitrary range cap.
    assert(consensus.nMatMulBMX4CAsertRescaleNum > 0);
    assert(consensus.nMatMulBMX4CAsertRescaleDen > 0);

    // ENC-BMX4C-D (v4.2-D) is an ADDITIONAL profile above ENC-BMX4C (design §2):
    // if configured it MUST fork STRICTLY ABOVE the ENC-BMX4C height (D succeeds
    // C; no dual-profile window at the same height), and its ASERT rescale ratio
    // must be strictly positive. Disabled (INT32_MAX) => no coupling.
    //
    // PROOF CARRIAGE (design §3): D's ~32 MiB sketch is carried as a SEGREGATED
    // PRUNABLE PROOF, excluded from the block serialized size by construction, so
    // there is NO in-block 32 MiB payload gating to assert here (that was the old
    // P1/P3 blocker). Stage 2a wires the body-serialization gate, the store-backed
    // §3.3 binding + §3.4 size cap, and the miner offload; Stage 2b wires the
    // getmatmulproof/matmulproof P2P relay; Stage 2c wires prune/archive.
    if (consensus.nMatMulBMX4CDHeight == std::numeric_limits<int32_t>::max()) return;

    // ACTIVATION COUPLING (design §3.6), mirroring the BTX_HEADER_NONCE_ON_WIRE
    // gate: enabling a segregated-proof profile is a coordinated header/relay
    // protocol change. A NETWORKED node that receives a segregated block from a
    // peer must be able to OBTAIN its proof, or it stalls (the sketch is off-body).
    // Stage 2a delivers the single-node carriage + a PROCESS-LOCAL proof store, but
    // the Stage-2b P2P relay is NOT yet present, so D MUST NOT be activatable on any
    // PUBLIC (peer-to-peer) network until BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY is
    // flipped true in the change that lands the relay. Fail LOUD at startup here.
    //
    // The single-node on-demand-mining exemption is deliberate and narrowly scoped:
    // on such a chain (regtest / dev) the miner and validator share one process and
    // the LOCAL store fully stands in for the relay, so the Stage-2a segregated path
    // is exercisable end-to-end WITHOUT the relay. MineBlocksOnDemand() ==
    // consensus.fPowNoRetargeting, which is FALSE on every PUBLIC network
    // (main/testnet/testnet4/signet all set it false above), so this cannot loosen
    // them: activating D there while the relay flag is false aborts the node.
    assert(Consensus::BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY ||
           consensus.fPowNoRetargeting);

    assert(consensus.nMatMulBMX4CDHeight > consensus.nMatMulBMX4CHeight);
    assert(consensus.nMatMulBMX4CDAsertRescaleNum > 0);
    assert(consensus.nMatMulBMX4CDAsertRescaleDen > 0);
    // §4.3 per-profile dimension/payload pin for the D profile: its DELIBERATELY
    // larger committed object (b=2 -> m=2048 -> 32 MiB) is pinned to the D tile
    // via the per-profile params, so a dimension retarget cannot silently move
    // the D rank/payload off its calibrated 32 MiB either (b -> 4 at n -> 8192
    // would hold m = 2048). At nMatMulBMX4CDHeight the live profile is ENC_BMX4CD
    // (D > C is asserted just above), so GetMatMulProfileParams yields the D shape.
    assert_profile_dimension_pin(
        consensus.GetMatMulProfileParams(consensus.nMatMulBMX4CDHeight));
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
        consensus.nMatMulProofPruneDepth = 10'000;
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
        // that re-enables compact serving; that would require a payload-carrying P2P
        // extension (getmatmulproof/matmulproof, btx-matmul-pow-spec.md S13.3).
        consensus.fMatMulRequireProductPayload = false;
        consensus.nMatMulFreivaldsBindingHeight = 61'000;
        consensus.nMatMulProductDigestHeight = 61'000;
        // MatMul v4 (doc/btx-matmul-v4-design-spec.md): consensus.nMatMulV4Height
        // is deliberately left at its Consensus::Params default
        // (std::numeric_limits<int32_t>::max(), i.e. disabled) here. v4 mainnet
        // activation deliberately unset -- requires calibration + audit (spec
        // Appendix C). Mainnet stays on v3 exclusively until a future release
        // explicitly sets this height, chooses nMatMulV4AsertRescaleNum/Den from
        // benchmarked v4 reference-miner throughput, and schedules at least two
        // release cycles of deployment runway past the tip at tag time (spec
        // §G.1, §G.4 invariant #6). Do not set a mainnet value speculatively.
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

        // Mainnet anchor refreshed on 2026-07-10 at height 155'700 from a
        // synced canonical node so stale history below the current public
        // release floor is rejected quickly.
        consensus.nMinimumChainWork = uint256{"0000000000000000000000000000000000000000000000000000d441262318ef"};
        // Assume signatures valid up to the same anchored block to speed sync.
        consensus.defaultAssumeValid = uint256{"b5ea1fb02d12e1cfa4bbc5ccc4946ca026ad4a5f270b99a0816aa95853306c3d"};

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
        // Measured from the 2026-07-10 mainnet archive datadirs near height
        // 155'870: ~104 GB of blocks plus chain/shielded state, rounded up so
        // users see a conservative disk estimate before sync begins.
        m_assumed_blockchain_size = 106;
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
        // INT32_MAX -- so a future mainnet activation that sets only the height
        // cannot ship without the fork-ordering / dim / rescale-positivity guards).
        AssertBMX4CConstructionInvariants(consensus);

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
                {155700, uint256{"b5ea1fb02d12e1cfa4bbc5ccc4946ca026ad4a5f270b99a0816aa95853306c3d"}},
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
        };
        chainTxData = ChainTxData{
            .nTime = 1783686055,
            .tx_count = 213654,
            .dTxRate = 0.021856663125,
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
        consensus.nMatMulProofPruneDepth = 10'000;
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
        // DoS verify budgets above the v4 fork (spec §I.5): the O(n^2) verify
        // costs ~0.14-0.28 s CPU/check at n=4096, so the global cap is 16/min
        // (~4.8 s CPU/min) and each peer 4/min.
        consensus.nMatMulV4GlobalVerifyBudgetPerMin = 16;
        consensus.nMatMulV4PeerVerifyBudgetPerMin = 4;
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
        AssertBMX4CConstructionInvariants(consensus);

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
        consensus.nMatMulProofPruneDepth = 10'000;
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
        AssertBMX4CConstructionInvariants(consensus);

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
        consensus.nMatMulProofPruneDepth = 10'000;
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
        AssertBMX4CConstructionInvariants(consensus);
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
        consensus.nMatMulProofPruneDepth = 10'000;
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
        // MatMul v4.2-D ENC-BMX4C-D segregated-proof profile (solver-evolution
        // Stage 2a; design §3). Regtest-only override so a single node can mine
        // across into D heights and exercise the store-backed binding + Freivalds
        // path. D must fork STRICTLY ABOVE the ENC-BMX4C height (D succeeds C — the
        // strict-above assert in AssertBMX4CConstructionInvariants fails loud on
        // D<=C). The D ASERT rescale stays at its 1/1 default (regtest has no
        // pre-fork throughput history). Activation here is permitted because
        // regtest is fPowNoRetargeting (MineBlocksOnDemand) — the segregated-proof
        // relay-ready compile gate exempts single-node chains (see the assert).
        if (opts.matmul_bmx4cd_height.has_value()) {
            consensus.nMatMulBMX4CDHeight = *opts.matmul_bmx4cd_height;
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
        AssertBMX4CConstructionInvariants(consensus);
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
            opts.matmul_nonce_seed_height.has_value() ||
            opts.matmul_parent_mtp_seed_height.has_value() ||
            opts.matmul_v4_height.has_value() ||
            opts.matmul_v4_dimension.has_value() ||
            opts.matmul_bmx4c_height.has_value() ||
            opts.matmul_bmx4cd_height.has_value() ||
            opts.shielded_tx_binding_activation_height.has_value() ||
            opts.shielded_bridge_tag_activation_height.has_value() ||
            opts.shielded_smile_rice_codec_disable_height.has_value() ||
            opts.shielded_matrict_disable_height.has_value() ||
            opts.shielded_spend_path_recovery_activation_height.has_value() ||
            opts.shielded_pq128_upgrade_height.has_value() ||
            opts.shielded_pool_credit_disable_height.has_value() ||
            opts.shielded_sunset_height.has_value() ||
            opts.shielded_direct_send_public_flow_disable_height.has_value() ||
            opts.shielded_v2_send_zero_output_exit_activation_height.has_value() ||
            opts.reorg_protection_start_height.has_value() ||
            opts.empty_block_subsidy_penalty_height.has_value() ||
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
                    // Deterministic TestChain100Setup (regtest) snapshot metadata at height 110.
                    .height = 110,
                    .hash_serialized = AssumeutxoHash{uint256{"c35580bfd4f6c2ab69a8b1ac446962e5aacb164dc13e237867bd2170b91d7c98"}},
                    .m_chain_tx_count = 111,
                    .blockhash = consteval_ctor(uint256{"9e3817054fd9df2c2a27f647a3b9f55f8bc91f05168753543a902074a8f21700"}),
                },
                {
                    // Deterministic TestChain100Setup + BTX-compatible
                    // feature_assumeutxo extension using RAW_P2PKH wallet flows.
                    .height = 299,
                    .hash_serialized = AssumeutxoHash{uint256{"2e5dcf9f04328141c721b5615a32dc265da783050ba7bd3e436a48b5a2013ae1"}},
                    .m_chain_tx_count = 300,
                    .blockhash = consteval_ctor(uint256{"78e6ea382d4d5466b1d8421c1b8789e9c7cde9de8b6da4042be00ca2948a4860"}),
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
        consensus.nMatMulProofPruneDepth = 10'000;
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
        AssertBMX4CConstructionInvariants(consensus);
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
