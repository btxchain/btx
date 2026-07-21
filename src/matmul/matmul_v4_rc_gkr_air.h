// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_GKR_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_GKR_AIR_H

#include <matmul/matmul_v4_rc_extract.h>
#include <matmul/matmul_v4_rc_gkr_field.h>
#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

// ENC_RC winner-GKR — Relation (3) "Extract" AIR (parked / arbiter OFF).
//
// This file implements the SOUND Extract-relation arithmetization from
//   doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md  §5 (Thm 5.2)
//   doc/btx-matmul-v4.5-rc-gkr-soundness-table-2026-07-21.md
//
// WHY THIS EXISTS (the crux). The shipped v6 "virtual table" G3 check compares
// two prover-computed vectors and therefore rejects a forged Extract witness
// with probability EXACTLY 0 (blueprint Theorem 5.1). Extract is NOT a fixed
// table: it is a ChaCha20-keyed, per-tile, int64-domain rejection sampler with
// a SHA-256-derived power-of-two scale (see src/matmul/matmul_v4_rc_extract.h
// and src/matmul/matmul_v4_lt.cpp, the IMMUTABLE int64 reference). The sound
// construction must (a) recompute the ChaCha20 keystream in-circuit, (b)
// recompute the SHA-256 scale in-circuit, (c) constrain the int64-domain
// rejection-sampling transition (input y -> mantissa -> output), and (d) prove
// every tabular sub-relation (mantissa map, 4-bit XOR, 16-bit range) by a
// LogUp lookup against a PREPROCESSED (consensus-constant) table, aggregated
// with DUAL-alpha over Fp2 so the alpha-collision term clears 2^-64 (single-
// alpha over Fp2 gives only 45 bits post-grind; Thm 5.2 / soundness table R3).
//
// IMPORTANT: the int64 reference (ExtractMXTileInt64) is the sole oracle. This
// AIR is validated byte-for-byte AGAINST it; the AIR never redefines Extract.
// Everything here is behind the OFF arbiter; nMatMulRCHeight stays INT32_MAX.

namespace matmul::v4::rc::gkr_air {

using gkr_field::Fp;
using gkr_field::Fp2;

// ---------------------------------------------------------------------------
// 0. Abstract trace-column interface (documented column indices).
//
// The integration wave wires these logical columns to the concrete
// RCGkrTraceLayout owned by the foundation agent. Nothing here hard-depends on
// that layout: an AIR is generated over local column streams identified by the
// RCAirCol role below, and RCAirColumnMap records, per role, the GLOBAL column
// index that role occupies once concatenated into the §2.1 A-columns. The
// integration code fills RCAirColumnMap from RCGkrTraceLayout and copies each
// local stream into its global column; the constraint set is unchanged.
// ---------------------------------------------------------------------------

/** Logical column roles of the Extract AIR (see blueprint §5.4/§6.2). */
enum class RCAirCol : uint32_t {
    // ---- ChaCha20 block AIR (§5.4) ----
    kChaChaInitState = 0,  // 16 words: constants|key|counter|nonce (public)
    kChaChaRoundState,     // 16 words * 80 quarter-rounds (working state)
    kChaChaAddCarry,       // carry bit per 32-bit modular add
    kChaChaAddLimbLo,      // low 16-bit limb of each add result   (-> T_R16)
    kChaChaAddLimbHi,      // high 16-bit limb of each add result  (-> T_R16)
    kChaChaXorNibA,        // 8 nibbles of xor operand a           (-> T_X)
    kChaChaXorNibB,        // 8 nibbles of xor operand b           (-> T_X)
    kChaChaXorNibR,        // 8 nibbles of xor result              (-> T_X)
    kChaChaRotHi,          // rotate split: high part
    kChaChaRotLo,          // rotate split: low part
    kChaChaOutNibble,      // final keystream nibble stream (consumed by C-E1)

    // ---- Scale SHA-256 AIR (§6.2) ----
    kShaMsgWord,           // 64 message-schedule words W[t]
    kShaWorkingA,          // working var a per round (h..a), field value
    kShaBitDecomp,         // 32 booleanity bits per arithmetized 32-bit word
    kShaAddCarry,          // carry witnesses for modular adds
    kShaScaleByte0,        // digest byte 0 (= (h0>>24)&0xff)
    kShaScaleE,            // e = byte0 & 3  (feeds C-E10)

    // ---- Extract sampler AIR (C-E1..E10) ----
    kSampKappa,            // kappa(c): candidate nibble (bound to ChaCha C-E1)
    kSampPos,              // pos(c) in [0,32]
    kSampAcc,              // acc(c) in {0,1}
    kSampMu,               // mu(c) mantissa from T_M
    kSampMixed,            // mixed(c) = kappa ^ H(c)          (-> T_X)
    kSampH,                // H(c) top nibble of golden mix
    kSampInvLive,          // liveness inverse witness (C-E5)
    kSampYLo,              // low 32 bits of two's-complement y (2 x T_R16 limbs)
    kSampYHi,              // high 32 bits of two's-complement y
    kSampYSign,            // sign bit s (top bit of hi)
    kSampBranch,           // branch b in {0,1} (in-range vs fold)
    kSampUmix,             // u = b?lo:(lo^hi)
    kSampGoldQ,            // q in u*G = q*2^32 + v
    kSampGoldV,            // v in u*G = q*2^32 + v            (-> T_R16)
    kSampMantissaM,        // M_tau[t]: mantissa per final position t
    kSampOut,              // out_tau[t] = M[t] * 2^e
    kSampInputY,           // committed int64 input y (field embedding)

    kNumRoles
};

/** Per-role GLOBAL column index in the concatenated §2.1 A-columns. */
struct RCAirColumnMap {
    std::array<uint32_t, static_cast<size_t>(RCAirCol::kNumRoles)> base{};
    // Set by integration from RCGkrTraceLayout. -1 sentinel = unwired.
    RCAirColumnMap() { base.fill(0xFFFFFFFFu); }
    [[nodiscard]] uint32_t Global(RCAirCol c) const {
        return base[static_cast<size_t>(c)];
    }
};

// ---------------------------------------------------------------------------
// 1. Preprocessed lookup tables (consensus constants; §5.3).
//
// The TABLE side of every LogUp instance is preprocessed-canonical, not prover
// data. This is exactly what restores meaning to the fractional-sum argument
// (Thm 5.1 last paragraph): the v6 "w := t" cloning attack is no longer
// expressible. Each table self-checks against the int64 reference at build.
// ---------------------------------------------------------------------------

/** T_M (16 rows): (nib, acc, mu) — the MantissaTable graph. */
struct TableTM {
    std::array<uint8_t, 16> acc{};
    std::array<int8_t, 16> mu{};
    TableTM();  // populated from bmx4::SampleMantissaNibble (the reference).
};

/** T_X (256 rows): (a,b,a^b) for 4-bit a,b (indexed a*16+b). */
struct TableTX {
    std::array<uint8_t, 256> axorb{};
    TableTX();
};

// T_R16 (2^16 rows): membership predicate v in [0, 2^16). Enforced as the
// range table; represented implicitly (0 <= v < 65536) plus its LogUp column.

/** Build-time self-check of all preprocessed tables vs the reference. */
[[nodiscard]] bool SelfCheckTables();

// ---------------------------------------------------------------------------
// 2. Dual-alpha LogUp aggregate (§5.5, Thm 5.2 / soundness table R3).
//
// One LogUp system over ALL membership constraints. Fractional columns
//   phi_i = 1/(alpha - w_i),  psi_j = m_j/(alpha - t_j)
// with constraints phi_i*(alpha - w_i) = 1, psi_j*(alpha - t_j) = m_j, and
// Sum phi = Sum psi.  AMPLIFICATION: instantiate the whole system TWICE with
// independent FS challenges alpha_1, alpha_2 in Fp2 (one FS round emits both).
// A false membership survives only if the fractional equality holds at BOTH
// alpha_s; over Fp2^2 the bad-pair density is ((N_w+N_t)/|Fp2|)^2.
// ---------------------------------------------------------------------------

/** One tuple contributed to a LogUp instance (already fingerprinted). */
struct LogUpTuple {
    Fp2 fp;       // FS-compressed field fingerprint of the tuple coordinates
};

/** A LogUp instance: witness multiset (mult 1 each) + table multiset (m_j). */
struct LogUpInstance {
    std::string name;
    std::vector<Fp2> witness;         // one fingerprint per witness row
    std::vector<Fp2> table;           // one fingerprint per table row
    std::vector<uint64_t> table_mult; // committed multiplicity m_j per table row
};

/** Result of a dual-alpha aggregate verification. */
struct LogUpVerifyResult {
    bool ok{false};
    bool sum_ok_a1{false};
    bool sum_ok_a2{false};
    std::string failure;             // first failing constraint, if any
    uint64_t n_witness{0};
    uint64_t n_table{0};
    double achieved_bits{0.0};       // -log2 acceptance of a false membership
};

/**
 * Verify the dual-alpha LogUp aggregate over a set of instances. Returns
 * ok=true iff, for BOTH alpha_1 and alpha_2, every fractional constraint holds
 * and Sum phi = Sum psi in every instance. `achieved_bits` reports the Thm-5.2
 * alpha-collision soundness for the supplied (N_w+N_t) over Fp2^2 (post the
 * repo grinding convention g=40).
 */
[[nodiscard]] LogUpVerifyResult LogUpDualAlphaVerify(
    const std::vector<LogUpInstance>& instances, Fp2 alpha1, Fp2 alpha2);

// ---------------------------------------------------------------------------
// 3. The Extract-tile AIR: witness + constraint system for ONE tile.
//
// Trace() runs the reference sub-primitives (ChaCha20 block, SHA-256 scale,
// int64 rejection sampler) and records EVERY intermediate into the columns
// above. CheckConstraints() evaluates every AIR constraint (C-E1..E10, ChaCha,
// SHA) using ONLY committed cells plus public inputs and the preprocessed
// tables — it never recomputes from the raw input, so a swapped intermediate
// is caught by a broken algebraic identity, not by re-derivation.
// ---------------------------------------------------------------------------

/** Public per-tile inputs (all native/public functions of the header). */
struct TilePublic {
    uint256 prf_key;
    uint32_t i{0};
    uint32_t bj{0};
};

/** Fully-populated witness for one Extract tile. */
struct TileWitness {
    TilePublic pub;
    std::array<int64_t, kRCMxBlockLen> input{};   // committed int64 inputs y_t
    std::array<int8_t, kRCMxBlockLen> out{};      // AIR-produced output

    // ChaCha blocks actually consumed (>=1). Each is 16 init + working trace.
    uint32_t chacha_blocks{0};
    std::vector<uint8_t> keystream;               // chacha_blocks * 64 bytes

    // SHA scale.
    uint8_t scale_e{0};
    uint8_t scale_byte0{0};

    // Sampler per-candidate rows.
    struct Cand {
        uint32_t global_c{0};   // remix*128 + c
        uint8_t kappa{0};
        uint32_t pos{0};
        uint8_t acc{0};
        int8_t mu{0};
        uint8_t mixed{0};
        uint8_t h{0};
        // MixBits witnesses for the candidate's input position:
        uint32_t y_lo{0};
        uint32_t y_hi{0};
        uint8_t y_sign{0};
        uint8_t branch{0};
        uint32_t u_mix{0};
        uint32_t gold_q{0};
        uint32_t gold_v{0};
    };
    std::vector<Cand> cands;
    std::array<int8_t, kRCMxBlockLen> mantissa{}; // M_tau[t]

    // LogUp instances generated by this tile (fingerprinted at Trace time is
    // deferred; raw tuples are stashed for the aggregate builder).
};

/** Generate the full witness for one tile from public inputs + int64 input. */
[[nodiscard]] TileWitness TraceTile(const TilePublic& pub,
                                    const std::array<int64_t, kRCMxBlockLen>& input);

/** Constraint-check result for one tile. */
struct TileCheckResult {
    bool ok{false};
    std::string failure;         // first failing constraint id
};

/**
 * Evaluate every AIR constraint over the tile witness (C-E1..E10 + ChaCha +
 * SHA structural identities). Membership sub-relations (T_M/T_X/T_R16) are
 * checked here structurally AND, in the full pipeline, via the dual-alpha
 * LogUp; this returns false on the first violated identity.
 */
[[nodiscard]] TileCheckResult CheckTileConstraints(const TileWitness& w,
                                                   const TableTM& tm,
                                                   const TableTX& tx);

/** Append this tile's LogUp tuples (T_M/T_X/T_R16) to the aggregate builder. */
void AppendTileLookups(const TileWitness& w, const TableTM& tm, const TableTX& tx,
                       Fp2 gamma,
                       LogUpInstance& inst_tm, LogUpInstance& inst_tx,
                       LogUpInstance& inst_r16);

/** Finalize table multiplicities for the three shared instances. */
void FinalizeTableMultiplicities(LogUpInstance& inst_tm, LogUpInstance& inst_tx,
                                 LogUpInstance& inst_r16);

// ---------------------------------------------------------------------------
// 4. End-to-end byte-exactness oracle.
// ---------------------------------------------------------------------------

/**
 * Run TraceTile then compare w.out to the IMMUTABLE reference
 * ExtractMXTileInt64. Returns true iff byte-identical for all 32 lanes.
 */
[[nodiscard]] bool ByteExactVsReference(const TilePublic& pub,
                                        const std::array<int64_t, kRCMxBlockLen>& input);

} // namespace matmul::v4::rc::gkr_air

#endif // BTX_MATMUL_MATMUL_V4_RC_GKR_AIR_H
