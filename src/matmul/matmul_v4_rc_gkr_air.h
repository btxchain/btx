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
// 2b. Committed AIR trace cells (Construction II).
//
// These structs ARE the trace columns: every 32-bit intermediate of the
// ChaCha20 ARX permutation and of the SHA-256 compression is a committed cell.
// The constraint checker and the polynomial emitter (§8 below) consume ONLY
// these cells plus public inputs; they never re-derive an intermediate from
// the raw input, so a swapped cell is caught by a broken algebraic identity.
// ---------------------------------------------------------------------------

/** One committed 32-bit modular add: r = a + b - carry*2^32, carry in {0,1}. */
struct ChaChaAdd {
    uint32_t a{0}, b{0}, r{0};
    uint8_t carry{0};
};

/** Committed cells of one ChaCha20 block (20 rounds + feed-forward). */
struct ChaChaBlockTrace {
    std::array<uint32_t, 16> init{};            // public-bound init state
    std::array<uint32_t, 16> final_working{};   // pre feed-forward
    std::array<uint32_t, 16> keystream_words{}; // post feed-forward
    std::vector<ChaChaAdd> adds;                // 336 = 320 QR + 16 feed-forward
    std::vector<std::array<uint32_t, 3>> xors;  // 320 x {op_a, op_b, result}
    std::array<uint8_t, 64> out_bytes{};        // LE byte image (C-E1 source)
};

/** One committed n-ary modular add (mod 2^32) with integer carry witness. */
struct ShaAdd {
    uint32_t r{0};
    uint8_t carry{0};
    std::vector<uint32_t> terms;
};

/** Committed cells of one SHA-256 compression. */
struct ShaCompressTrace {
    std::array<uint32_t, 8> h_in{};
    std::array<uint32_t, 64> w{};                    // message schedule
    std::array<std::array<uint32_t, 8>, 65> vars{};  // a..h per round boundary
    std::array<uint32_t, 8> h_out{};
    std::vector<ShaAdd> adds;                        // witnessed modular adds
};

// ---------------------------------------------------------------------------
// 3. The Extract-tile AIR: witness + constraint system for ONE tile.
//
// TraceTile() runs the reference sub-primitives (ChaCha20 block, SHA-256
// scale, int64 rejection sampler) and records EVERY intermediate into the
// committed cells above. CheckTileConstraints() evaluates every AIR constraint
// (C-E1..E10, ChaCha ARX wiring, SHA rounds) over the COMMITTED cells plus
// public inputs and the preprocessed tables — it does not re-derive the
// ChaCha/SHA intermediates, so a swapped intermediate is caught by a broken
// algebraic identity, not by re-derivation.
// ---------------------------------------------------------------------------

/** Public per-tile inputs (all native/public functions of the header). */
struct TilePublic {
    uint256 prf_key;
    uint32_t i{0};
    uint32_t bj{0};
};

/** Fully-populated assignment (column vectors) for one Extract tile. */
struct TileWitness {
    TilePublic pub;
    std::array<int64_t, kRCMxBlockLen> input{};   // committed int64 inputs y_t
    std::array<int8_t, kRCMxBlockLen> out{};      // AIR-produced output

    // ChaCha blocks actually consumed (>=1). Each is 16 init + working trace.
    uint32_t chacha_blocks{0};
    std::vector<uint8_t> keystream;               // chacha_blocks * 64 bytes

    // Committed ChaCha ARX cells, one block trace per consumed block. These
    // are the cells the §8 polynomial identities range over.
    std::vector<ChaChaBlockTrace> chacha;

    // SHA scale: committed compression cells (chained blocks of the fixed
    // 67-byte scale message) plus the derived scale outputs.
    std::vector<ShaCompressTrace> scale_sha;
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
        // C-E5 liveness inverse witness: inv_live * (32 - pos) = 1 in Fp.
        // Well-defined because pos < 32 on every candidate row.
        Fp inv_live{0};
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

// ---------------------------------------------------------------------------
// 5. AIR-level intermediate edit hooks (invalid-assignment self-test).
//
// The ChaCha20 / SHA-256 intermediate columns (quarter-round add results,
// working-variable words) are the committed cells of §2b. These hooks build
// an honest in-circuit trace, edit ONE intermediate cell, and return true iff
// the constraint checker (CheckChaChaBlock / CheckShaCompress) REJECTS the
// edited assignment — a violated identity evaluates to a nonzero field
// element at the arithmetic-constraint level, not merely at the output
// boundary. (For the same property through the composition polynomial over a
// full tile, see §8 and air_construction2_composition_polynomial.)
// ---------------------------------------------------------------------------

/** true iff tampering a ChaCha20 quarter-round add result is rejected. */
[[nodiscard]] bool ChaChaIntermediateTamperRejected();

/** true iff tampering a SHA-256 round working variable is rejected. */
[[nodiscard]] bool ShaIntermediateTamperRejected();

// ---------------------------------------------------------------------------
// 6. MxExpand operand-expansion AIR (§5.7 — "grounding the induction").
//
// The leaf operands Q/K/V/X0/W_l/G_L are produced by ExpandMxDequantInt8, i.e.
// the SHA-256 counter-mode mantissa XOF (E2M1 rejection into M11) + the E8M0
// scale XOF, then out[i,j] = mu[i,j]·2^e. This AIR recomputes both XOF streams
// in-circuit (SHA-256 compressions constraint-checked by CheckShaCompress),
// binds each accepted nibble to the (nib,acc,mu) T_M row via the SAME dual-α
// LogUp used by Extract, and binds the committed operand column to the seed by
// the dequant identity. Without this, A/B openings ground out in committed-but-
// unconstrained leaf operands (Forgery F0 again). The int64 reference
// (ExpandMxDequantInt8) stays the sole oracle; this AIR never redefines it.
// ---------------------------------------------------------------------------

/** Result of binding one committed operand column to its expansion seed. */
struct MxExpandVerifyResult {
    bool ok{false};
    std::string failure;
    uint64_t n_mantissa_blocks{0}; // SHA XOF compressions for the mantissa stream
    uint64_t n_scale_blocks{0};    // SHA XOF compressions for the scale stream
};

/**
 * In-circuit MxExpand: recompute the mantissa/scale XOF for `seed` at (rows,cols)
 * with every SHA-256 compression constraint-checked, assert the dequantized
 * output equals `committed_out` byte-for-byte, and append the (nib,acc,mu) T_M
 * lookups to `inst_tm` for the dual-α aggregate. RowBlock scale axis (the
 * consensus ExpandMxDequantInt8 convention). Returns ok=false with the first
 * failing constraint id on any deviation.
 */
[[nodiscard]] MxExpandVerifyResult VerifyMxExpandColumn(const uint256& seed, uint32_t rows,
                                                        uint32_t cols,
                                                        const std::vector<int8_t>& committed_out,
                                                        const TableTM& tm, Fp2 gamma,
                                                        LogUpInstance& inst_tm);

/** Run VerifyMxExpandColumn then compare to ExpandMxDequantInt8 (the reference). */
[[nodiscard]] bool MxExpandByteExactVsReference(const uint256& seed, uint32_t rows, uint32_t cols);

/** true iff tampering a SHA-256 intermediate inside the mantissa XOF is rejected. */
[[nodiscard]] bool MxExpandIntermediateTamperRejected();

// ---------------------------------------------------------------------------
// 7. Tile-tree AIR (§6.3 — round-root binding to the committed extract stream).
//
// The Phase-3 round stream (Z ‖ per-layer X_{l+1} ‖ G_l ‖ D_l as int8 bytes in
// the frozen V1 layout) is hashed by a SHA256d Merkle tile-tree
// (RoundMerkleStream) whose root is the public round_root. This AIR recomputes
// the SAME tree with every SHA-256 compression constraint-checked
// (CheckShaCompress), so a tampered hash intermediate is caught by the ARX
// identity, not merely at the root boundary. It returns the recomputed root; the
// verifier asserts root == round_root. This is the only sound way for the
// succinct verifier to know the PoW-winning roots commit the same bytes the
// sumcheck layers talk about (Thm 5.1 / Forgery F0). RoundMerkleStream is the
// sole oracle; this AIR never redefines the tree layout.
// ---------------------------------------------------------------------------

struct TileTreeCheckResult {
    bool ok{false};
    std::string failure;
    uint256 root;                // recomputed root
    uint64_t n_compressions{0};  // SHA-256 compressions checked
};

/**
 * Recompute the RoundMerkleStream root of `stream` (leaf size `t_leaf`) with
 * in-circuit, constraint-checked SHA-256 compressions and assert it equals
 * `claimed_root`. ok=false + failure id if any compression constraint is
 * violated or the recomputed root differs from `claimed_root`.
 */
[[nodiscard]] TileTreeCheckResult CheckTileTreeInCircuit(const std::vector<int8_t>& stream,
                                                         uint32_t t_leaf,
                                                         const uint256& claimed_root);

/** true iff tampering a SHA-256 intermediate inside a tile-tree hash is rejected. */
[[nodiscard]] bool TileTreeIntermediateTamperRejected();

// ---------------------------------------------------------------------------
// 8. CONSTRUCTION II — the Extract constraint system as explicit low-degree
//    polynomial identities over F_p, plus the composition polynomial.
//
// The map E (ChaCha20 ARX permutation + SHA-256 compression + integer
// rejection sampler) is expressed as a family of polynomial identities
// C_1..C_r of degree <= kAirMaxConstraintDegree over the committed column
// cells, all of which vanish on the trace domain IFF the assignment is a
// correct evaluation of E:
//
//   - add mod 2^32:   a + b - c - 2^32*carry = 0,  carry*(carry-1) = 0, with
//                     operands range-bound by bit columns:
//                     sum_i 2^i b_i - v = 0  and  b_i*(b_i - 1) = 0.
//   - rotate by r:    out - sum_i 2^{(i+r) mod 32} b_i = 0  (a fixed index
//                     relabeling of the bit columns; no new cells).
//   - xor (per bit):  x + y - 2xy - z = 0  (degree 2).
//   - SHA Boolean fns: Maj(a,b,c) = ab+ac+bc-2abc,  Ch(a,b,c) = c + a(b-c),
//                     Sigma/sigma = xors of bit relabelings (degree <= 3).
//   - sampler:        acceptance selector as a degree-4 polynomial in the 4
//                     candidate-nibble bits; liveness (32-pos)*inv - 1 = 0;
//                     position transition pos' - pos - acc = 0; boundary
//                     pos(0) = 0 and pos_final = 32.
//
// Rows are gadget instances (one add, one xor, one SHA round, one sampler
// candidate, ...); slots index the constraint family within a row. All rows
// share ONE random challenge eta in Fp2: the composition value of row x is
//   Comp(x) = sum_slot eta^slot * C_slot(x),
// and the single check is "Comp vanishes on the whole domain". For an
// invalid assignment (some C_slot(x*) != 0), Comp(x*) = 0 for at most
// (n_slots - 1)/|Fp2| of the eta's (Schwartz–Zippel on the slot polynomial),
// so the separation probability of the composition check is
//   <= (kAirSlotBudget - 1)/|Fp2| < 2^8/2^128 = 2^-120   (pre-grinding)
//   -> 2^-80 after the repo grinding convention g = 40.
// ---------------------------------------------------------------------------

/** Maximum slot index + 1 across all gadget rows (bounds the eta-collision). */
inline constexpr uint32_t kAirSlotBudget = 256;
/** Maximum total degree of any emitted constraint polynomial. */
inline constexpr uint32_t kAirMaxConstraintDegree = 4;

// -- degree-<=4 bit-polynomial gadgets over Fp (bits are 0/1 field values) --
/** x XOR y = x + y - 2xy (degree 2). */
[[nodiscard]] Fp AirXorBit(Fp x, Fp y);
/** x XOR y XOR z via nested AirXorBit (degree 3). */
[[nodiscard]] Fp AirXor3Bit(Fp x, Fp y, Fp z);
/** Maj(a,b,c) = ab + ac + bc - 2abc (degree 3). */
[[nodiscard]] Fp AirMajBit(Fp a, Fp b, Fp c);
/** Ch(a,b,c) = c + a(b-c) (degree 2). */
[[nodiscard]] Fp AirChBit(Fp a, Fp b, Fp c);
/** Booleanity b(b-1); zero iff b in {0,1} (degree 2). */
[[nodiscard]] Fp AirBool(Fp b);
/**
 * Acceptance selector of the rejection sampler as a polynomial in the four
 * nibble bits (b0 = LSB): 1 - (1-b2)*((1-b3)*b0 + b3*(1 - b1 + b1*b0)),
 * degree 4. Equals 1 exactly on the 11 accepted E2M1 codes and 0 on the
 * rejected set {1,3,8,9,11} (build-time cross-checked against T_M).
 */
[[nodiscard]] Fp AirAcceptNibblePoly(Fp b0, Fp b1, Fp b2, Fp b3);

/** The flattened evaluations of every constraint polynomial over the trace. */
struct RCAirConstraintSet {
    struct Entry {
        uint64_t row;        // gadget-instance index (trace-domain point)
        uint32_t slot;       // constraint family within the row
        const char* family;  // static identifier (diagnostics)
        Fp value;            // C_slot(row) — must be 0 for a valid assignment
    };
    std::vector<Entry> entries;
    uint64_t n_rows{0};
    uint32_t n_slots{0};     // max slot + 1 actually used (<= kAirSlotBudget)
    void Push(uint64_t row, uint32_t slot, const char* family, Fp value);
};

/**
 * Evaluate EVERY Construction-II constraint polynomial over the committed
 * tile cells: ChaCha ARX (bit decompositions, add/carry identities, per-bit
 * xor, rotation relabelings, dataflow copy constraints), SHA-256 (message
 * schedule, round functions with Ch/Maj/Sigma as bit polynomials, carries,
 * feed-forward, digest/scale binding), and the sampler (C-E1..E10 including
 * the acceptance selector, liveness inverse, position transitions and the
 * MixBits int64 branch). Values are field elements that are zero iff the
 * corresponding identity holds at that row.
 */
[[nodiscard]] RCAirConstraintSet EmitTileConstraints(const TileWitness& w);

/** Result of the composition-polynomial check. */
struct CompositionResult {
    bool ok{false};                 // Comp(x) == 0 for every row x
    uint64_t n_rows{0};
    uint32_t n_slots{0};
    uint64_t n_constraints{0};      // total emitted entries
    uint64_t first_bad_row{0};      // first row with Comp != 0 (if !ok)
    std::string first_bad_families; // families with nonzero value on that row
    double soundness_bits{0.0};     // -log2 separation prob, post-grind g=40
};

/**
 * Combine all constraint families of each row with one challenge eta:
 * Comp(x) = sum_slot eta^slot * C_slot(x). ok iff Comp vanishes on the whole
 * domain. soundness_bits reports 2*log2(p) - log2(n_slots-1) - 40, the
 * -log2 separation probability of an invalid assignment for uniform eta.
 */
[[nodiscard]] CompositionResult ComposeConstraints(const RCAirConstraintSet& cs, Fp2 eta);

/** Composed Construction-II + Construction-III separation bound (bits). */
struct SeparationBound {
    double composition_bits{0.0};  // 2*log2(p) - log2(n_slots-1) - 40
    double lookup_bits{0.0};       // 2*(2*log2(p) - log2(N_w+N_t)) - 40
    double composed_bits{0.0};     // -log2(2^-composition + 2^-lookup)
};
[[nodiscard]] SeparationBound ComputeSeparationBound(uint32_t n_slots, uint64_t n_logup_rows);

// ---------------------------------------------------------------------------
// 9. CONSTRUCTION III — multiset inclusion against a FIXED reference vector.
//
// The assignment multiset W = {w_i} (fingerprinted tuples emitted by the
// Construction-II rows) must be included, with multiplicities, in a fixed
// reference vector T = {t_j} that is regenerable INDEPENDENTLY of the
// assignment: T_M/T_X/T_R16 are consensus constants (functions of nothing
// but the E2M1 decode table and the 4-bit/16-bit index sets). The
// log-derivative identity at a random alpha in Fp2,
//     sum_i 1/(alpha - w_i)  =  sum_j m_j/(alpha - t_j),
// holds as rational functions IFF W ⊆ T with the claimed multiplicities
// (Habock 2022/1530 Lemma 5; char Fp = p ~ 2^64 >> N so multiplicities
// cannot wrap). A false inclusion survives one uniform alpha with
// probability <= (N_w+N_t)/|Fp2|; the dual-alpha instantiation squares it.
//
// GAP-CLOSING obligations enforced by VerifyLookupAgainstPreprocessed:
//   (i)   the reference-vector side of every instance is REGENERATED here
//         and compared fingerprint-by-fingerprint — a vector chosen by the
//         constructing routine (e.g. table := witness) is rejected outright,
//         which closes the Theorem-5.1 vacuity of the shipped v6 check;
//   (ii)  multiplicity accounting: sum_j m_j = |W| exactly (deterministic),
//         and the per-row occurrence counts are certified by the dual-alpha
//         identity itself;
//   (iii) any alpha collision with a key (zero denominator = pole of the
//         log-derivative) fails CLOSED via FracSum/FracSumMult — the
//         summation is never computed through Inv(0).
// ---------------------------------------------------------------------------

/** The fixed reference vectors, fingerprinted; no assignment data enters. */
struct RCAirPreprocessedTables {
    LogUpInstance tm;   // T_M: 16 rows (nib, acc, mu)
    LogUpInstance tx;   // T_X: 256 rows (a, b, a^b)
    LogUpInstance r16;  // T_R16: 65536 rows (v)
};

/**
 * Regenerate the canonical reference vectors from consensus constants only.
 * Deterministic in gamma; contains no witness rows and no multiplicities.
 */
[[nodiscard]] RCAirPreprocessedTables BuildPreprocessedLogUpTables(Fp2 gamma);

/** Result of the Construction-III membership verification. */
struct LookupBindResult {
    bool ok{false};
    std::string failure;      // first failing obligation, if any
    LogUpVerifyResult logup;  // dual-alpha result (valid when reached)
};

/**
 * Verify a set of LogUp instances against the CANONICAL reference vectors:
 * regenerates T_M/T_X/T_R16 from consensus constants, rejects any instance
 * whose table side deviates from the canonical fingerprints (obligation i),
 * enforces sum_j m_j = |W| (obligation ii), then runs the fail-closed
 * dual-alpha log-derivative check (obligation iii).
 */
[[nodiscard]] LookupBindResult VerifyLookupAgainstPreprocessed(
    const std::vector<LogUpInstance>& instances, Fp2 gamma, Fp2 alpha1, Fp2 alpha2);

} // namespace matmul::v4::rc::gkr_air

#endif // BTX_MATMUL_MATMUL_V4_RC_GKR_AIR_H
