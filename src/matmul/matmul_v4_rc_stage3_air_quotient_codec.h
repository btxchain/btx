// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_AIR_QUOTIENT_CODEC_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_AIR_QUOTIENT_CODEC_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc {

/**
 * WHOLE-PROOF byte codec for AirQuotientProof on the row-wise Alg backends.
 *
 * WHY THIS EXISTS. AirQuotientProof (matmul_v4_rc_air_quotient.h) has three
 * members — `batch`, `next_openings`, `trace_commit` — and until now only
 * `batch` had a real byte serializer (SerializeFri3AlgBatchProof and its dual
 * variants in matmul_v4_rc_fri_ext3_alg.h). The other two were only ever
 * SIZE-ESTIMATED, by EstimateAlgAirProofBytes
 * (matmul_v4_rc_air_recurse.cpp:2995-3018), which is single-lane only; no
 * dual-path size estimator exists anywhere in src/matmul.
 *
 * That mattered for consensus in two ways. First, a Stage-3 relation section
 * that carries an AirQuotientProof cannot be put on the wire at all without a
 * whole-proof encoder. Second, and more insidiously, every "does it fit?"
 * argument about the in-block payload rested partly on a formula that had never
 * been checked against bytes actually produced. This codec closes both: it
 * emits the complete artifact, and MeasuredAirQuotientProofBytes returns the
 *measured length so size claims stop being mixed measured/estimated.
 *
 * SCOPE. Row-wise Alg backends only (AirFriBackendAlg<Fp3> and
 * AirFriBackendAlgDual<Fp3>), which are the ones Stage-3 uses. The per-column
 * backends have a different next_openings layout (W entries per query rather
 * than 2) and are not encoded here.
 *
 * LAYOUT, per the row-wise contract documented at
 * matmul_v4_rc_air_quotient.h:454-462 — note this is NOT the "3 rows + 3
 * row-paths per query" shape assumed by matmul_v4_rc_stage3_verify_cost_model.h,
 * which over-charges. next_openings[qi] has exactly TWO entries:
 *   [0] next-row opening: index, ALL W+1 row values, siblings vs batch.row_commit
 *   [1] trace-binding opening: index, values EMPTY, siblings vs trace_commit
 *
 *   envelope: u32 magic | u16 version | u8 lane_kind | u8 reserved(0)
 *             u32 batch_len | batch bytes (existing codec, verbatim)
 *             uint256 trace_commit
 *             u32 n_queries
 *               per query: u32 n_paths
 *                 per path: u32 index
 *                           u32 n_values | values (3 x u64 LE per Fp3)
 *                           u32 n_siblings | siblings (kAlgHashDigestLen x u64)
 *
 * All integers little-endian. Decoding is canonical: DeserializeAirQuotientProof
 * re-serializes and requires byte equality, so there is exactly one encoding per
 * proof (the same discipline DeserializeRCStage3RoleAirProof uses).
 *
 * UNTRUSTED-PARSE CEILING. Every length is checked against a hard bound BEFORE
 * any allocation, following the kRCFri3AlgBatchMaxColumns / recursive.cpp
 * MAX_VECTOR_ITEMS precedent:
 *   - total input                <= kAirQuotientCodecMaxBytes
 *   - n_queries                  <= kAirQuotientCodecMaxQueries
 *   - n_paths per query          <= kAirQuotientCodecMaxPathsPerQuery
 *   - n_values, n_siblings       <= kRCFri3AlgBatchMaxColumns, and additionally
 *                                   bounded by the bytes actually remaining, so
 *                                   a hostile length can never reserve memory it
 *                                   has not paid for on the wire.
 */

/** "AQP3" */
inline constexpr uint32_t kAirQuotientCodecMagic = 0x33505141U;
inline constexpr uint16_t kAirQuotientCodecVersion = 1;

/** Which batch codec produced the embedded `batch` blob. Carried explicitly so
 *  a dual proof can never be decoded with the single-lane reader. */
enum class AirQuotientCodecLane : uint8_t {
    SingleAlg = 0,   //!< Fri3AlgBatchProof   (SerializeFri3AlgBatchProof)
    DualAlg = 1,     //!< Fri3AlgDualBatchProof (SerializeFri3AlgDualBatchProof)
    DualAlgQ136 = 2, //!< Fri3AlgDualBatchProof (…Q136 envelope)
};

/** Hard parse ceilings. Deliberately generous relative to any real proof and
 *  deliberately finite: the point is that an attacker-chosen length can never
 *  drive an allocation. */
inline constexpr size_t kAirQuotientCodecMaxBytes = 64ULL * 1024ULL * 1024ULL;
inline constexpr uint32_t kAirQuotientCodecMaxQueries = 4096;
inline constexpr uint32_t kAirQuotientCodecMaxPathsPerQuery = 4;

/** The row-wise proof shapes this codec handles. */
using AirQuotientProofAlg =
    air_quotient::AirQuotientProof<gkr_field::Fp3,
                                   air_quotient::AirFriBackendAlg<gkr_field::Fp3>>;
using AirQuotientProofDualAlg =
    air_quotient::AirQuotientProof<gkr_field::Fp3,
                                   air_quotient::AirFriBackendAlgDual<gkr_field::Fp3>>;

[[nodiscard]] bool SerializeAirQuotientProofAlg(const AirQuotientProofAlg& proof,
                                                std::vector<unsigned char>& out,
                                                std::string* why = nullptr);
[[nodiscard]] std::optional<AirQuotientProofAlg>
DeserializeAirQuotientProofAlg(const std::vector<unsigned char>& in,
                               std::string* why = nullptr);

/** DUAL path. `lane` selects which dual envelope the embedded batch uses. */
[[nodiscard]] bool SerializeAirQuotientProofDualAlg(
    const AirQuotientProofDualAlg& proof,
    AirQuotientCodecLane lane,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);
[[nodiscard]] std::optional<AirQuotientProofDualAlg>
DeserializeAirQuotientProofDualAlg(const std::vector<unsigned char>& in,
                                   std::string* why = nullptr);

/**
 * MEASURED whole-artifact size, in bytes, by actually encoding.
 *
 * This is the number that should replace EstimateAlgAirProofBytes in any size
 * argument. It is not a model; if it returns a value, those bytes exist.
 */
[[nodiscard]] std::optional<size_t> MeasuredAirQuotientProofAlgBytes(
    const AirQuotientProofAlg& proof);
[[nodiscard]] std::optional<size_t> MeasuredAirQuotientProofDualAlgBytes(
    const AirQuotientProofDualAlg& proof, AirQuotientCodecLane lane);

/**
 * Size of everything OUTSIDE the batch blob — i.e. exactly the part that had no
 * serializer and was previously only estimated. Reported separately so the
 * previously-estimated remainder can be compared against the formula it
 * replaces, on either lane.
 */
[[nodiscard]] size_t MeasuredAirQuotientWrapperBytes(
    const std::vector<std::vector<air_quotient::AirAlgRowPath>>& next_openings);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_AIR_QUOTIENT_CODEC_H
