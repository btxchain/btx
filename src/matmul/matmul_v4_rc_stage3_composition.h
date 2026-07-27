// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COMPOSITION_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COMPOSITION_H

#include <matmul/matmul_v4_rc_stage3.h>

#include <string>

namespace matmul::v4::rc {

/**
 * Canonical transcript commitment for the complete Stage-3 envelope.
 *
 * The commitment binds the statement, every public input other than the
 * commitment itself, every fixed-role commitment root, and the hash of every
 * relation-proof section in canonical registry order. It is deliberately
 * independent of in-memory object layout.
 */
[[nodiscard]] uint256
ComputeRCStage3TranscriptCommitment(const RCStage3SuccinctProof& proof);

/**
 * Fiat-Shamir base seed for recursive relation aggregates. It binds the public
 * statement, but excludes proof sections, their outer section commitments, and
 * the transcript commitment to avoid a circular proof/seed dependency. Child
 * trace/fold roots are public pins of the verifier AIR and are absorbed by the
 * aggregate proof itself.
 */
[[nodiscard]] uint256
ComputeRCStage3AggregationSeed(const RCStage3SuccinctProof& proof);

/**
 * Consensus digest selected by the Stage-3 statement:
 *
 *  - episode-only: the proved episode digest;
 *  - coupled-only: the proved coupled digest;
 *  - composed: a domain-separated binding of both proved legs and their
 *    header/parameter/profile context.
 */
[[nodiscard]] uint256
ComputeRCStage3FinalDigest(const RCStage3SuccinctProof& proof);

/**
 * Verify the deterministic composition/link relation. This is a real
 * relation check, but it does not verify the episode or coupled proof engines.
 * A complete verifier must AND this result with every required role verifier.
 */
[[nodiscard]] bool
VerifyRCStage3CompositionLink(const RCStage3SuccinctProof& proof,
                              std::string* why = nullptr);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COMPOSITION_H
