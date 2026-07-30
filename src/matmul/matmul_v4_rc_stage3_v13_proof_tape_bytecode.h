// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_PROOF_TAPE_BYTECODE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_PROOF_TAPE_BYTECODE_H

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v13_proof_tape_air.h>

#include <string>

namespace matmul::v4::rc::stage3_multirow_v13_proof_tape_air {

/**
 * Canonical, proof-independent bytecode for every constraint emitted by
 * BuildConstraintSystemV1, in identical ordinal order.
 *
 * The expected tape digest is loaded from verifier-owned R0 statement
 * columns.  It is deliberately not captured as a bytecode Constant, so the
 * table commitment is stable across child proofs and can be frozen in the
 * recursive program registry.
 */
[[nodiscard]] bool BuildCanonicalProgramTableV1(
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Rebuild the proof-tape AIR with the canonical table as the sole executable
 * relation.  The native builder is used only to regenerate verifier-owned
 * preprocessed schedule columns; its opaque constraint callbacks are
 * discarded before this function returns.
 */
[[nodiscard]] bool BuildCanonicalConstraintSystemV1(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    air_quotient::AirConstraintSystem<
        gkr_field::Fp3>& out,
    LayoutV1* layout = nullptr,
    ScheduleV1* schedule = nullptr,
    constraint_bytecode::ProgramTable*
        program = nullptr,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::stage3_multirow_v13_proof_tape_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_PROOF_TAPE_BYTECODE_H
