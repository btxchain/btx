// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_POSEIDON_BYTECODE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_POSEIDON_BYTECODE_H

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <string>

// ============================================================================
// Bytecode migration of the recursion/leaf-wrap Poseidon2 x^7 replay relation.
//
// stage3_poseidon_air::BuildFixedConstraints emits the 4*118 = 472 quadratic
// identities of the fully-decomposed x^7 S-box (x2 = x*x, x4 = x2*x2,
// x6 = x4*x2, y = x6*x) over the canonical 484-column permutation layout as
// OPAQUE std::function AirConstraint closures. Every one of those residuals is
// pure Fp3 field arithmetic over committed columns, so the whole builder is
// expressible in the constraint_bytecode opcode set
// {Current, Constant, Add, Sub, Mul} with NO Challenge column class.
//
// The affine S-box input form A_s(cells) that the x2 and output residuals
// consume is degree-1 (the Poseidon2 linear layer + round constants). Its Fp
// coefficients are recovered from the existing public air_recurse::PermSboxInput
// by unit-vector evaluation, so this migration hardcodes NO constant table and
// stays bit-identical to the native builder by construction.
//
// This is a proof-only AIR fragment; it carries the recursion-aggregation role
// (CompositionLink) and NO consensus authority. It does not flip any soundness
// or authority flag.
// ============================================================================

namespace matmul::v4::rc::stage3_poseidon_air {

/**
 * Canonical ProgramTable for the fixed (non-selector-gated) Poseidon2 x^7
 * decomposition. Program `4*s + k` for S-box s and k in {0,1,2,3} is the
 * bytecode form of BuildFixedConstraints(CanonicalLayout())[4*s + k], in the
 * identical constraint order. 472 programs, current_width 484, next_width 0,
 * challenge_width 0, every program declared degree 2.
 */
[[nodiscard]] bool BuildFixedProgramTable(
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::stage3_poseidon_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_POSEIDON_BYTECODE_H
