// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/pow_v4.h>

#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <utility>
#include <vector>

namespace matmul_v4 {

static_assert(kTileB == matmul::v4::kTileB, "v4 tile size constants diverged");

bool ComputeDigest(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                   uint256& digest_out, std::vector<unsigned char>& sketch_payload_out)
{
    // §A.4 Solve (digest + sketch), §E.1 payload.
    uint32_t m = 0;
    if (!matmul::v4::ValidateDims(n, kTileB, m)) {
        return false;
    }
    if (rounds == 0) {
        return false;
    }

    const uint256 sigma = matmul::v4::DeriveSigma(header);
    const uint256 seed_a = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::A);
    const uint256 seed_b = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::B);
    const auto [seed_u, seed_v] = matmul::v4::DeriveProjectorSeeds(header);

    const std::vector<int8_t> A = matmul::v4::ExpandOperand(seed_a, n);
    const std::vector<int8_t> B = matmul::v4::ExpandOperand(seed_b, n);
    const std::vector<int8_t> U = matmul::v4::ExpandProjector(seed_u, m, n);
    const std::vector<int8_t> V = matmul::v4::ExpandProjector(seed_v, n, m);

    // Optimal miner path (§E.3): evaluate the sketch Chat = (U*A)(B*V) over q
    // directly, never forming the n x n product C. This is byte-identical to the
    // full-C reference ComputeSketch(U, ComputeExactProduct(A,B), V) by
    // integer-matrix associativity (U*A)(B*V) == U*(A*B)*V, so the committed
    // payload and digest are unchanged -- it is a pure performance factoring
    // (~2*n^2*m MACs vs Theta(n^3)). The full-C path stays exposed in matmul_v4.h
    // as the consensus/verifier-side reference and is exercised by the unit
    // tests (matmul_v4_sketch_tests: optimal_sketch_matches_full_c_reference).
    const std::vector<matmul::v4::Fq> Chat = matmul::v4::ComputeSketchOptimal(U, A, B, V, n, m);

    sketch_payload_out = matmul::v4::SerializeSketch(Chat);
    digest_out = matmul::v4::ComputeSketchDigest(sigma, sketch_payload_out);
    return true;
}

bool VerifySketch(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                  const std::vector<unsigned char>& sketch_payload, uint256& digest_out)
{
    // §0.7-(1)/§D/§E.2: O(n^2) verify -- regenerate A,B, run sketch-Freivalds,
    // recompute digest. Never forms C, never runs the O(n^3) product.
    uint32_t m = 0;
    if (!matmul::v4::ValidateDims(n, kTileB, m)) {
        return false;
    }

    // Parse and range-check the payload before any hashing/algebra (§D.3-(1)).
    std::vector<matmul::v4::Fq> sketch;
    if (!matmul::v4::ParseSketch(sketch_payload, m, sketch)) {
        return false;
    }

    const uint256 sigma = matmul::v4::DeriveSigma(header);

    // Digest recompute and Fiat-Shamir binding both use the payload as shipped.
    digest_out = matmul::v4::ComputeSketchDigest(sigma, sketch_payload);
    if (digest_out != header.matmul_digest) {
        return false;
    }

    const uint256 seed_a = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::A);
    const uint256 seed_b = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::B);
    const auto [seed_u, seed_v] = matmul::v4::DeriveProjectorSeeds(header);

    const std::vector<int8_t> A = matmul::v4::ExpandOperand(seed_a, n);
    const std::vector<int8_t> B = matmul::v4::ExpandOperand(seed_b, n);
    const std::vector<int8_t> U = matmul::v4::ExpandProjector(seed_u, m, n);
    const std::vector<int8_t> V = matmul::v4::ExpandProjector(seed_v, n, m);

    return matmul::v4::SketchFreivalds(A, B, U, V, sketch, sigma, sketch_payload, n, m, rounds);
}

bool PayloadMatchesCommitment(const CBlockHeader& header,
                             const std::vector<unsigned char>& sketch_payload)
{
    // Recompute the digest over the payload exactly as shipped (§E.1 binding).
    // A payload that does not hash to the committed digest is a body mutation:
    // the header is unchanged, so a correct payload for this same header exists.
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    return matmul::v4::ComputeSketchDigest(sigma, sketch_payload) == header.matmul_digest;
}

} // namespace matmul_v4
