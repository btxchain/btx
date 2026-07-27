// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_verify.h>

#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <matmul/matmul_v4_rc_stage3_coupled.h>
#include <matmul/matmul_v4_rc_stage3_episode.h>
#include <matmul/matmul_v4_rc_stage3_recursive.h>
#include <primitives/block.h>

namespace matmul::v4::rc {
namespace {

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:verify:" + message;
    return false;
}

} // namespace

bool VerifyRCStage3MathematicalProof(const RCStage3SuccinctProof& proof,
                                     const CBlockHeader& header,
                                     const Consensus::Params& params,
                                     int32_t height,
                                     const arith_uint256& target,
                                     std::string* why)
{
    std::string binding_why;
    if (!ValidateRCStage3ConsensusBinding(
            proof, header, params, height, ArithToUint256(target),
            &binding_why)) {
        return Fail(why, "binding:" + binding_why);
    }

    std::string relation_why;
    if (!VerifyRCStage3EpisodeRelations(proof, &relation_why)) {
        return Fail(why, "episode:" + relation_why);
    }

    if (proof.statement == RCStage3StatementKind::Composed &&
        !VerifyRCStage3CoupledRelations(proof, &relation_why)) {
        return Fail(why, "coupled:" + relation_why);
    }
    if (proof.statement == RCStage3StatementKind::Coupled) {
        return Fail(why, "coupled_only_not_authorized");
    }

    if (!VerifyRCStage3CompositionLink(proof, &relation_why)) {
        return Fail(why, "composition:" + relation_why);
    }
    return true;
}

static_assert(!kRCStage3MathematicalVerifierReady,
              "Stage-3 mathematical authority must remain fail-closed");
static_assert(!kRCStage3SuccinctAuthorityReady ||
                  kRCStage3MathematicalVerifierReady,
              "consensus authority cannot precede the complete verifier");
static_assert(!kRCStage3EpisodeRelationsReady,
              "episode proof-only engines are not complete");
static_assert(!kRCStage3CoupledRelationEnginesReady,
              "coupled proof-only engines are not complete");
static_assert(!kRCStage3RecursiveAggregationReady,
              "recursive aggregation fixed point is not complete");

} // namespace matmul::v4::rc
