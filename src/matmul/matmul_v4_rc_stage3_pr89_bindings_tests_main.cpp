// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Isolated private binary (dodges test_btx relink contention) exercising the
// two new PR-89 endpoint bindings:
//   #4 EpisodeBuilderTrace  (hybrid BuilderTraceSchedule alg-fold + junction pin)
//   #8 EpisodeGemmSumcheck  (Thaler product-sumcheck alg-FS binding)

#include <matmul/matmul_v4_rc_stage3_episode_builder_trace_binding.h>
#include <matmul/matmul_v4_rc_stage3_gemm_sumcheck_binding.h>

#include <hash.h>
#include <util/translation.h>

#include <chrono>
#include <cstdio>
#include <functional>
#include <string>

// Normally supplied by the daemon/CLI entry point; the isolated test binary
// provides its own no-op translation hook.
const std::function<std::string(const char*)> G_TRANSLATION_FUN{};

using namespace matmul::v4::rc;
namespace gf = gkr_field;
using gf::Fp3;

static int g_pass = 0;
static int g_fail = 0;

static void Check(bool cond, const std::string& label)
{
    if (cond) {
        ++g_pass;
        std::printf("  PASS  %s\n", label.c_str());
    } else {
        ++g_fail;
        std::printf("  FAIL  %s\n", label.c_str());
    }
}

static uint256 Seeded(uint64_t s)
{
    HashWriter h;
    h << "BTX_PR89_BINDING_TEST_SEED" << s;
    return h.GetHash();
}

// ---------------------------------------------------------------------------
// Binding #8: EpisodeGemmSumcheck
// ---------------------------------------------------------------------------
static void TestSumcheck()
{
    std::printf("\n=== Binding #8 EpisodeGemmSumcheck (Thaler product-sumcheck) ===\n");

    for (uint32_t kappa : {3u, 7u}) { // K = 8 and K = 128
        const uint32_t layer = 2;
        const auto t =
            BuildRCStage3HonestGemmSumcheckLayerTranscript(layer, kappa, 0xBEEF);
        const uint256 root = ComputeRCStage3GemmSumcheckRoot(t);

        auto t0 = std::chrono::steady_clock::now();
        RCStage3GemmSumcheckAlgBindingResult r;
        std::string why;
        const bool ok = VerifyRCStage3GemmSumcheckAlgBinding(
            t, t.initial_claim, root, r, &why);
        auto t1 = std::chrono::steady_clock::now();
        const double ms =
            std::chrono::duration<double, std::milli>(t1 - t0).count();

        std::printf("[honest K=2^%u, rounds=%u] complete=%d air_proved=%d "
                    "air_verified=%d fs=%d fold_pin=%d  (%.2f ms/instance)\n",
                    kappa, kappa, (int)r.binding_complete, (int)r.air_proved,
                    (int)r.air_verified, (int)r.challenge_fs_ok,
                    (int)r.fold_root_pinned, ms);
        Check(ok && r.binding_complete,
              "honest K=2^" + std::to_string(kappa) + " accepts (all 4 families + in-AIR)");
        Check(r.air_proved && r.air_verified,
              "honest K=2^" + std::to_string(kappa) + " in-AIR quotient proof verifies");

        const auto pin = RCStage3GemmSumcheckWireSemanticPin(r);
        Check(pin.semantic_relation_complete && pin.sumcheck_root == root,
              "semantic pin exposes complete=true + sumcheck_root");
    }

    // Fixed layer for tamper tests (K = 8).
    const uint32_t kappa = 3, layer = 5;
    const auto base =
        BuildRCStage3HonestGemmSumcheckLayerTranscript(layer, kappa, 0x1234);
    const uint256 base_root = ComputeRCStage3GemmSumcheckRoot(base);

    // (a) tamper a g_k polynomial coefficient -> chaining fails + in-AIR rejects.
    {
        auto t = base;
        t.rounds[1].g0 = gf::Add(t.rounds[1].g0, Fp3::One());
        const uint256 root = ComputeRCStage3GemmSumcheckRoot(t);
        RCStage3GemmSumcheckAlgBindingResult r;
        const bool ok =
            VerifyRCStage3GemmSumcheckAlgBinding(t, t.initial_claim, root, r, nullptr);
        Check(!ok && !r.chaining_ok, "TAMPER g_k coeff -> chaining rejects (" + r.note + ")");
        Check(!r.air_proved, "TAMPER g_k coeff -> in-AIR quotient rejects");
    }

    // (b) wrong r_k (FS-inconsistent), families i/ii/iii kept consistent so ONLY
    // the alg-hash sponge FS family rejects.
    {
        auto t = base;
        auto& last = t.rounds.back();
        last.r = gf::Add(last.r, Fp3::One());
        // Recompute terminal claim for the tampered r and re-pin a_eval*b_eval.
        Fp3 claim = t.initial_claim;
        for (size_t k = 0; k < t.rounds.size(); ++k) {
            const auto& rd = t.rounds[k];
            const Fp3 inv2 = gf::Inv(gf::FromU64_3(2));
            const Fp3 rm1 = gf::Sub(rd.r, gf::FromU64_3(1));
            const Fp3 rm2 = gf::Sub(rd.r, gf::FromU64_3(2));
            const Fp3 l0 = gf::Mul(gf::Mul(rm1, rm2), inv2);
            const Fp3 l1 = gf::Sub(gf::FromU64_3(0), gf::Mul(rd.r, rm2));
            const Fp3 l2 = gf::Mul(gf::Mul(rd.r, rm1), inv2);
            claim = gf::Add(gf::Add(gf::Mul(rd.g0, l0), gf::Mul(rd.g1, l1)),
                            gf::Mul(rd.g2, l2));
        }
        t.a_eval = Fp3::One();
        t.b_eval = claim;
        const uint256 root = ComputeRCStage3GemmSumcheckRoot(t);
        RCStage3GemmSumcheckAlgBindingResult r;
        const bool ok =
            VerifyRCStage3GemmSumcheckAlgBinding(t, t.initial_claim, root, r, nullptr);
        Check(!ok && !r.challenge_fs_ok && r.chaining_ok && r.terminal_ok,
              "TAMPER r_k (FS-inconsistent) -> sponge FS rejects, others hold (" + r.note + ")");
    }

    // (c) claim_last != a_eval*b_eval -> terminal fails + in-AIR rejects.
    {
        auto t = base;
        t.b_eval = gf::Add(t.b_eval, Fp3::One());
        RCStage3GemmSumcheckAlgBindingResult r;
        const bool ok = VerifyRCStage3GemmSumcheckAlgBinding(
            t, t.initial_claim, base_root, r, nullptr);
        Check(!ok && !r.terminal_ok, "TAMPER claim_last!=a*b -> terminal rejects (" + r.note + ")");
        Check(!r.air_proved, "TAMPER terminal -> in-AIR quotient rejects");
    }

    // (d) wrong initial claim vs Y commitment -> initial fails.
    {
        RCStage3GemmSumcheckAlgBindingResult r;
        const Fp3 wrong_y = gf::Add(base.initial_claim, Fp3::One());
        const bool ok =
            VerifyRCStage3GemmSumcheckAlgBinding(base, wrong_y, base_root, r, nullptr);
        Check(!ok && !r.initial_claim_ok, "TAMPER initial claim vs Y -> initial rejects (" + r.note + ")");
    }

    // (e) wrong sumcheck_commitment pin -> fold pin fails (families all hold).
    {
        RCStage3GemmSumcheckAlgBindingResult r;
        const bool ok = VerifyRCStage3GemmSumcheckAlgBinding(
            base, base.initial_claim, Seeded(999), r, nullptr);
        Check(!ok && !r.fold_root_pinned && r.chaining_ok && r.terminal_ok &&
                  r.challenge_fs_ok,
              "TAMPER sumcheck_commitment pin -> fold pin rejects (" + r.note + ")");
    }
}

// ---------------------------------------------------------------------------
// Binding #4: EpisodeBuilderTrace
// ---------------------------------------------------------------------------
static RCStage3EpisodeBuilderTraceProduct BuildSyntheticProduct(
    std::vector<uint256>& ep3_roots_out)
{
    RCStage3EpisodeBuilderTraceProduct p;
    p.statement_commitment = Seeded(0x5747);
    p.root_memory.endpoint = RCStage3RelationEndpoint::EpisodeBuilderTrace;

    // Two expansions, each with two dequant shards.
    ep3_roots_out.clear();
    for (uint32_t j = 0; j < 2; ++j) {
        RCStage3EpisodeBuilderTraceExpansion e;
        e.expansion_index = j;
        e.kind = (j == 0) ? RCStage3EpisodeOperandKind::Q
                          : RCStage3EpisodeOperandKind::WUp;
        e.round_index = j;
        e.layer_index = 0;
        e.rows = 16;
        e.cols = 8;
        e.operand_xof_indices = {j * 2u, j * 2u + 1u};
        e.source_link_root = Seeded(0x3000 + j); // == ep3 §4 stream root
        ep3_roots_out.push_back(e.source_link_root);
        for (uint32_t s = 0; s < 2; ++s) {
            RCStage3EpisodeBuilderTraceAirShard sh;
            sh.shard_index = s;
            sh.output_root = Seeded(0x4000 + j * 16 + s);
            e.shards.push_back(sh);
        }
        p.expansions.push_back(e);
    }

    // Three trace columns; wiring_vector_root is the genuine VectorRoot the
    // GEMM operand openings (endpoints 5/6) open, computed from the expansion's
    // shard output roots via the production helper.
    for (uint32_t i = 0; i < 3; ++i) {
        RCStage3EpisodeBuilderTraceColumn c;
        c.trace_index = i;
        c.tensor = RCGkrTensor::Q;
        c.round_index = i;
        c.layer_index = 0;
        c.rows = 16;
        c.cols = 8;
        c.first_column = i * 8;
        c.n_chunks = 4;
        c.expansion_index = i % 2;
        std::vector<uint256> shard_roots;
        for (const auto& sh : p.expansions[c.expansion_index].shards) {
            shard_roots.push_back(sh.output_root);
        }
        c.wiring_vector_root = ComputeRCStage3EpisodeWiringVectorRoot(
            p.statement_commitment, c.first_column, c.n_chunks,
            static_cast<uint64_t>(c.n_chunks) * 8, shard_roots);
        p.trace_columns.push_back(c);
    }
    return p;
}

static void TestBuilderTrace()
{
    std::printf("\n=== Binding #4 EpisodeBuilderTrace (two-layer alg fold + junction pin) ===\n");

    std::vector<uint256> ep3;
    const auto base = BuildSyntheticProduct(ep3);
    const auto roots = ComputeRCStage3BuilderTraceAlgRoots(base);

    // Honest.
    {
        RCStage3BuilderTraceAlgBindingResult r;
        std::string why;
        const bool ok = VerifyRCStage3BuilderTraceAlgBinding(
            base, roots.expansion_ledger_root, roots.builder_trace_root, ep3, r, &why);
        std::printf("[honest] complete=%d canonical=%d exp_ledger=%d trace_ledger=%d "
                    "cross_pin=%d root_mem=%d wiring_roots=%zu\n",
                    (int)r.binding_complete, (int)r.schedule_canonical_ordered,
                    (int)r.expansion_ledger_matches, (int)r.trace_ledger_matches,
                    (int)r.cross_pin_ok, (int)r.root_memory_consistent,
                    r.wiring_vector_roots.size());
        Check(ok && r.binding_complete, "honest schedule accepts (leaf-for-leaf + junction)");
        Check(r.wiring_vector_roots.size() == base.trace_columns.size(),
              "wiring_vector_roots exported for every trace column (endpoints 5/6)");
        const auto pin = RCStage3BuilderTraceWireSemanticPin(r);
        Check(pin.semantic_relation_complete &&
                  pin.builder_trace_root == roots.builder_trace_root &&
                  pin.wiring_vector_roots.size() == base.trace_columns.size(),
              "semantic pin exposes complete=true + builder_trace_root + operand roots");
    }

    // (a) reorder a trace column -> non-canonical index -> reject.
    {
        auto p = base;
        std::swap(p.trace_columns[0], p.trace_columns[2]); // trace_index now 2,1,0
        RCStage3BuilderTraceAlgBindingResult r;
        const bool ok = VerifyRCStage3BuilderTraceAlgBinding(
            p, roots.expansion_ledger_root, roots.builder_trace_root, ep3, r, nullptr);
        Check(!ok && !r.schedule_canonical_ordered,
              "TAMPER reorder trace column -> rejects (" + r.note + ")");
    }

    // (b) omit a trace column -> recomputed builder_trace_root != committed.
    {
        auto p = base;
        p.trace_columns.pop_back();
        RCStage3BuilderTraceAlgBindingResult r;
        const bool ok = VerifyRCStage3BuilderTraceAlgBinding(
            p, roots.expansion_ledger_root, roots.builder_trace_root, ep3, r, nullptr);
        Check(!ok && !r.trace_ledger_matches,
              "TAMPER omit trace column -> rejects (" + r.note + ")");
    }

    // (c) substitute a trace column field -> leaf changes -> reject.
    {
        auto p = base;
        p.trace_columns[1].rows = 32;
        RCStage3BuilderTraceAlgBindingResult r;
        const bool ok = VerifyRCStage3BuilderTraceAlgBinding(
            p, roots.expansion_ledger_root, roots.builder_trace_root, ep3, r, nullptr);
        Check(!ok && !r.trace_ledger_matches,
              "TAMPER substitute trace column field -> rejects (" + r.note + ")");
    }

    // (d) mismatched source_link_root vs ep3 stream root -> junction reject.
    {
        auto ep3_bad = ep3;
        ep3_bad[1] = Seeded(0xDEAD);
        RCStage3BuilderTraceAlgBindingResult r;
        const bool ok = VerifyRCStage3BuilderTraceAlgBinding(
            base, roots.expansion_ledger_root, roots.builder_trace_root, ep3_bad, r, nullptr);
        Check(!ok && !r.cross_pin_ok,
              "TAMPER source_link_root != ep3 stream root -> junction rejects (" + r.note + ")");
    }

    // (e) wrong wiring_vector_root -> trace leaf changes -> reject.
    {
        auto p = base;
        p.trace_columns[0].wiring_vector_root = Seeded(0xBAD0);
        RCStage3BuilderTraceAlgBindingResult r;
        const bool ok = VerifyRCStage3BuilderTraceAlgBinding(
            p, roots.expansion_ledger_root, roots.builder_trace_root, ep3, r, nullptr);
        Check(!ok && !r.trace_ledger_matches,
              "TAMPER wrong wiring_vector_root -> rejects (" + r.note + ")");
    }

    // (f) tamper an expansion shard root -> expansion ledger changes -> reject.
    {
        auto p = base;
        p.expansions[0].shards[0].output_root = Seeded(0xBAD1);
        RCStage3BuilderTraceAlgBindingResult r;
        const bool ok = VerifyRCStage3BuilderTraceAlgBinding(
            p, roots.expansion_ledger_root, roots.builder_trace_root, ep3, r, nullptr);
        Check(!ok && !r.expansion_ledger_matches,
              "TAMPER expansion shard root -> expansion ledger rejects (" + r.note + ")");
    }
}

int main()
{
    std::printf("PR-89 endpoint bindings — isolated differential/tamper suite\n");
    TestSumcheck();
    TestBuilderTrace();
    std::printf("\n==== RESULT: %d passed, %d failed ====\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
