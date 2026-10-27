// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acc03/acc03.h>
#include <modelnet/dt_ckpt/codes.h>
#include <modelnet/dt_dense/dt_dense.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>
#include <system_error>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(acc03_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass_latches)
{
    modelnet::Acc03 eng;
    std::string err = "stale";
    const std::string dir = PathToString(m_path_root / "acc03");

    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.Pass("", err));
    BOOST_CHECK_EQUAL(err, "FIELD");

    BOOST_REQUIRE(eng.Pass(dir, err));
    BOOST_CHECK(err.empty());
    const modelnet::Acc03Proof& got = eng.proof();

    BOOST_CHECK_EQUAL(got.manifest_digest_a.size(), static_cast<std::size_t>(96));
    BOOST_CHECK(got.manifest_digest_a != got.manifest_digest_b);
    BOOST_CHECK_EQUAL(got.manifest_digest_a, got.manifest_digest_after_refuse);
    BOOST_CHECK_EQUAL(got.manifest_children, 4);
    BOOST_CHECK_EQUAL(got.manifest_child_err, "CHILDREN");
    BOOST_CHECK_EQUAL(got.manifest_depth_err, "DEPTH");
    BOOST_CHECK_EQUAL(got.manifest_meta_err, "META");
    BOOST_CHECK_EQUAL(got.manifest_length_err, "OVERFLOW");
    BOOST_CHECK_EQUAL(got.manifest_overflow_children, 1);
    BOOST_CHECK_EQUAL(got.manifest_length_kept, std::numeric_limits<int64_t>::max());

    BOOST_CHECK(!got.stream_artifact.empty());
    BOOST_CHECK(got.stream_artifact.find("INTEGER_MODEL") != std::string::npos);
    BOOST_CHECK_EQUAL(got.stream_bytes, got.stream_artifact);
    BOOST_CHECK_EQUAL(got.stream_ceiling, static_cast<int64_t>(32));
    BOOST_CHECK(got.stream_peak > static_cast<int64_t>(0));
    BOOST_CHECK(got.stream_peak <= got.stream_ceiling);
    BOOST_CHECK(got.stream_resumed_from > static_cast<int64_t>(0));
    BOOST_CHECK(got.stream_resumed_from <= static_cast<int64_t>(got.stream_bytes.size()));
    BOOST_CHECK_EQUAL(got.stream_cap_err, "CAP");

    BOOST_CHECK_EQUAL(got.generation_symlink_err, "SYMLINK");
    BOOST_CHECK_EQUAL(got.generation_target, "secret");
    BOOST_CHECK_EQUAL(got.generation_sealed, "alpha-bytes");
    BOOST_CHECK_EQUAL(got.generation_after_replace, "alpha-bytes");
    BOOST_CHECK_EQUAL(got.generation_replace_err, "REPLACEMENT");
    BOOST_CHECK_EQUAL(got.generation_lease_err, "LEASE");
    BOOST_CHECK_EQUAL(got.generation_toctou_err, "TOCTOU");
    BOOST_CHECK_EQUAL(got.generation_overflow_err, "OVERFLOW");
    BOOST_CHECK(got.generation_big_absent);

    BOOST_CHECK_EQUAL(got.loader_err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(got.loader_err, "UNQUALIFIED");

    BOOST_CHECK(got.kv_exact);
    BOOST_CHECK_EQUAL(got.kv_tokenizer_err, "SHAPE");
    BOOST_CHECK_EQUAL(got.kv_shape_err, "SHAPE");
    BOOST_CHECK_EQUAL(got.kv_derivative_err, "DERIVATIVE");

    const std::vector<int> edited{1, 0, 0};
    const std::vector<int> appended{1, 0, 0, 1};
    BOOST_CHECK(got.prefix_after_edit == edited);
    BOOST_CHECK(got.prefix_after_append == appended);

    BOOST_CHECK_EQUAL(got.tensor_meta_err, "METADATA");
    const std::vector<float> tensor{1.5f, -2.f, 3.f};
    BOOST_CHECK(got.tensor == tensor);

    BOOST_CHECK(got.assure_recomputed);
    BOOST_CHECK_EQUAL(got.assure_shortcut_err, "SHORTCUT");
    BOOST_CHECK_EQUAL(got.assure_tamper_err, "BTX035_ID_MISMATCH");

    BOOST_CHECK(got.prefetch_hot);
    BOOST_CHECK_EQUAL(got.prefetch_speculative, 2);
    BOOST_CHECK_EQUAL(got.prefetch_bound_err, "BOUND");
    BOOST_CHECK(got.prefetch_revoked_absent);
    BOOST_CHECK(got.prefetch_third);

    BOOST_CHECK_EQUAL(got.sched_resident, static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(got.sched_moving, static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(got.sched_recompute, static_cast<int64_t>(9));
    BOOST_CHECK_EQUAL(got.sched_choice, 1);
    BOOST_CHECK_EQUAL(got.sched_resident_2, static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(got.sched_moving_2, static_cast<int64_t>(9));
    BOOST_CHECK_EQUAL(got.sched_recompute_2, static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(got.sched_choice_recompute, 2);

    BOOST_CHECK(got.gradient_sum == got.gradient_analytic);
    BOOST_CHECK(!got.gradient_sum.empty());
    BOOST_CHECK(got.gradient_nonzero);
    BOOST_CHECK(got.weight_changed);
    BOOST_CHECK_EQUAL(got.gradient_missing_err, modelnet::DT_DENSE_MISSING);
    BOOST_CHECK(got.weight_missing_unchanged);

    const std::vector<unsigned char> weights{1, 2, 3, 4};
    const std::vector<unsigned char> adam_m{5, 6};
    const std::vector<unsigned char> adam_v{7, 8};
    BOOST_CHECK(got.recovered_weights == weights);
    BOOST_CHECK(got.recovered_adam_m == adam_m);
    BOOST_CHECK(got.recovered_adam_v == adam_v);
    BOOST_CHECK_EQUAL(got.recovered_step, static_cast<std::uint64_t>(7));
    BOOST_CHECK_EQUAL(got.recovered_rng, static_cast<std::uint64_t>(8));
    BOOST_CHECK_EQUAL(got.recovered_cursor, static_cast<std::uint64_t>(9));
    BOOST_CHECK_EQUAL(got.recovered_recipe, "recipe-a");
    BOOST_CHECK_EQUAL(got.recovered_topology, "topo-a");
    BOOST_CHECK_EQUAL(got.recovered_epoch, static_cast<std::uint64_t>(10));
    BOOST_CHECK(got.recovered_exact);
    BOOST_CHECK_EQUAL(got.recovery_partial_err, modelnet::kDtCkptPartial);
    BOOST_CHECK(!got.recovery_partial_exact);

    BOOST_CHECK(got.wan_accepted);
    BOOST_CHECK_EQUAL(got.wan_duplicate_err, "DUPLICATE");
    BOOST_CHECK_EQUAL(got.wan_incompatible_err, "INCOMPATIBLE");
    BOOST_CHECK_EQUAL(got.wan_influence_err, "INFLUENCE_CAP");

    BOOST_CHECK_EQUAL(got.experience_rights, "retain-local");
    BOOST_CHECK_EQUAL(got.experience_policy, static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(got.experience_body, "public-step-2");
    BOOST_CHECK_EQUAL(got.experience_rights_err, "RIGHTS");
    BOOST_CHECK_EQUAL(got.experience_policy_err, "POLICY");

    BOOST_CHECK_EQUAL(got.distill_loss_before, static_cast<int64_t>(20));
    BOOST_CHECK_EQUAL(got.distill_loss_after, static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(got.distill_weight, static_cast<int64_t>(1));
    BOOST_CHECK(got.distill_loss_after < got.distill_loss_before);
    BOOST_CHECK_EQUAL(got.merge_err, "EVAL");
    BOOST_CHECK_EQUAL(got.merge_blend, static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(got.merge_error, static_cast<int64_t>(0));

    BOOST_CHECK_EQUAL(got.react_after_bad, "hold");
    BOOST_CHECK_EQUAL(got.react_after_good, "loss-up");

    BOOST_CHECK_EQUAL(got.pop_general, "winner");
    BOOST_CHECK_EQUAL(got.pop_general_q, static_cast<int64_t>(9));
    BOOST_CHECK_EQUAL(got.pop_specialist, "spec");
    BOOST_CHECK_EQUAL(got.pop_specialist_q, static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(got.pop_explore, "probe");
    BOOST_CHECK_EQUAL(got.pop_explore_err, "EXPLORE");
    BOOST_CHECK(!got.pop_single);

    BOOST_CHECK_EQUAL(got.alloc_base_0, static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(got.alloc_base_1, static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(got.alloc_adapt_0, static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(got.alloc_adapt_1, static_cast<int64_t>(3));
    BOOST_CHECK(got.alloc_base_0 != got.alloc_adapt_0);

    const std::vector<int64_t> shadow{4, 4, 2};
    BOOST_CHECK(got.shadow_actions == shadow);
    BOOST_CHECK_EQUAL(got.shadow_production, static_cast<int64_t>(0));

    BOOST_CHECK_EQUAL(got.commit_before_err, "COMMIT");
    BOOST_CHECK_EQUAL(got.commit_score, static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(got.commit_hex.size(), static_cast<std::size_t>(96));
    BOOST_CHECK_EQUAL(got.commit_immutable_err, "IMMUTABLE");
    BOOST_CHECK_EQUAL(got.commit_hex_again, got.commit_hex);

    BOOST_CHECK_EQUAL(got.confidence_first, static_cast<int64_t>(1000000));
    BOOST_CHECK_EQUAL(got.confidence_repeat, got.confidence_first);
    BOOST_CHECK_EQUAL(got.confidence_shared, got.confidence_first);
    BOOST_CHECK_EQUAL(got.confidence_new, static_cast<int64_t>(500000));

    BOOST_CHECK_EQUAL(got.challenge_after_propose, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(got.challenge_sole_err, "SOLE");
    BOOST_CHECK_EQUAL(got.challenge_after_sole, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(got.challenge_refute_err, "REFUTED");
    BOOST_CHECK_EQUAL(got.challenge_after_refute, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(got.challenge_after_independent, static_cast<int64_t>(4));

    BOOST_CHECK_EQUAL(got.gate_before_err, "GATE");
    BOOST_CHECK_EQUAL(got.gate_promoted, "cand-1");
    BOOST_CHECK(got.gate_adopted_early.empty());
    BOOST_CHECK_EQUAL(got.gate_adopted, "cand-1");

    BOOST_CHECK(got.cycle_weight_1 != got.cycle_weight_2);
    BOOST_CHECK_EQUAL(got.cycle_step, static_cast<std::uint64_t>(2));
    BOOST_CHECK(got.cycle_momentum != static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(got.cycle_noop_err, "WORK");
    BOOST_CHECK_EQUAL(got.cycle_noop_weight, got.cycle_weight_1);
    BOOST_CHECK_EQUAL(got.cycle_noop_step, static_cast<std::uint64_t>(1));

    const std::string digest = got.manifest_digest_a;
    BOOST_CHECK(eng.Pass("", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.proof().manifest_digest_a, digest);
    BOOST_CHECK_EQUAL(eng.proof().cycle_weight_2, got.cycle_weight_2);

    BOOST_CHECK(!eng.Apply("ASR-ART-005", "load", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Apply("ASR-ART-002", "leaf", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Apply("NO-SUCH", "leaf", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");

    std::error_code ec;
    fs::remove_all(fs::PathFromString(dir), ec);
}

BOOST_AUTO_TEST_SUITE_END()
