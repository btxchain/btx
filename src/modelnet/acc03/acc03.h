// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ACC03_ACC03_H
#define BITCOIN_MODELNET_ACC03_ACC03_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-process proofs for ASR-ART-002 through ASR-VAL-005.
 * ASR-ART-005 stays unqualified: a real runtime load from a second source
 * is not claimed here. Pass latches the other sentences. passed(),
 * gpu_passed(), windows_passed(), release_qualified(), and
 * hardware_qualified() stay false. hosts() stays 1. Spend stays
 * NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0.
 */
struct Acc03Proof {
    std::string manifest_digest_a;
    std::string manifest_digest_b;
    std::string manifest_digest_after_refuse;
    int manifest_children{0};
    int manifest_overflow_children{0};
    std::string manifest_child_err;
    std::string manifest_depth_err;
    std::string manifest_meta_err;
    std::string manifest_length_err;
    int64_t manifest_length_kept{0};

    std::string stream_bytes;
    std::string stream_artifact;
    int64_t stream_peak{0};
    int64_t stream_resumed_from{0};
    std::string stream_cap_err;
    int64_t stream_ceiling{0};

    std::string generation_symlink_err;
    std::string generation_target;
    std::string generation_sealed;
    std::string generation_after_replace;
    std::string generation_replace_err;
    std::string generation_lease_err;
    std::string generation_toctou_err;
    std::string generation_overflow_err;
    bool generation_big_absent{false};

    std::string loader_err;

    bool kv_exact{false};
    std::string kv_tokenizer_err;
    std::string kv_shape_err;
    std::string kv_derivative_err;

    std::vector<int> prefix_after_edit;
    std::vector<int> prefix_after_append;

    std::string tensor_meta_err;
    std::vector<float> tensor;

    bool assure_recomputed{false};
    std::string assure_shortcut_err;
    std::string assure_tamper_err;

    bool prefetch_hot{false};
    int prefetch_speculative{0};
    std::string prefetch_bound_err;
    bool prefetch_revoked_absent{false};
    bool prefetch_third{false};

    int64_t sched_resident{0};
    int64_t sched_moving{0};
    int64_t sched_recompute{0};
    int sched_choice{0};
    int64_t sched_resident_2{0};
    int64_t sched_moving_2{0};
    int64_t sched_recompute_2{0};
    int sched_choice_recompute{0};

    std::vector<float> gradient_sum;
    std::vector<float> gradient_analytic;
    bool gradient_nonzero{false};
    bool weight_changed{false};
    std::string gradient_missing_err;
    bool weight_missing_unchanged{false};

    std::vector<unsigned char> recovered_weights;
    std::vector<unsigned char> recovered_adam_m;
    std::vector<unsigned char> recovered_adam_v;
    std::uint64_t recovered_step{0};
    std::uint64_t recovered_rng{0};
    std::uint64_t recovered_cursor{0};
    std::string recovered_recipe;
    std::string recovered_topology;
    std::uint64_t recovered_epoch{0};
    bool recovered_exact{false};
    std::string recovery_partial_err;
    bool recovery_partial_exact{false};

    std::string wan_duplicate_err;
    std::string wan_incompatible_err;
    std::string wan_influence_err;
    bool wan_accepted{false};

    std::string experience_rights;
    int64_t experience_policy{0};
    std::string experience_body;
    std::string experience_rights_err;
    std::string experience_policy_err;

    int64_t distill_loss_before{0};
    int64_t distill_loss_after{0};
    int64_t distill_weight{0};
    std::string merge_err;
    int64_t merge_blend{0};
    int64_t merge_error{0};

    std::string react_after_bad;
    std::string react_after_good;

    std::string pop_general;
    int64_t pop_general_q{0};
    std::string pop_specialist;
    int64_t pop_specialist_q{0};
    std::string pop_explore;
    std::string pop_explore_err;
    bool pop_single{true};

    int64_t alloc_base_0{0};
    int64_t alloc_base_1{0};
    int64_t alloc_adapt_0{0};
    int64_t alloc_adapt_1{0};

    std::vector<int64_t> shadow_actions;
    int64_t shadow_production{0};

    std::string commit_before_err;
    int64_t commit_score{0};
    std::string commit_hex;
    std::string commit_immutable_err;
    std::string commit_hex_again;

    int64_t confidence_first{0};
    int64_t confidence_repeat{0};
    int64_t confidence_shared{0};
    int64_t confidence_new{0};

    int64_t challenge_after_propose{0};
    std::string challenge_sole_err;
    int64_t challenge_after_sole{0};
    std::string challenge_refute_err;
    int64_t challenge_after_refute{0};
    int64_t challenge_after_independent{0};

    std::string gate_before_err;
    std::string gate_promoted;
    std::string gate_adopted_early;
    std::string gate_adopted;

    int64_t cycle_weight_1{0};
    int64_t cycle_weight_2{0};
    std::uint64_t cycle_step{0};
    int64_t cycle_momentum{0};
    std::string cycle_noop_err;
    int64_t cycle_noop_weight{0};
    std::uint64_t cycle_noop_step{0};
};

class Acc03 {
public:
    bool Pass(const std::string& work_dir, std::string& err);
    /** Owned ids return FIELD, except ASR-ART-005 which returns NIFDT_UNQUALIFIED.
     *  Jrn03 journal ids keep their earlier admission rules. Any other id returns ID. */
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    const Acc03Proof& proof() const { return m_proof; }

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    bool passed() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool Art002(std::string& err);
    bool Art003(std::string& err);
    bool Art004(const std::string& work_dir, std::string& err);
    bool Art005(std::string& err);
    bool Kvc001(std::string& err);
    bool Kvc002(std::string& err);
    bool Kvc003(std::string& err);
    bool Kvc004(std::string& err);
    bool Kvc005(std::string& err);
    bool Kvc006(std::string& err);
    bool Trn001(std::string& err);
    bool Trn002(std::string& err);
    bool Trn003(std::string& err);
    bool Trn004(std::string& err);
    bool Trn005(std::string& err);
    bool Evo001(std::string& err);
    bool Evo002(std::string& err);
    bool Evo003(std::string& err);
    bool Evo004(std::string& err);
    bool Val001(std::string& err);
    bool Val002(std::string& err);
    bool Val003(std::string& err);
    bool Val004(std::string& err);
    bool Val005(std::string& err);

    Acc03Proof m_proof;
    bool m_done{false};
    std::map<std::string, std::string> m_journal;
};

} // namespace modelnet

#endif
