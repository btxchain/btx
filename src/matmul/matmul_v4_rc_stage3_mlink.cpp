// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_mlink.h>

#include <hash.h>

#include <cmath>
#include <limits>

namespace matmul::v4::rc::stage3_mlink {
namespace {

using gkr_field::Fp3;

/** Seed root binding every ordered shard commitment, the manifest commitment
 *  and a draw counter. The challenges are squeezed from this; the shard roots
 *  are inputs, so they can never depend on the challenges (no FS fixed point). */
uint256 SeedRoot(const std::vector<uint256>& ordered_shard_roots,
                 const uint256& manifest_commitment,
                 uint32_t draw_counter)
{
    HashWriter h;
    h << kMLinkChallengeDomainV1;
    h << manifest_commitment;
    h << static_cast<uint32_t>(ordered_shard_roots.size());
    for (const auto& root : ordered_shard_roots) h << root;
    h << draw_counter;
    return h.GetHash();
}

Fp3 DrawFp3(const uint256& seed_root, uint32_t index)
{
    HashWriter h;
    h << kMLinkChallengeDomainV1;
    h << seed_root;
    h << index;
    const uint256 digest = h.GetHash();
    return gkr_field::FromChallengeBytes3(digest.begin());
}

/** Tuple RLC over (row_index, value): t = row_index + alpha * value. Row-first
 *  tagging means a pure row permutation (same values, different rows) changes
 *  the compressed tuple and is caught, which value-only equality would miss. */
Fp3 CompressTuple(const MLinkCellV1& cell, const Fp3& alpha)
{
    return gkr_field::Add(gkr_field::FromU64_3(cell.row_index),
                          gkr_field::Mul(alpha, cell.value));
}

} // namespace

MLinkChallengesV1 DeriveMLinkChallengesV1(
    const std::vector<uint256>& ordered_shard_roots,
    const uint256& manifest_commitment,
    const std::vector<MLinkObligationV1>& obligations,
    uint32_t max_draws)
{
    MLinkChallengesV1 ch;
    ch.drawn_after_all_shard_commitments = true;
    for (uint32_t draw = 0; draw < std::max<uint32_t>(1, max_draws); ++draw) {
        const uint256 seed = SeedRoot(ordered_shard_roots, manifest_commitment, draw);
        ch.draw_counter = draw;
        ch.gamma[0] = DrawFp3(seed, 0);
        ch.alpha[0] = DrawFp3(seed, 1);
        ch.beta[0] = DrawFp3(seed, 2);
        ch.gamma[1] = DrawFp3(seed, 3);
        ch.alpha[1] = DrawFp3(seed, 4);
        ch.beta[1] = DrawFp3(seed, 5);

        // Reject any structurally weak lane (zero alpha/beta drops the tuple or
        // the link batching).
        bool weak = false;
        for (int lane = 0; lane < 2; ++lane) {
            if (gkr_field::IsZero(ch.alpha[lane]) ||
                gkr_field::IsZero(ch.beta[lane])) {
                weak = true;
            }
        }
        if (weak) continue;

        // Reject any gamma that collides with a committed tuple (denominator 0)
        // in either lane; that would make Inv() return 0 and silently break the
        // fraction identity.
        bool degenerate = false;
        for (const auto& ob : obligations) {
            for (int lane = 0; lane < 2 && !degenerate; ++lane) {
                for (const auto& cell : ob.anchor_cells) {
                    if (gkr_field::IsZero(
                            gkr_field::Sub(ch.gamma[lane],
                                           CompressTuple(cell, ch.alpha[lane])))) {
                        degenerate = true;
                        break;
                    }
                }
                for (const auto& cell : ob.replica_cells) {
                    if (degenerate) break;
                    if (gkr_field::IsZero(
                            gkr_field::Sub(ch.gamma[lane],
                                           CompressTuple(cell, ch.alpha[lane])))) {
                        degenerate = true;
                        break;
                    }
                }
            }
            if (degenerate) break;
        }
        if (!degenerate) {
            ch.degenerate_free = true;
            return ch;
        }
    }
    ch.degenerate_free = false;
    return ch;
}

MLinkEvalV1 EvaluateMLinkV1(
    const std::vector<MLinkObligationV1>& obligations,
    const MLinkChallengesV1& challenges)
{
    MLinkEvalV1 out;
    out.link_count = static_cast<uint32_t>(obligations.size());
    if (!challenges.drawn_after_all_shard_commitments) {
        out.note = "stage3:mlink:challenges_not_post_commitment";
        return out;
    }

    bool inverse_ok_all = true;
    for (int lane = 0; lane < 2; ++lane) {
        const Fp3 gamma = challenges.gamma[lane];
        const Fp3 alpha = challenges.alpha[lane];
        const Fp3 beta = challenges.beta[lane];

        Fp3 accumulator = Fp3::Zero();     // root=0 pin: starts at zero.
        Fp3 beta_power = beta;             // link k contributes beta^{k+1}.
        bool inverse_ok = true;
        uint32_t first_nonzero = std::numeric_limits<uint32_t>::max();

        for (const auto& ob : obligations) {
            Fp3 bracket = Fp3::Zero();
            const auto accumulate = [&](const MLinkCellV1& cell, bool anchor) {
                const Fp3 denom = gkr_field::Sub(gamma, CompressTuple(cell, alpha));
                const Fp3 inv = gkr_field::Inv(denom);
                // Degree-2 inverse witness: inv * (gamma - t) - 1 == 0.
                if (!gkr_field::Eq(gkr_field::Mul(inv, denom), Fp3::One())) {
                    inverse_ok = false;
                }
                bracket = anchor ? gkr_field::Add(bracket, inv)
                                 : gkr_field::Sub(bracket, inv);
            };
            for (const auto& cell : ob.anchor_cells) accumulate(cell, true);
            for (const auto& cell : ob.replica_cells) accumulate(cell, false);

            if (!gkr_field::IsZero(bracket) &&
                first_nonzero == std::numeric_limits<uint32_t>::max()) {
                first_nonzero = ob.link_index;
            }
            accumulator = gkr_field::Add(accumulator,
                                         gkr_field::Mul(beta_power, bracket));
            beta_power = gkr_field::Mul(beta_power, beta);

            if (lane == 0) {
                out.tuple_count +=
                    ob.anchor_cells.size() + ob.replica_cells.size();
            }
        }

        out.lane[lane].accumulator_root = accumulator;
        out.lane[lane].root_is_zero = gkr_field::IsZero(accumulator);
        out.lane[lane].inverse_witness_consistent = inverse_ok;
        out.lane[lane].first_nonzero_link = first_nonzero;
        inverse_ok_all = inverse_ok_all && inverse_ok;
    }

    out.executable = inverse_ok_all && challenges.degenerate_free;
    out.honest_all_roots_zero =
        out.lane[0].root_is_zero && out.lane[1].root_is_zero;
    out.link_fires = !out.honest_all_roots_zero;
    if (out.link_fires) {
        for (int lane = 0; lane < 2; ++lane) {
            if (!out.lane[lane].root_is_zero &&
                out.lane[lane].first_nonzero_link !=
                    std::numeric_limits<uint32_t>::max()) {
                out.violated_link_index = out.lane[lane].first_nonzero_link;
                break;
            }
        }
    }
    out.note = out.executable
                   ? (out.honest_all_roots_zero
                          ? "stage3:mlink:executable;honest;root0_both_lanes"
                          : "stage3:mlink:executable;link_fires")
                   : "stage3:mlink:degenerate_challenge_or_inverse_witness";
    return out;
}

std::optional<std::vector<MLinkObligationV1>>
BuildMLinkObligationsFromManifestV1(
    const stage3_relation_local_sharding::RelationLocalShardManifestV1& manifest,
    const MLinkManifestWitnessV1& witness,
    std::string* why)
{
    std::vector<MLinkObligationV1> obligations;
    obligations.reserve(manifest.equality_links.size());
    for (const auto& link : manifest.equality_links) {
        const auto anchor_key =
            std::make_pair(link.anchor_shard, link.anchor_local_column);
        const auto replica_key =
            std::make_pair(link.replica_shard, link.replica_local_column);
        const auto anchor_it = witness.shard_column_cells.find(anchor_key);
        const auto replica_it = witness.shard_column_cells.find(replica_key);
        if (anchor_it == witness.shard_column_cells.end() ||
            replica_it == witness.shard_column_cells.end()) {
            if (why != nullptr) {
                *why = "stage3:mlink:witness_missing_column";
            }
            return std::nullopt;
        }
        MLinkObligationV1 ob;
        ob.link_index = link.index;
        ob.global_column = link.global_column;
        ob.anchor_shard = link.anchor_shard;
        ob.replica_shard = link.replica_shard;
        ob.anchor_cells = anchor_it->second;
        ob.replica_cells = replica_it->second;
        obligations.push_back(std::move(ob));
    }
    return obligations;
}

MLinkSoundnessV1 AssessMLinkSoundnessV1(uint64_t distinct_tuple_events)
{
    MLinkSoundnessV1 out;
    out.event_envelope =
        distinct_tuple_events > 0
            ? distinct_tuple_events
            : static_cast<uint64_t>(kMLinkCtlBusesPerSite) *
                  static_cast<uint64_t>(kMLinkCtlEventsPerBus);
    out.site_log2 =
        std::log2(static_cast<double>(kMLinkCanonicalProductionSites));
    out.event_log2 = std::log2(static_cast<double>(out.event_envelope));

    // Single global gamma-injectivity floor, composed on the same basis as the
    // ledger's CtlRationalIdentity term: log2|Fp3| minus the site count, minus
    // the total tuple-event envelope, minus the FS/FRI query grind. ONE epsilon
    // for the whole M-LINK (one batched accumulator + one global draw per
    // lane), not a 2*Lambda per-link union.
    out.gamma_injectivity_floor_bits =
        kMLinkConservativeFp3Bits - out.site_log2 - out.event_log2 -
        kMLinkGrindingBits;
    out.epsilon_mlink_bits = out.gamma_injectivity_floor_bits;
    out.one_global_epsilon = true;
    out.dual_independent_lanes = true;
    out.clears_minimum_acceptance_bar =
        out.epsilon_mlink_bits >= kMLinkMinimumAcceptanceBar;
    out.clears_qstar_76_threat_bar =
        out.epsilon_mlink_bits >= kMLinkThreatModelQStarBar;
    out.note = "stage3:mlink:single_global_epsilon;dual_fp3_logup_lanes";
    return out;
}

bool MLinkDualLaneArithmeticExecutable() { return true; }

} // namespace matmul::v4::rc::stage3_mlink
