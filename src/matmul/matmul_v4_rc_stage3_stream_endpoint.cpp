// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_stream_endpoint.h>

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>

#include <hash.h>

#include <array>
#include <string>
#include <vector>

// ============================================================================
// ARCHITECTURE DECISION — RECURSIVE-CHILD (concrete cost model).
//
// The reference Poseidon opener BuildRCStage3OpeningConstraintSystem folds a
// depth-3 alg_hash Merkle path in n_rows = path_len + 1 = 4 rows, because one
// Poseidon permutation is ONE row of a round chip.  A SHA-256 compression, by
// contrast, is the fixed 952-instruction program executed over a LANE of 1024
// rows in the vertical boundary AIR (BuildFixedProgramVerticalWitnessBoundary-
// Instance: out.n_rows == 1024 * scheduled_instances).  A SHA256d hash is two
// passes: first pass = ceil((|msg|+9)/64) compressions, second pass = 1.
//
// One §4 endpoint opening folds leaf(value,index) up `path_len` levels:
//   leaf  SHA256d : 1 first-pass block (<=55B preimage) + 1  = 2 compressions
//   node  SHA256d : 2 first-pass blocks (64B preimage)  + 1  = 3 compressions
// so a depth-d path is 2 + 3d compressions, scheduled up to the next power of
// two, each occupying 1024 rows:
//   d=1 :  5 comp -> 8  lanes -> 8192  rows
//   d=3 : 11 comp -> 16 lanes -> 16384 rows
//   d=8 : 26 comp -> 32 lanes -> 32768 rows
// at ~250 vertical columns => 8k..33k rows x 250 Fp3 cells (24 B each) =
// ~50..200 MB PER opening.  INLINE folds this whole vertical block into the
// role's C_rho column-shifted direct product, forcing every fragment kernel and
// every sibling opening to that 8k..33k row schedule; a role with k stream
// endpoints multiplies the width by k at that height.  That is 3-4 orders of
// magnitude heavier than the Poseidon opener (4 rows) and defeats the whole
// point of the light inline product.
//
// RECURSIVE-CHILD keeps the SHA256d fold as a SEPARATE AirConstraintSystem
// child (the aggregation seam air_recurse::ProveAggregate/VerifyAggregate folds
// it exactly as the g4 lane folds BuildChildAirChallengeShaReplayV1), and lets
// C_rho column-shift only the deg-1 binding fragment that pins the committed
// root.  Both pieces are genuinely CS-verifiable via CountWitnessViolationsOnH
// without a full FRI prove, so the closer is testable far under the terminal-
// round budget.  This is the registry lane's stated fallback for intractable
// inline, and it is the one implemented here.
// ============================================================================

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace ar = air_recurse;
namespace ha = stage3_hash_air;

using Fp3 = gf::Fp3;

[[nodiscard]] Fp3 U32(uint32_t x) { return Fp3::FromFp(gf::FromU64(x)); }

const char* FamilyDomain(RCStage3StreamFamily family)
{
    switch (family) {
    case RCStage3StreamFamily::XofCounter:
        return "BTX_RC_STAGE3_STREAM_ENDPOINT_XOFCOUNTER_V1";
    case RCStage3StreamFamily::ChaChaInitAndBlock:
        return "BTX_RC_STAGE3_STREAM_ENDPOINT_CHACHA_V1";
    case RCStage3StreamFamily::CompleteStream:
        return "BTX_RC_STAGE3_STREAM_ENDPOINT_COMPLETESTREAM_V1";
    case RCStage3StreamFamily::DirectSha256d:
        return "BTX_RC_STAGE3_STREAM_ENDPOINT_DIRECTSHA256D_V1";
    case RCStage3StreamFamily::DirectSha256dEpisodeDigest:
        return "BTX_RC_STAGE3_STREAM_ENDPOINT_DIRECTSHA256D_EPISODEDIGEST_V1";
    case RCStage3StreamFamily::DirectSha256dCoupledBarrier:
        return "BTX_RC_STAGE3_STREAM_ENDPOINT_DIRECTSHA256D_COUPLEDBARRIER_V1";
    case RCStage3StreamFamily::DirectSha256dCoupledDigest:
        return "BTX_RC_STAGE3_STREAM_ENDPOINT_DIRECTSHA256D_COUPLEDDIGEST_V1";
    }
    return "BTX_RC_STAGE3_STREAM_ENDPOINT_UNKNOWN_V1";
}

// A 32-bit domain word derived from the family separator: bound into the leaf
// preimage so a value at leaf_index cannot be replayed across families.
uint32_t FamilyDomainWord(RCStage3StreamFamily family)
{
    HashWriter w;
    w << std::string(FamilyDomain(family));
    const uint256 h = w.GetHash();
    return uint32_t{h.data()[0]} | (uint32_t{h.data()[1]} << 8) |
           (uint32_t{h.data()[2]} << 16) | (uint32_t{h.data()[3]} << 24);
}

// SHA reads message words most-significant-byte first; serialize a 32-bit word
// into the preimage in that big-endian order so MessageWords() recovers it and
// so a linked-in prior digest (already BE-serialized) round-trips word-exact.
void PutBE32(std::vector<uint8_t>& bytes, uint32_t word)
{
    bytes.push_back(static_cast<uint8_t>((word >> 24) & 0xffU));
    bytes.push_back(static_cast<uint8_t>((word >> 16) & 0xffU));
    bytes.push_back(static_cast<uint8_t>((word >> 8) & 0xffU));
    bytes.push_back(static_cast<uint8_t>(word & 0xffU));
}

bool Fail(std::string* why, const char* msg)
{
    if (why != nullptr) *why = msg;
    return false;
}

// One SHA256d step appended to the shared vertical schedule.
struct StepPlan {
    uint32_t base{0};       // first boundary index of this step
    uint32_t n_first{0};    // first-pass compressions
    uint32_t out_index{0};  // boundary whose final_words are the step digest
    std::array<uint32_t, 8> digest_words{}; // == boundaries[out_index].final_words
};

// Build the SHA256d(preimage) compressions, append them to the shared boundary
// vector, mask off the internally-chained externals, and emit the intra-step
// links that wire first-pass block outputs into the next block's chaining state
// and the first-pass digest into the second pass (mirrors the g4 SHA256d fold).
bool AppendSha256dStep(const std::vector<uint8_t>& preimage,
                       std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
                       std::vector<std::vector<uint8_t>>& masks,
                       std::vector<ha::FixedProgramWitnessBoundaryLink>& links,
                       StepPlan& plan, std::string* why)
{
    ha::ShaManifest manifest;
    if (!ha::BuildShaManifest(preimage, ha::ShaMode::Double, manifest, why)) {
        return false;
    }
    std::vector<ha::FixedProgramBoundaryInstance> step;
    if (!ha::BuildShaManifestBoundaryInstances(manifest, step, why)) {
        return false;
    }
    const uint32_t n_first =
        static_cast<uint32_t>(manifest.first.padded_blocks.size());
    if (n_first == 0 || step.size() != n_first + 1) {
        return Fail(why, "stream_endpoint:step_boundary_count");
    }
    plan.base = static_cast<uint32_t>(boundaries.size());
    plan.n_first = n_first;
    plan.out_index = plan.base + n_first;
    for (uint32_t w = 0; w < 8; ++w) {
        plan.digest_words[w] = step.back().final_words[w];
    }
    for (auto& b : step) {
        boundaries.push_back(std::move(b));
        // External layout: message words 0..15, h_in 16..23, K 24..87.
        masks.emplace_back(88, static_cast<uint8_t>(1));
    }
    // Chain first-pass block b-1 output state into block b input chaining state.
    for (uint32_t b = 1; b < n_first; ++b) {
        for (uint32_t w = 0; w < 8; ++w) {
            masks[plan.base + b][16 + w] = 0;
            links.push_back({.source_instance = plan.base + b - 1,
                             .source_final_word = w,
                             .target_instance = plan.base + b,
                             .target_external_address = 17 + w,
                             .link_id = 0});
        }
    }
    // Chain the first-pass digest into the second-pass message words 0..7.
    for (uint32_t w = 0; w < 8; ++w) {
        masks[plan.base + n_first][w] = 0;
        links.push_back({.source_instance = plan.base + n_first - 1,
                         .source_final_word = w,
                         .target_instance = plan.base + n_first,
                         .target_external_address = 1 + w,
                         .link_id = 0});
    }
    return true;
}

// Canonical leaf preimage: domain_word ‖ leaf_index ‖ stream_value(8 words),
// each big-endian.  domain_word + index are public; the value words are the
// private authenticated cell (leaf block-0 message words 2..9).
std::vector<uint8_t> LeafPreimage(RCStage3StreamFamily family,
                                  uint32_t leaf_index,
                                  const std::array<uint32_t, 8>& value)
{
    std::vector<uint8_t> p;
    PutBE32(p, FamilyDomainWord(family));
    PutBE32(p, leaf_index);
    for (uint32_t j = 0; j < 8; ++j) PutBE32(p, value[j]);
    return p;
}

// Canonical node preimage: [acc | sib] (dir==0) or [sib | acc] (dir==1), one
// clean 64-byte block; acc is the previous fold digest, sib the authentication
// sibling.  Direction is resolved by the public index bit.
std::vector<uint8_t> NodePreimage(bool dir, const std::array<uint32_t, 8>& acc,
                                  const std::array<uint32_t, 8>& sib)
{
    std::vector<uint8_t> p;
    const std::array<uint32_t, 8>& first = dir ? sib : acc;
    const std::array<uint32_t, 8>& second = dir ? acc : sib;
    for (uint32_t j = 0; j < 8; ++j) PutBE32(p, first[j]);
    for (uint32_t j = 0; j < 8; ++j) PutBE32(p, second[j]);
    return p;
}

// Scalar SHA256d of a preimage -> 8 state words (the same digest the in-AIR
// fold pins).  Reuses the exact §4 boundary adapter so the scalar root and the
// AIR fold output are byte-identical.
bool Sha256dWords(const std::vector<uint8_t>& pre,
                  std::array<uint32_t, 8>& out, std::string* why)
{
    ha::ShaManifest m;
    if (!ha::BuildShaManifest(pre, ha::ShaMode::Double, m, why)) return false;
    std::vector<ha::FixedProgramBoundaryInstance> b;
    if (!ha::BuildShaManifestBoundaryInstances(m, b, why)) return false;
    if (b.empty() || b.back().final_words.size() != 8) {
        return Fail(why, "stream_endpoint:scalar_digest_shape");
    }
    for (uint32_t i = 0; i < 8; ++i) out[i] = b.back().final_words[i];
    return true;
}

} // namespace

bool RCStage3StreamEndpointCommittedRoot(
    RCStage3StreamFamily family, const RCStage3StreamEndpointManifest& manifest,
    std::array<uint32_t, 8>& out_root, std::string* why)
{
    if (manifest.directions.size() != manifest.siblings.size()) {
        return Fail(why, "stream_endpoint:manifest_shape");
    }
    std::array<uint32_t, 8> acc{};
    if (!Sha256dWords(
            LeafPreimage(family, manifest.leaf_index, manifest.stream_value),
            acc, why)) {
        return false;
    }
    for (size_t level = 0; level < manifest.siblings.size(); ++level) {
        std::array<uint32_t, 8> next{};
        if (!Sha256dWords(NodePreimage(manifest.directions[level], acc,
                                       manifest.siblings[level]),
                          next, why)) {
            return false;
        }
        acc = next;
    }
    out_root = acc;
    return true;
}

RCStage3StreamEndpointManifest BuildRCStage3StreamEndpointCanonicalManifest(
    RCStage3StreamFamily family, const std::array<uint32_t, 8>& stream_value,
    uint32_t leaf_index, uint32_t path_len)
{
    RCStage3StreamEndpointManifest m;
    m.leaf_index = leaf_index;
    m.stream_value = stream_value;
    m.siblings.resize(path_len);
    m.directions.resize(path_len);
    for (uint32_t level = 0; level < path_len; ++level) {
        // Deterministic per-level sibling seeded from family/index/level.
        HashWriter w;
        w << std::string(FamilyDomain(family));
        w << static_cast<uint32_t>(leaf_index);
        w << static_cast<uint32_t>(level);
        const uint256 h = w.GetHash();
        for (uint32_t j = 0; j < 8; ++j) {
            m.siblings[level][j] =
                uint32_t{h.data()[4 * j]} |
                (uint32_t{h.data()[4 * j + 1]} << 8) |
                (uint32_t{h.data()[4 * j + 2]} << 16) |
                (uint32_t{h.data()[4 * j + 3]} << 24);
        }
        m.directions[level] = ((leaf_index >> level) & 1U) != 0U;
    }
    return m;
}

Fp3 RCStage3StreamEndpointCtlValue(
    const RCStage3StreamEndpointManifest& manifest)
{
    return gf::Add(
        U32(manifest.stream_value[0]),
        gf::Add(
            gf::Mul(
                Fp3{0, 1, 0},
                U32(manifest.stream_value[1])),
            gf::Mul(
                Fp3{0, 0, 1},
                U32(manifest.stream_value[2]))));
}

RCStage3StreamEndpointClosure RCStage3StreamEndpointClose(
    RCStage3StreamFamily family,
    const RCStage3StreamEndpointManifest& manifest, const uint256& fs_seed,
    std::string* why, bool run_cs_checks,
    const uint256& precommitted_base_row)
{
    RCStage3StreamEndpointClosure out;
    out.family = family;
    out.leaf_index = manifest.leaf_index;
    out.path_len = static_cast<uint32_t>(manifest.siblings.size());
    if (manifest.directions.size() != manifest.siblings.size()) {
        out.note = "stream_endpoint:manifest_shape";
        return out;
    }
    if (fs_seed.IsNull()) {
        out.note = "stream_endpoint:null_fs_seed";
        return out;
    }

    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    std::vector<std::vector<uint8_t>> masks;
    std::vector<ha::FixedProgramWitnessBoundaryLink> links;

    // Leaf step: preimage = domain_word ‖ leaf_index ‖ stream_value(8 words).
    // domain_word + index are PUBLIC (mask 1); the 8 stream-value message words
    // are PRIVATE witness (mask 0) — this is the authenticated cell.
    const std::vector<uint8_t> leaf_pre =
        LeafPreimage(family, manifest.leaf_index, manifest.stream_value);
    StepPlan leaf;
    std::string step_why;
    if (!AppendSha256dStep(leaf_pre, boundaries, masks, links, leaf, &step_why)) {
        out.note = "stream_endpoint:leaf:" + step_why;
        return out;
    }
    // Value message words occupy leaf block-0 words 2..9 (domain@0, index@1).
    for (uint32_t w = 0; w < 8; ++w) masks[leaf.base][2 + w] = 0;

    // Node steps: preimage = [acc | sib] (dir==0) or [sib | acc] (dir==1), each
    // a clean 64-byte block.  acc == previous step digest (cross-linked from the
    // previous step's output); sib is PRIVATE witness (mask 0).  Direction is
    // resolved by the PUBLIC index bit at build time — no in-AIR conditional
    // swap needed (the reference opener likewise pins direction to public bits).
    StepPlan prev = leaf;
    for (uint32_t level = 0; level < out.path_len; ++level) {
        const bool dir = manifest.directions[level];
        const std::array<uint32_t, 8>& sib = manifest.siblings[level];
        const std::vector<uint8_t> node_pre =
            NodePreimage(dir, prev.digest_words, sib);
        StepPlan node;
        if (!AppendSha256dStep(node_pre, boundaries, masks, links, node,
                               &step_why)) {
            out.note = "stream_endpoint:node:" + step_why;
            return out;
        }
        // acc + sib message words are all private (mask 0); acc is cross-linked.
        const uint32_t acc_word_base = dir ? 8U : 0U;
        const uint32_t sib_word_base = dir ? 0U : 8U;
        for (uint32_t w = 0; w < 8; ++w) {
            masks[node.base][acc_word_base + w] = 0;
            masks[node.base][sib_word_base + w] = 0;
            links.push_back({.source_instance = prev.out_index,
                             .source_final_word = w,
                             .target_instance = node.base,
                             .target_external_address = 1 + acc_word_base + w,
                             .link_id = 0});
        }
        prev = node;
    }

    // The terminal fold output is the committed stream_column_root.
    out.committed_root = prev.digest_words;

    const auto program =
        ha::BuildCanonicalProgram(ha::ProgramKind::Sha256Compression);
    auto inst = ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
        program, boundaries, masks, links, fs_seed,
        precommitted_base_row);
    if (!inst.valid) {
        out.note = "stream_endpoint:vertical:" + inst.note;
        return out;
    }
    out.child_cs = inst.cs;
    out.child_witness = inst.columns;
    out.child_output_export_base = inst.output_export_base;
    out.child_semantic_compressions =
        static_cast<uint32_t>(boundaries.size());

    // Export the first three stream words as one broadcast Fp3 cell owned by
    // the SHA child.  The vertical witness already exports every first-pass
    // message word at its unique (active,address) row.  Three fixed selectors
    // pick leaf block-0 addresses 2,3,4 (domain and leaf index occupy 0,1);
    // the selected words are broadcast and recomposed inside the AIR.  This
    // gives a direct parent a literal child column to alias to the role CTL
    // cell instead of trusting a duplicated host manifest value.
    const uint32_t word_export_base =
        out.child_cs.n_columns;
    out.child_value_export_column =
        word_export_base + 3U;
    const uint32_t selector_base =
        word_export_base + 4U;
    out.child_cs.n_columns += 7U;
    out.child_witness.resize(
        out.child_cs.n_columns,
        std::vector<Fp3>(
            out.child_cs.n_rows, Fp3::Zero()));
    for (uint32_t word = 0; word < 3; ++word) {
        const uint32_t export_column =
            word_export_base + word;
        std::fill(
            out.child_witness[export_column].begin(),
            out.child_witness[export_column].end(),
            U32(manifest.stream_value[word]));
        std::vector<Fp3> selector(
            out.child_cs.n_rows, Fp3::Zero());
        uint32_t selected_rows = 0;
        for (uint32_t row = 0;
             row < out.child_cs.n_rows; ++row) {
            if (gf::Eq(
                    out.child_witness[
                        inst.input_active_column][row],
                    Fp3::One()) &&
                gf::Canonical(
                    out.child_witness[
                        inst.input_address_column][row].c0) ==
                    2U + word &&
                out.child_witness[
                    inst.input_address_column][row].c1 ==
                    0 &&
                out.child_witness[
                    inst.input_address_column][row].c2 ==
                    0) {
                selector[row] = Fp3::One();
                ++selected_rows;
            }
        }
        if (selected_rows != 1) {
            out.note =
                "stream_endpoint:value_export_schedule";
            return out;
        }
        out.child_witness[selector_base + word] =
            selector;
        out.child_cs.preprocessed.emplace_back(
            selector_base + word,
            std::move(selector));
        out.child_cs.constraints.push_back(
            {
                "stream_endpoint:value_word_constant",
                aq::AirKind::kTransition, 1,
                [export_column](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>& next) {
                    return gf::Sub(
                        next[export_column],
                        cur[export_column]);
                },
            });
        out.child_cs.constraints.push_back(
            {
                "stream_endpoint:value_word_from_sha_input",
                aq::AirKind::kEverywhere, 2,
                [export_column, selector_column =
                                    selector_base + word,
                 input_word = inst.input_word_base](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        cur[selector_column],
                        gf::Sub(
                            cur[export_column],
                            cur[input_word]));
                },
            });
    }
    const Fp3 ctl_value =
        RCStage3StreamEndpointCtlValue(manifest);
    std::fill(
        out.child_witness[
            out.child_value_export_column].begin(),
        out.child_witness[
            out.child_value_export_column].end(),
        ctl_value);
    out.child_cs.constraints.push_back(
        {
            "stream_endpoint:value_export_constant",
            aq::AirKind::kTransition, 1,
            [column =
                 out.child_value_export_column](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>& next) {
                return gf::Sub(
                    next[column], cur[column]);
            },
        });
    out.child_cs.constraints.push_back(
        {
            "stream_endpoint:value_export_recompose",
            aq::AirKind::kEverywhere, 1,
            [column = out.child_value_export_column,
             word_export_base](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                const Fp3 recomposed =
                    gf::Add(
                        cur[word_export_base],
                        gf::Add(
                            gf::Mul(
                                Fp3{0, 1, 0},
                                cur[word_export_base + 1]),
                            gf::Mul(
                                Fp3{0, 0, 1},
                                cur[word_export_base + 2])));
                return gf::Sub(
                    cur[column], recomposed);
            },
        });

    // Terminal root pin: the broadcast final-output export words (constrained in
    // the vertical AIR to equal boundaries.back().final_words) are pinned to the
    // committed root.  Tampering any private stream value / sibling breaks the
    // fold's compression AIR; tampering the root breaks this pin — either way
    // CountWitnessViolationsOnH > 0.
    const uint32_t export_base = inst.output_export_base;
    for (uint32_t w = 0; w < 8; ++w) {
        const uint32_t col = export_base + w;
        const Fp3 want = U32(out.committed_root[w]);
        out.child_cs.constraints.push_back(
            {"stream_endpoint:root_pin", aq::AirKind::kEverywhere, 1,
             [col, want](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
                 return gf::Sub(cur[col], want);
             }});
    }

    // The two internal CS scans are gated: a full vertical SHA scan is heavy
    // (~1024*scheduled rows), so registry composition and fast probes can build
    // the CS/witness without paying the scan and verify on their own schedule.
    out.child_violations =
        run_cs_checks
            ? ar::CountWitnessViolationsOnH(out.child_cs, out.child_witness)
            : 0U;

    // Light deg-1 binding fragment C_rho column-shifts.  The aliasable value is
    // the Fp3 recomposition of the first three stream-value words.
    out.bind_cs = BuildRCStage3StreamEndpointConstraintSystem(
        family, manifest.leaf_index, out.committed_root, out.path_len);
    out.bind_witness =
        BuildRCStage3StreamEndpointWitness(out.committed_root, ctl_value);
    out.bind_value_column = kRCStage3StreamEndpointBindValueColumn;
    out.bind_root_base = kRCStage3StreamEndpointBindRootBase;
    out.bind_violations =
        ar::CountWitnessViolationsOnH(out.bind_cs, out.bind_witness);

    out.ok = (!run_cs_checks || out.child_violations == 0) &&
             out.bind_violations == 0;
    out.note = out.ok ? "stream_endpoint:closed"
                      : "stream_endpoint:violations";
    return out;
}

aq::AirConstraintSystem<gf::Fp3> BuildRCStage3StreamEndpointConstraintSystem(
    RCStage3StreamFamily /*family*/, uint32_t /*leaf_index*/,
    const std::array<uint32_t, 8>& committed_root, uint32_t /*path_len*/)
{
    // Columns: [0] value (aliasable cell), [1] leaf_value (CTL from child leaf),
    // [2..9] committed_root (pinned public constants).  n_rows = 2.
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 2;
    cs.n_columns = kRCStage3StreamEndpointBindWidth;

    // value == leaf_value: the child-authenticated leaf cell equals the alias.
    cs.constraints.push_back(
        {"stream_endpoint:value_alias", aq::AirKind::kEverywhere, 1,
         [](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
             return gf::Sub(cur[kRCStage3StreamEndpointBindValueColumn],
                            cur[kRCStage3StreamEndpointBindValueColumn + 1]);
         }});

    // Root columns pinned to the committed root the child folds to.
    for (uint32_t w = 0; w < 8; ++w) {
        const uint32_t col = kRCStage3StreamEndpointBindRootBase + w;
        const Fp3 want = Fp3::FromFp(gf::FromU64(committed_root[w]));
        cs.constraints.push_back(
            {"stream_endpoint:bind_root_pin", aq::AirKind::kEverywhere, 1,
             [col, want](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
                 return gf::Sub(cur[col], want);
             }});
    }
    return cs;
}

std::vector<std::vector<gf::Fp3>> BuildRCStage3StreamEndpointWitness(
    const std::array<uint32_t, 8>& committed_root, const gf::Fp3& ctl_value)
{
    const uint32_t rows = 2;
    std::vector<std::vector<Fp3>> cols(kRCStage3StreamEndpointBindWidth,
                                       std::vector<Fp3>(rows, Fp3::Zero()));
    for (uint32_t r = 0; r < rows; ++r) {
        cols[kRCStage3StreamEndpointBindValueColumn][r] = ctl_value;
        cols[kRCStage3StreamEndpointBindValueColumn + 1][r] = ctl_value;
        for (uint32_t w = 0; w < 8; ++w) {
            cols[kRCStage3StreamEndpointBindRootBase + w][r] =
                Fp3::FromFp(gf::FromU64(committed_root[w]));
        }
    }
    return cols;
}

} // namespace matmul::v4::rc
