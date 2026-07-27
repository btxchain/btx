// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Isolated private binary (dodges test_btx relink contention) exercising the
// five remaining PR-89 relation-endpoint bindings with REAL production
// fixtures driven through the executable engines:
//   #10 CoupledBankRoot         (§4 SHA256d manifest clone)
//   #11 CoupledGemmSignedRange  (endpoint-9 value-roots ordered-fold clone)
//   #2  EpisodeBuilderSeedChain (§4 SHA256d per-round seed clone)
//   #7-9 EpisodeWiring{Transpose,Residual,RoundOrder} (ledger binding)

#include <matmul/matmul_v4_rc_stage3_coupled_bank_root_binding.h>
#include <matmul/matmul_v4_rc_stage3_seed_chain_binding.h>
#include <matmul/matmul_v4_rc_stage3_coupled_signed_range_binding.h>
#include <matmul/matmul_v4_rc_stage3_episode_wiring_binding.h>

#include <hash.h>
#include <util/translation.h>

#include <array>
#include <cstdio>
#include <functional>
#include <string>

// Normally supplied by the daemon/CLI entry point; the isolated test binary
// provides its own no-op translation hook.
const std::function<std::string(const char*)> G_TRANSLATION_FUN{};

using namespace matmul::v4::rc;
namespace gf = gkr_field;
namespace ha = stage3_hash_air;

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

static uint256 H(unsigned char value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{Span<const unsigned char>{bytes.data(), bytes.size()}};
}

static RCStage3CoupledShape ToyShape()
{
    return MakeRCStage3CoupledShape(MakeToyRCCoupParams(), MakeV4RCCoupOptions());
}

static RCStage3SuccinctProof CoupledStatement(const uint256& digest = H(0x44))
{
    RCStage3SuccinctProof statement;
    statement.statement = RCStage3StatementKind::Composed;
    statement.public_inputs.height = 17;
    statement.public_inputs.episode_profile = 2;
    statement.public_inputs.coupled_profile = 4;
    statement.public_inputs.transcript_version = ENC_RC_V4;
    statement.public_inputs.header_commitment = H(0x11);
    statement.public_inputs.params_commitment = H(0x22);
    statement.public_inputs.sigma = H(0x33);
    statement.public_inputs.coupled_digest = digest;
    return statement;
}

// ---------------------------------------------------------------------------
// Binding #10: CoupledBankRoot (§4 SHA256d manifest clone)
// ---------------------------------------------------------------------------
static std::vector<uint8_t> BankPages(const RCStage3CoupledShape& shape,
                                      uint8_t seed)
{
    const uint64_t n = uint64_t{shape.bank_pages} * shape.lobe_width *
                       shape.lobe_width;
    std::vector<uint8_t> pages(n);
    for (uint64_t i = 0; i < n; ++i) {
        pages[i] = static_cast<uint8_t>(17 * i + seed);
    }
    return pages;
}

static void TestBankRoot()
{
    std::printf("\n=== Binding #10 CoupledBankRoot (§4 SHA256d manifest clone) ===\n");
    const auto statement = CoupledStatement();
    const auto shape = ToyShape();
    const auto pages = BankPages(shape, 3);

    RCStage3CoupledBankRootManifest manifest;
    std::string why;
    if (!BuildRCStage3CoupledBankRootManifest(statement, shape, pages, manifest,
                                              &why)) {
        Check(false, "BuildRCStage3CoupledBankRootManifest: " + why);
        return;
    }

    RCStage3CoupledBankRootAlgBinding committed;
    if (!ComputeRCStage3CoupledBankRootAlgBinding(manifest, committed, &why)) {
        Check(false, "ComputeRCStage3CoupledBankRootAlgBinding: " + why);
        return;
    }
    std::printf("[honest] instances=%llu stream_root=%s bank_root=%s\n",
                (unsigned long long)committed.instance_count,
                committed.binding.stream_column_root.ToString().substr(0, 12).c_str(),
                committed.bank_root.ToString().substr(0, 12).c_str());

    // Honest accept.
    {
        RCStage3CoupledBankRootBindingResult r;
        const bool ok = VerifyRCStage3CoupledBankRootAlgBinding(
            manifest, committed, manifest.bank_root, r, &why);
        Check(ok && r.binding_complete,
              "honest bank-root binding accepts (§4 stream fold + bank_root pin)");
        Check(r.instance_count_ok && r.instance_count == committed.instance_count,
              "instance_count matches derived compression stream length");
        const auto pin = RCStage3CoupledBankRootWireSemanticPin(r);
        Check(pin.semantic_relation_complete &&
                  pin.stream_column_root == committed.binding.stream_column_root &&
                  pin.bank_root == manifest.bank_root,
              "semantic pin exposes complete=true + stream_column_root + bank_root");
    }

    // (a) reorder pages -> different preimage -> stream/manifest mismatch.
    {
        auto reordered = pages;
        std::swap(reordered.front(), reordered.back());
        RCStage3CoupledBankRootManifest m2;
        Check(BuildRCStage3CoupledBankRootManifest(statement, shape, reordered,
                                                   m2, &why),
              "reordered-page manifest builds");
        RCStage3CoupledBankRootBindingResult r;
        const bool ok = VerifyRCStage3CoupledBankRootAlgBinding(
            m2, committed, manifest.bank_root, r, nullptr);
        Check(!ok && !r.binding_verified,
              "TAMPER reorder pages -> §4 binding rejects (" + r.note + ")");
    }

    // (b) tamper a single page byte.
    {
        auto tampered = pages;
        tampered[tampered.size() / 2] ^= 0x01;
        RCStage3CoupledBankRootManifest m2;
        Check(BuildRCStage3CoupledBankRootManifest(statement, shape, tampered, m2,
                                                   &why),
              "single-byte-tampered manifest builds");
        RCStage3CoupledBankRootBindingResult r;
        const bool ok = VerifyRCStage3CoupledBankRootAlgBinding(
            m2, committed, manifest.bank_root, r, nullptr);
        Check(!ok && !r.binding_verified,
              "TAMPER page byte -> §4 binding rejects (" + r.note + ")");
    }

    // (c) substitute the stream_column_root in the committed binding.
    {
        auto bad = committed;
        bad.binding.stream_column_root.begin()[0] ^= 0x01;
        RCStage3CoupledBankRootBindingResult r;
        const bool ok = VerifyRCStage3CoupledBankRootAlgBinding(
            manifest, bad, manifest.bank_root, r, nullptr);
        Check(!ok && !r.binding_verified,
              "TAMPER substitute stream root -> rejects (" + r.note + ")");
    }

    // (d) wrong instance_count in the committed binding.
    {
        auto bad = committed;
        bad.binding.instance_count += 1;
        RCStage3CoupledBankRootBindingResult r;
        const bool ok = VerifyRCStage3CoupledBankRootAlgBinding(
            manifest, bad, manifest.bank_root, r, nullptr);
        Check(!ok && (!r.instance_count_ok || !r.binding_verified),
              "TAMPER wrong instance_count -> rejects (" + r.note + ")");
    }

    // (e) wrong committed bank_root pin.
    {
        RCStage3CoupledBankRootBindingResult r;
        const bool ok = VerifyRCStage3CoupledBankRootAlgBinding(
            manifest, committed, H(0xBE), r, nullptr);
        Check(!ok && !r.bank_root_pinned,
              "TAMPER wrong bank_root pin -> rejects (" + r.note + ")");
    }
}

// ---------------------------------------------------------------------------
// Binding #2: EpisodeBuilderSeedChain (§4 SHA256d per-round seed clone)
// ---------------------------------------------------------------------------
static bool BuildSeedChainFixture(RCStage3SuccinctProof& statement,
                                  RCEpisodeParams& params,
                                  RCStage3EpisodeBuilderSeedChainProduct& product,
                                  std::string* why)
{
    params = MakeToyRCEpisodeParams();
    params.rounds = 2;
    std::vector<uint256> roots{H(0x61), H(0x62)};
    ha::EpisodeDigestManifest digest;
    if (!ha::BuildEpisodeDigestManifest(roots.size(), roots, digest, why)) {
        return false;
    }
    statement = {};
    statement.statement = RCStage3StatementKind::Episode;
    statement.public_inputs.height = 17;
    statement.public_inputs.episode_profile = 2;
    statement.public_inputs.transcript_version = ENC_RC_V4;
    statement.public_inputs.header_commitment = H(0x11);
    statement.public_inputs.params_commitment = H(0x22);
    statement.public_inputs.sigma = H(0x33);
    statement.public_inputs.episode_digest = digest.direct.digest;
    return ProveRCStage3EpisodeBuilderSeedChainProduct(statement, params, digest,
                                                       product, why);
}

static void TestSeedChain()
{
    std::printf("\n=== Binding #2 EpisodeBuilderSeedChain (§4 per-round seed clone) ===\n");
    RCStage3SuccinctProof statement;
    RCEpisodeParams params;
    RCStage3EpisodeBuilderSeedChainProduct product;
    std::string why;
    if (!BuildSeedChainFixture(statement, params, product, &why)) {
        Check(false, "BuildSeedChainFixture (ProveRCStage3EpisodeBuilderSeedChainProduct): " + why);
        return;
    }
    // Product itself must verify through the real engine (honest fixture).
    Check(VerifyRCStage3EpisodeBuilderSeedChainProduct(statement, params, product, &why),
          "seed-chain product verifies through the real engine");

    RCStage3SeedChainAlgBinding committed;
    if (!ComputeRCStage3SeedChainAlgBinding(product, committed, &why)) {
        Check(false, "ComputeRCStage3SeedChainAlgBinding: " + why);
        return;
    }
    std::printf("[honest] rounds=%llu stream_root=%s\n",
                (unsigned long long)committed.round_count,
                committed.binding.stream_column_root.ToString().substr(0, 12).c_str());

    // Honest accept.
    {
        RCStage3SeedChainBindingResult r;
        const bool ok =
            VerifyRCStage3SeedChainAlgBinding(statement, product, committed, r, &why);
        Check(ok && r.binding_complete,
              "honest seed-chain binding accepts (§4 per-round fold + chain edges)");
        Check(r.chain_edges_ok && r.round_index_ordered,
              "chain edges hold (σ -> round0, round_root[r-1] -> round r)");
        const auto pin = RCStage3SeedChainWireSemanticPin(r);
        Check(pin.semantic_relation_complete &&
                  pin.stream_column_root == committed.binding.stream_column_root,
              "semantic pin exposes complete=true + stream_column_root");
    }

    // (a) break a chain edge: round 1 source no longer == round_root[0].
    {
        auto p = product;
        p.steps[1].source = H(0xEE);
        RCStage3SeedChainBindingResult r;
        const bool ok =
            VerifyRCStage3SeedChainAlgBinding(statement, p, committed, r, nullptr);
        // Source change also changes the SHA preimage -> stream mismatch; either
        // the chain edge OR the §4 fold fails closed.
        Check(!ok && (!r.chain_edges_ok || !r.binding_verified),
              "TAMPER break chain edge -> rejects (" + r.note + ")");
    }

    // (b) reorder rounds: swap the two steps -> round_index/leaf order broken.
    {
        auto p = product;
        std::swap(p.steps[0], p.steps[1]);
        RCStage3SeedChainBindingResult r;
        const bool ok =
            VerifyRCStage3SeedChainAlgBinding(statement, p, committed, r, nullptr);
        Check(!ok && (!r.round_index_ordered || !r.binding_verified ||
                      !r.chain_edges_ok),
              "TAMPER reorder rounds -> rejects (" + r.note + ")");
    }

    // (c) tamper a seed: mutate a committed stream root -> §4 fold rejects.
    {
        auto bad = committed;
        bad.binding.stream_column_root.begin()[0] ^= 0x01;
        RCStage3SeedChainBindingResult r;
        const bool ok =
            VerifyRCStage3SeedChainAlgBinding(statement, product, bad, r, nullptr);
        Check(!ok && !r.binding_verified,
              "TAMPER substitute seed stream root -> rejects (" + r.note + ")");
    }

    // (d) wrong σ anchor in the statement -> round-0 chain edge fails.
    {
        auto s2 = statement;
        s2.public_inputs.sigma = H(0xAB);
        RCStage3SeedChainBindingResult r;
        const bool ok =
            VerifyRCStage3SeedChainAlgBinding(s2, product, committed, r, nullptr);
        Check(!ok && !r.chain_edges_ok,
              "TAMPER wrong σ anchor -> chain edge rejects (" + r.note + ")");
    }
}

// ---------------------------------------------------------------------------
// Binding #11: CoupledGemmSignedRange (endpoint-9 value-roots ordered fold)
// ---------------------------------------------------------------------------
namespace aq = air_quotient;

// Build one REAL signed-range shard entry: real 69 columns via the executable
// column builder, real RANGE_VALUE column root via AirCommittedValuesRoot, and
// y_interval_root == RANGE_VALUE root (root identity).  `flip_row` optionally
// perturbs a single signed value so the RANGE_VALUE root differs.
static bool BuildRealShardEntry(const RCStage3CoupledSignedRangeManifest& manifest,
                                uint32_t shard_index, int64_t flip_row,
                                RCStage3SignedRangeShardEntry& entry,
                                std::string* why)
{
    entry = {};
    RCStage3SignedRangePin pin;
    if (shard_index == 0) {
        if (!MakeRCStage3CoupledSignedRangePin(manifest, 0, pin, why)) return false;
    } else {
        // Second shard: a real pin at the next contiguous interval (the
        // single-shard ToyShape cannot itself span 2 shards; this is a genuine
        // ledger-level order-binding instance over two real range value roots).
        if (!MakeRCStage3CoupledSignedRangePin(manifest, 0, pin, why)) return false;
        pin.shard_index = 1;
        pin.shard_count = 2;
        pin.cell_begin = pin.logical_rows;
    }
    std::vector<int64_t> values(pin.logical_rows);
    for (uint32_t row = 0; row < values.size(); ++row) {
        int64_t v = static_cast<int64_t>((row + shard_index) % (pin.max_abs + 1));
        values[row] = (row % 2 == 0) ? v : -v;
    }
    if (flip_row >= 0 && flip_row < static_cast<int64_t>(values.size())) {
        values[flip_row] = -values[flip_row] + 1;
    }
    std::vector<std::vector<gf::Fp3>> columns;
    if (!BuildRCStage3SignedRangeColumns(pin, values, columns, why)) return false;
    pin.column_roots[kRCStage3RangeValue].root =
        aq::AirCommittedValuesRoot<gf::Fp3>(columns[kRCStage3RangeValue], pin.n_rows);
    entry.pin = pin;
    entry.y_interval_root = pin.column_roots[kRCStage3RangeValue].root;
    return true;
}

static void TestSignedRange()
{
    std::printf("\n=== Binding #11 CoupledGemmSignedRange (endpoint-9 value-roots fold) ===\n");
    const auto statement = CoupledStatement();
    const auto shape = ToyShape();
    RCStage3CoupledSignedRangeManifest manifest;
    std::string why;
    if (!BuildRCStage3CoupledSignedRangeManifest(statement, shape, manifest, &why)) {
        Check(false, "BuildRCStage3CoupledSignedRangeManifest: " + why);
        return;
    }

    RCStage3SignedRangeShardEntry s0;
    if (!BuildRealShardEntry(manifest, 0, -1, s0, &why)) {
        Check(false, "BuildRealShardEntry(0): " + why);
        return;
    }
    std::printf("[honest] range_value_root=%s (real 69-col signed-range shard, "
                "logical_rows=%u n_rows=%u max_abs=%llu)\n",
                s0.pin.column_roots[kRCStage3RangeValue].root.ToString().substr(0, 12).c_str(),
                s0.pin.logical_rows, s0.pin.n_rows, (unsigned long long)s0.pin.max_abs);

    // The engine's own value-roots commitment executes over this real shard
    // (proves the fixture drives the real value-roots engine).
    {
        RCStage3CoupledSignedRangeExecution exec;
        exec.manifest = manifest;
        RCStage3CoupledSignedRangeShardProof shard;
        shard.pin = s0.pin;
        exec.shards.push_back(shard);
        const uint256 engine_commit =
            CommitRCStage3CoupledSignedRangeValueRoots(manifest, exec.shards);
        Check(!engine_commit.IsNull(),
              "engine CommitRCStage3CoupledSignedRangeValueRoots executes over the real shard");
    }

    // Single real shard: honest accept.
    std::vector<RCStage3SignedRangeShardEntry> one{s0};
    RCStage3SignedRangeAlgBinding committed1;
    if (!ComputeRCStage3SignedRangeAlgBinding(one, committed1, &why)) {
        Check(false, "ComputeRCStage3SignedRangeAlgBinding(1): " + why);
        return;
    }
    {
        RCStage3SignedRangeBindingResult r;
        const bool ok = VerifyRCStage3SignedRangeAlgBinding(one, committed1, r, &why);
        Check(ok && r.binding_complete,
              "honest single-shard binding accepts (value-roots fold + Y identity)");
        Check(r.y_interval_equal,
              "RANGE_VALUE root == CoupledGemmOutputY interval root");
        const auto pin = RCStage3SignedRangeWireSemanticPin(r);
        Check(pin.semantic_relation_complete &&
                  pin.value_roots_commitment == committed1.value_roots_commitment,
              "semantic pin exposes complete=true + value_roots_commitment");
    }

    // Two real shards: honest accept + order-binding.
    RCStage3SignedRangeShardEntry s1;
    if (!BuildRealShardEntry(manifest, 1, -1, s1, &why)) {
        Check(false, "BuildRealShardEntry(1): " + why);
        return;
    }
    std::vector<RCStage3SignedRangeShardEntry> two{s0, s1};
    RCStage3SignedRangeAlgBinding committed2;
    Check(ComputeRCStage3SignedRangeAlgBinding(two, committed2, &why),
          "two-real-shard ledger fold builds");
    {
        RCStage3SignedRangeBindingResult r;
        const bool ok = VerifyRCStage3SignedRangeAlgBinding(two, committed2, r, &why);
        Check(ok && r.binding_complete, "honest two-shard binding accepts");
    }

    // (a) reorder shards -> ordered fold changes -> reject.
    {
        std::vector<RCStage3SignedRangeShardEntry> swapped{s1, s0};
        RCStage3SignedRangeBindingResult r;
        const bool ok = VerifyRCStage3SignedRangeAlgBinding(swapped, committed2, r, nullptr);
        Check(!ok && (!r.shards_ordered || !r.value_roots_pinned),
              "TAMPER reorder shards -> rejects (" + r.note + ")");
    }

    // (b) wrong range value -> RANGE_VALUE root changes -> reject.
    {
        RCStage3SignedRangeShardEntry bad;
        Check(BuildRealShardEntry(manifest, 0, 100, bad, &why),
              "tampered-value shard builds");
        // Keep the ORIGINAL Y interval root so both the fold and the Y identity break.
        bad.y_interval_root = s0.y_interval_root;
        std::vector<RCStage3SignedRangeShardEntry> tampered{bad};
        RCStage3SignedRangeBindingResult r;
        const bool ok = VerifyRCStage3SignedRangeAlgBinding(tampered, committed1, r, nullptr);
        Check(!ok && (!r.value_roots_pinned || !r.y_interval_equal),
              "TAMPER wrong range value -> rejects (" + r.note + ")");
    }

    // (c) mismatched CoupledGemmOutputY interval root -> equality reject.
    {
        auto bad = s0;
        bad.y_interval_root = H(0x5A);
        std::vector<RCStage3SignedRangeShardEntry> mism{bad};
        RCStage3SignedRangeAlgBinding cb;
        Check(ComputeRCStage3SignedRangeAlgBinding(mism, cb, &why),
              "mismatched-Y ledger fold builds");
        RCStage3SignedRangeBindingResult r;
        const bool ok = VerifyRCStage3SignedRangeAlgBinding(mism, cb, r, nullptr);
        Check(!ok && !r.y_interval_equal,
              "TAMPER mismatched Y interval root -> rejects (" + r.note + ")");
    }
}

// ---------------------------------------------------------------------------
// Bindings #7-9: EpisodeWiring{Transpose,Residual,RoundOrder} (ledger binding)
// ---------------------------------------------------------------------------
static RCStage3SuccinctProof WiringStatement()
{
    RCStage3SuccinctProof out;
    out.statement = RCStage3StatementKind::Episode;
    out.public_inputs.height = 183;
    out.public_inputs.n_bits = 0x207fffffU;
    out.public_inputs.episode_profile = 2;
    out.public_inputs.transcript_version = ENC_RC_V4;
    out.public_inputs.header_commitment = H(0x11);
    out.public_inputs.params_commitment = H(0x22);
    out.public_inputs.sigma = H(0x33);
    out.public_inputs.target = H(0xff);
    out.public_inputs.episode_digest = H(0x44);
    out.public_inputs.final_digest = H(0x44);
    return out;
}

static RCEpisodeParams WiringTinyParams()
{
    RCEpisodeParams out;
    out.rounds = 1;
    out.d_head = 32;
    out.n_q = 32;
    out.n_ctx = 32;
    out.L_lyr = 1;
    out.d_model = 32;
    out.d_ff = 32;
    out.b_seq = 32;
    out.T_leaf = 64;
    return out;
}

static uint256 WiringVectorRoot(const uint256& statement_commitment,
                                uint32_t first_column, uint32_t n_chunks,
                                uint64_t count, std::string* why)
{
    const auto root = ComputeRCStage3EpisodeWiringVectorRootFromValues(
        statement_commitment, first_column, n_chunks,
        std::vector<gf::Fp3>(count, gf::Fp3::Zero()), why);
    return root.has_value() ? *root : uint256{};
}

struct WiringFixture {
    RCStage3SuccinctProof statement{WiringStatement()};
    RCStage3GemmExtractManifest manifest;
    RCStage3EpisodeGemmProduct gemm;
    RCStage3EpisodeExtractProduct extract;
    RCStage3EpisodeWiringProduct wiring;
};

static bool BuildWiringFixture(WiringFixture& f, std::string* why)
{
    const auto params = WiringTinyParams();
    const uint256 sc = RCStage3EpisodeStatementCommitment(f.statement);
    const auto layout = RCGkrTraceLayout(params);
    std::vector<RCStage3GemmExtractLayerBindings> bindings(layout.layers.size());
    for (uint32_t i = 0; i < bindings.size(); ++i) {
        auto& b = bindings[i];
        b.extract_prf = H(0x10 + i);
        b.operand_a_root = H(0x20 + i);
        b.operand_b_root = H(0x30 + i);
        b.gemm_y_root = H(0x40 + i);
        b.extract_input_root = H(0x50 + i);
        b.extract_output_root = H(0x60 + i);
        b.gemm_proof_root = H(0x70 + i);
        b.extract_recursive_root = H(0x80 + i);
        b.scale_schedule_root = H(0x90 + i);
        b.ctl_terminal_root = H(0xa0 + i);
    }
    const auto built = BuildRCStage3GemmExtractManifest(params, sc, bindings, why);
    if (!built.has_value()) return false;
    f.manifest = *built;

    f.gemm.statement_commitment = sc;
    f.gemm.layers.resize(f.manifest.layers.size());
    for (uint32_t i = 0; i < f.manifest.layers.size(); ++i) {
        auto& spec = f.manifest.layers[i];
        auto& layer = f.gemm.layers[i];
        layer.layer_ordinal = i;
        layer.operand_a.assign(static_cast<uint64_t>(spec.m) * spec.k, 0);
        layer.operand_b.assign(static_cast<uint64_t>(spec.k) * spec.n, 0);
        layer.gemm_y.assign(spec.gemm_cell_count, 0);
        if (spec.residual_first_column >= 0) {
            layer.residual.assign(spec.gemm_cell_count, 0);
        }
        spec.bindings.operand_a_root = WiringVectorRoot(
            sc, spec.a.first_column, spec.a.n_chunks, layer.operand_a.size(), why);
        spec.bindings.operand_b_root = WiringVectorRoot(
            sc, spec.b.first_column, spec.b.n_chunks, layer.operand_b.size(), why);
        spec.bindings.gemm_y_root = WiringVectorRoot(
            sc, spec.y_first_column, spec.y_chunks, layer.gemm_y.size(), why);
    }
    f.gemm.manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(f.manifest);
    f.gemm.collection_commitment = H(0xc1);

    f.extract.statement_commitment = sc;
    f.extract.manifest_commitment = f.gemm.manifest_commitment;
    f.extract.expected_tiles = f.manifest.total_extract_tiles;
    const std::vector<gf::Fp3> zero_output(kRCMxBlockLen, gf::Fp3::Zero());
    const uint256 zero_output_root =
        aq::AirCommittedValuesRoot<gf::Fp3>(zero_output, kRCMxBlockLen);
    for (uint32_t lo = 0; lo < f.manifest.layers.size(); ++lo) {
        const auto& spec = f.manifest.layers[lo];
        for (uint64_t local = 0; local < spec.extract_tile_count; ++local) {
            RCStage3EpisodeExtractTileProduct tile;
            tile.global_tile = f.extract.tiles.size();
            tile.layer_ordinal = lo;
            tile.layer_tile_index = local;
            tile.sampler_pin.logical_rows = kRCMxBlockLen;
            tile.sampler_pin.n_rows = kRCMxBlockLen;
            tile.sampler_pin.n_coeffs = kRCMxBlockLen;
            tile.sampler_pin.column_roots.resize(aq::kRcSamplerNumCols);
            for (uint32_t col = 0; col < aq::kRcSamplerNumCols; ++col) {
                tile.sampler_pin.column_roots[col] = {
                    col, H(static_cast<uint8_t>(1 + ((col + lo) % 250)))};
            }
            tile.sampler_pin.column_roots[aq::kColOut].root = zero_output_root;
            f.extract.tiles.push_back(std::move(tile));
        }
    }
    f.extract.collection_commitment = H(0xc2);

    return BuildRCStage3EpisodeWiringProduct(f.statement, f.manifest, f.gemm,
                                             f.extract, f.wiring, why);
}

static void TestWiring()
{
    std::printf("\n=== Bindings #7-9 EpisodeWiring{Transpose,Residual,RoundOrder} (ledger binding) ===\n");
    WiringFixture f;
    std::string why;
    if (!BuildWiringFixture(f, &why)) {
        Check(false, "BuildWiringFixture (BuildRCStage3EpisodeWiringProduct): " + why);
        return;
    }
    // The product's own local AIRs execute (honest fixture through the engine).
    Check(VerifyRCStage3EpisodeWiringLocalProduct(f.statement, f.manifest, f.gemm,
                                                  f.extract, f.wiring, &why),
          "wiring product local AIRs execute through the real engine");

    const auto committed = ComputeRCStage3WiringLedgerRoots(f.wiring);
    std::printf("[honest] transpose_edges=%zu residual_edges=%zu round_order_edges=%zu\n",
                f.wiring.transpose_edges.size(), f.wiring.residual_edges.size(),
                f.wiring.round_order_edges.size());

    // Honest accept.
    {
        RCStage3WiringBindingResult r;
        const bool ok = VerifyRCStage3WiringLedgerBinding(f.manifest, f.wiring,
                                                          committed, r, &why);
        Check(ok && r.binding_complete,
              "honest wiring ledger accepts (3 families, leaf-for-leaf + fold)");
        const auto pin = RCStage3WiringWireSemanticPin(r);
        Check(pin.transpose_complete && pin.residual_complete &&
                  pin.round_order_complete,
              "semantic pins expose all 3 endpoints complete");
    }

    // --- Transpose (endpoint 16) tampers ---
    {
        auto p = f.wiring;
        p.transpose_edges[0].transposed_vector_root = H(0xE2);
        RCStage3WiringBindingResult r;
        const bool ok =
            VerifyRCStage3WiringLedgerBinding(f.manifest, p, committed, r, nullptr);
        Check(!ok && !r.transpose_fold_matches,
              "TAMPER transpose: substitute output root -> rejects (" + r.note + ")");
    }
    if (f.wiring.transpose_edges.size() >= 2) {
        auto p = f.wiring;
        std::swap(p.transpose_edges[0], p.transpose_edges[1]);
        RCStage3WiringBindingResult r;
        const bool ok =
            VerifyRCStage3WiringLedgerBinding(f.manifest, p, committed, r, nullptr);
        Check(!ok, "TAMPER transpose: reorder edges -> rejects (" + r.note + ")");
    } else {
        auto p = f.wiring;
        p.transpose_edges.pop_back();
        RCStage3WiringBindingResult r;
        const bool ok =
            VerifyRCStage3WiringLedgerBinding(f.manifest, p, committed, r, nullptr);
        Check(!ok && !r.transpose_schedule_matches,
              "TAMPER transpose: drop edge -> rejects (" + r.note + ")");
    }

    // --- Residual (endpoint 17) tampers ---
    {
        auto p = f.wiring;
        p.residual_edges.pop_back();
        RCStage3WiringBindingResult r;
        const bool ok =
            VerifyRCStage3WiringLedgerBinding(f.manifest, p, committed, r, nullptr);
        Check(!ok && !r.residual_schedule_matches,
              "TAMPER residual: drop edge -> rejects (" + r.note + ")");
    }
    {
        auto p = f.wiring;
        p.residual_edges[0].schedule.registered_y_root = H(0xE5);
        RCStage3WiringBindingResult r;
        const bool ok =
            VerifyRCStage3WiringLedgerBinding(f.manifest, p, committed, r, nullptr);
        Check(!ok && !r.residual_schedule_matches,
              "TAMPER residual: substitute registered_y_root -> rejects (" + r.note + ")");
    }

    // --- Round-order (endpoint 18) tampers ---
    {
        auto p = f.wiring;
        p.round_order_edges.pop_back();
        RCStage3WiringBindingResult r;
        const bool ok =
            VerifyRCStage3WiringLedgerBinding(f.manifest, p, committed, r, nullptr);
        Check(!ok && !r.round_order_schedule_matches,
              "TAMPER round_order: drop edge -> rejects (" + r.note + ")");
    }
    {
        auto p = f.wiring;
        p.round_order_edges[0].pin.pin_commitment = H(0xE7);
        RCStage3WiringBindingResult r;
        const bool ok =
            VerifyRCStage3WiringLedgerBinding(f.manifest, p, committed, r, nullptr);
        Check(!ok && !r.round_order_fold_matches,
              "TAMPER round_order: substitute pin_commitment -> rejects (" + r.note + ")");
    }
}

int main(int argc, char** argv)
{
    std::string only = (argc > 1) ? argv[1] : "";
    auto run = [&](const std::string& name) {
        return only.empty() || only == name;
    };
    std::printf("PR-89 remaining endpoint bindings — isolated fixture/tamper suite\n");
    if (run("bank")) TestBankRoot();
    if (run("seed")) TestSeedChain();
    if (run("range")) TestSignedRange();
    if (run("wiring")) TestWiring();
    std::printf("\n==== RESULT: %d passed, %d failed ====\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
