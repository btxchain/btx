// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// DATA ONLY. This translation unit exists to hold the committed production
// golden manifest literal and nothing else -- no logic, no helpers, no
// conditional compilation. That restriction is load-bearing, not stylistic.
//
// The build-relevant source_tree_fingerprint each entry carries is
// sha256(git ls-tree -r --full-tree <rev> -- CMakeLists.txt cmake src). While
// the manifest lived in matmul_v4_rc_production_canary.cpp, that hash covered
// the very bytes being sealed: writing a fingerprint into the file changed the
// file, which changed the fingerprint, so a manifest could never describe the
// tree it shipped in. Every seal in this branch's history was therefore
// off-by-one, citing its own parent commit, and re-running the providers could
// not fix it -- it only moved the target.
//
// The fingerprint computation now excludes exactly this path (see
// contrib/matmul-v4/multi-gpu-golden-corpus.sh and
// contrib/matmul-v4/verify-evidence-provenance.py). The exclusion is sound only
// while this file contains no code that can affect a transcript, a digest, or a
// qualification decision. Do not add any. Anything with behaviour belongs in
// matmul_v4_rc_production_canary.cpp, where the freeze still binds it.

#include <matmul/matmul_v4_rc_production_canary.h>

#include <vector>

namespace matmul::v4::rc {

const std::vector<RCProductionGoldenManifestEntry>&
CommittedRCProductionGoldenManifest()
{
    // POPULATED for the Epoch-A activation at mainnet height 182'600.
    //
    // Precondition satisfied: contrib/matmul-v4/multi-gpu-golden-corpus.sh
    // reported complete_multi_gpu_match=true for CUDA and Metal reproduced from
    // ONE code freeze -- the same source_revision AND the same build-relevant
    // source_tree_fingerprint, which is what RCProductionGoldenManifestCohortValid
    // requires and what every earlier corpus in this branch failed. Digest
    // equality alone was never the gate.
    //
    // This is also the first seal in this branch that describes its OWN tree
    // rather than its parent: the fingerprint below was recomputed by both rigs
    // from clean checkouts of this revision and is unchanged by the act of
    // writing it here, because this file is excluded from it. See the header
    // comment for why that exclusion is what makes a self-consistent seal
    // possible at all.
    //
    // Evidence: doc/evidence/multi-gpu-profile1-goldens-cuda-metal-2026-08-03-review-closure.
    // Both providers independently reported 1'088 device calls and
    // 1'129'198'441'725'952 device MACs with zero CPU GEMM calls, zero CPU MACs
    // and zero fallbacks, and ExtractMX self-qualification PASS. All eight
    // digests and all eight frozen header byte strings are byte-identical
    // across providers, verified independently of the comparator script.
    //
    // The two entries deliberately share header_nonce, expected_digest, epoch,
    // source_revision and source_tree_fingerprint, and differ only in
    // provider_class and harness_sha256: that is exactly the cohort shape the
    // validator enforces (one cuda entry, one metal entry, distinct provider
    // classes, identical workload and provenance).
    //
    // ANY_ACTIVATION_HEIGHT is correct here: the frozen canary header and the
    // Profile-1 transcript do not depend on the activation height, and runtime
    // capabilities still bind the real height separately.
    static const std::vector<RCProductionGoldenManifestEntry> manifest{
        RCProductionGoldenManifestEntry{
            .id = "epoch-a-profile1-cuda-sm120-nonce1",
            .provider_class = {.provider_family = "cuda",
                               .device_architecture = "sm_120"},
            .epoch = {.activation_height =
                          RCProductionEpochIdentity::ANY_ACTIVATION_HEIGHT,
                      .profile = 1,
                      .transcript_version = kRCTranscriptVersion,
                      .matmul_dimension = 4096,
                      .params = DefaultConsensusRCEpisodeParams()},
            .header_nonce = 1,
            .expected_digest = uint256{
                "b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953"},
            .independently_reproduced = true,
            .public_provenance =
                "doc/evidence/multi-gpu-profile1-goldens-cuda-metal-2026-08-03-review-closure",
            .source_revision = "75a6571b209527966a1ff2910fda573a1b009ba4",
            .source_tree_fingerprint =
                "b4a47c3d7647f5ed4e2bf8639bb871bded18c21809b95ebc4a232d22232501c1",
            .harness_sha256 =
                "b48526ad9756e2361b94db8dfd5654f9135c0f2f3cba58b5a95e96a144e3fef0",
        },
        RCProductionGoldenManifestEntry{
            .id = "epoch-a-profile1-metal-m4-nonce1",
            .provider_class = {.provider_family = "metal",
                               .device_architecture = "m4_class"},
            .epoch = {.activation_height =
                          RCProductionEpochIdentity::ANY_ACTIVATION_HEIGHT,
                      .profile = 1,
                      .transcript_version = kRCTranscriptVersion,
                      .matmul_dimension = 4096,
                      .params = DefaultConsensusRCEpisodeParams()},
            .header_nonce = 1,
            .expected_digest = uint256{
                "b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953"},
            .independently_reproduced = true,
            .public_provenance =
                "doc/evidence/multi-gpu-profile1-goldens-cuda-metal-2026-08-03-review-closure",
            .source_revision = "75a6571b209527966a1ff2910fda573a1b009ba4",
            .source_tree_fingerprint =
                "b4a47c3d7647f5ed4e2bf8639bb871bded18c21809b95ebc4a232d22232501c1",
            .harness_sha256 =
                "407284a7ba46e2b90ed03572d7acfa472a0852aace9bc63a79a4a02850569ae8",
        },
    };
    return manifest;
}

} // namespace matmul::v4::rc
