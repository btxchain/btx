// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>
#include <pqkey.h>
#include <shielded/bridge.h>

#include <array>
#include <cassert>
#include <vector>

namespace {

shielded::BridgeBatchLeaf BuildLeaf(uint32_t index)
{
    shielded::BridgeBatchLeaf leaf;
    leaf.kind = shielded::BridgeBatchLeafKind::SHIELD_CREDIT;
    leaf.wallet_id = uint256{static_cast<unsigned char>((index % 250) + 1)};
    leaf.destination_id = uint256{static_cast<unsigned char>(((index + 1) % 250) + 1)};
    leaf.amount = (static_cast<CAmount>((index % 5) + 1)) * COIN;
    leaf.authorization_hash = uint256{static_cast<unsigned char>(((index + 2) % 250) + 1)};
    assert(leaf.IsValid());
    return leaf;
}

std::vector<shielded::BridgeBatchLeaf> BuildLeaves(size_t count)
{
    std::vector<shielded::BridgeBatchLeaf> leaves;
    leaves.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        leaves.push_back(BuildLeaf(i));
    }
    return leaves;
}

std::vector<shielded::BridgeKeySpec> BuildAttestors(size_t count, PQAlgorithm algo = PQAlgorithm::ML_DSA_44)
{
    std::vector<shielded::BridgeKeySpec> attestors;
    attestors.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        std::array<unsigned char, 32> seed_material{};
        seed_material.fill(static_cast<unsigned char>(0x10 + i));
        CPQKey key;
        assert(key.MakeDeterministicKey(algo, seed_material));
        attestors.push_back({algo, key.GetPubKey()});
    }
    return attestors;
}

shielded::BridgeProofDescriptor BuildProofDescriptor(unsigned char seed);
std::vector<shielded::BridgeProofDescriptor> BuildProofDescriptors(size_t count);

shielded::BridgeProofSystemProfile BuildProofSystemProfile(unsigned char seed)
{
    shielded::BridgeProofSystemProfile profile;
    profile.family_id = uint256{seed};
    profile.proof_type_id = uint256{static_cast<unsigned char>(seed + 1)};
    profile.claim_system_id = uint256{static_cast<unsigned char>(seed + 2)};
    assert(profile.IsValid());
    return profile;
}

shielded::BridgeBatchAuthorization BuildAuthorization(PQAlgorithm algo, unsigned char seed)
{
    std::array<unsigned char, 32> seed_material{};
    seed_material.fill(seed);

    CPQKey key;
    assert(key.MakeDeterministicKey(algo, seed_material));

    shielded::BridgeBatchAuthorization authorization;
    authorization.direction = shielded::BridgeDirection::BRIDGE_OUT;
    authorization.ids.bridge_id = uint256{static_cast<unsigned char>(seed + 10)};
    authorization.ids.operation_id = uint256{static_cast<unsigned char>(seed + 11)};
    authorization.kind = shielded::BridgeBatchLeafKind::TRANSPARENT_PAYOUT;
    authorization.wallet_id = uint256{static_cast<unsigned char>(seed + 1)};
    authorization.destination_id = uint256{static_cast<unsigned char>(seed + 2)};
    authorization.amount = 3 * COIN;
    authorization.authorization_nonce = uint256{static_cast<unsigned char>(seed + 3)};
    authorization.authorizer = {algo, key.GetPubKey()};

    const uint256 authorization_hash = shielded::ComputeBridgeBatchAuthorizationHash(authorization);
    assert(!authorization_hash.IsNull());
    assert(key.Sign(authorization_hash, authorization.signature));
    assert(authorization.IsValid());
    return authorization;
}

shielded::BridgeBatchStatement BuildStatement()
{
    const auto leaves = BuildLeaves(8);
    shielded::BridgeBatchStatement statement;
    statement.direction = shielded::BridgeDirection::BRIDGE_OUT;
    statement.ids.bridge_id = uint256{0x21};
    statement.ids.operation_id = uint256{0x22};
    statement.entry_count = leaves.size();
    statement.total_amount = 21 * COIN;
    statement.batch_root = shielded::ComputeBridgeBatchRoot(leaves);
    statement.domain_id = uint256{0x23};
    statement.source_epoch = 17;
    statement.data_root = uint256{0x24};
    assert(statement.IsValid());
    return statement;
}

shielded::BridgeBatchStatement BuildHybridStatement()
{
    auto statement = BuildStatement();
    const auto attestors = BuildAttestors(16);
    const auto verifier_set = shielded::BuildBridgeVerifierSetCommitment(attestors, 8);
    assert(verifier_set.has_value());
    const auto descriptors = BuildProofDescriptors(16);
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, 8);
    assert(proof_policy.has_value());
    statement.version = 4;
    statement.verifier_set = *verifier_set;
    statement.proof_policy = *proof_policy;
    assert(statement.IsValid());
    return statement;
}

shielded::BridgeProofClaim BuildProofClaim(const shielded::BridgeBatchStatement& statement,
                                           shielded::BridgeProofClaimKind kind)
{
    const auto claim = shielded::BuildBridgeProofClaimFromStatement(statement, kind);
    assert(claim.has_value());
    return *claim;
}

shielded::BridgeProofAdapter BuildProofAdapter(unsigned char seed,
                                               shielded::BridgeProofClaimKind kind)
{
    shielded::BridgeProofAdapter adapter;
    adapter.profile = BuildProofSystemProfile(seed);
    adapter.claim_kind = kind;
    assert(adapter.IsValid());
    return adapter;
}

shielded::BridgeProofArtifact BuildProofArtifact(const shielded::BridgeBatchStatement& statement,
                                                 unsigned char seed,
                                                 shielded::BridgeProofClaimKind kind)
{
    const auto adapter = BuildProofAdapter(seed, kind);
    const auto artifact = shielded::BuildBridgeProofArtifact(statement,
                                                             adapter,
                                                             uint256{static_cast<unsigned char>(seed + 3)},
                                                             uint256{static_cast<unsigned char>(seed + 4)},
                                                             uint256{static_cast<unsigned char>(seed + 5)},
                                                             4096,
                                                             96,
                                                             512);
    assert(artifact.has_value());
    return *artifact;
}

shielded::BridgeAggregateSettlement BuildAggregateSettlement()
{
    const auto statement = BuildStatement();
    shielded::BridgeAggregateSettlement settlement;
    settlement.statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    settlement.batched_user_count = 64;
    settlement.new_wallet_count = 24;
    settlement.input_count = 64;
    settlement.output_count = 64;
    settlement.base_non_witness_bytes = 900;
    settlement.base_witness_bytes = 2600;
    settlement.state_commitment_bytes = 192;
    settlement.proof_payload_bytes = 16384;
    settlement.data_availability_payload_bytes = 4096;
    settlement.control_plane_bytes = 320;
    settlement.auxiliary_offchain_bytes = 1024;
    settlement.proof_payload_location = shielded::BridgeAggregatePayloadLocation::INLINE_WITNESS;
    settlement.data_availability_location = shielded::BridgeAggregatePayloadLocation::L1_DATA_AVAILABILITY;
    assert(settlement.IsValid());
    return settlement;
}

shielded::BridgeDataArtifact BuildDataArtifact(const shielded::BridgeBatchStatement& statement,
                                               unsigned char seed,
                                               shielded::BridgeDataArtifactKind kind,
                                               uint32_t payload_size_bytes = 2048,
                                               uint32_t auxiliary_data_size_bytes = 128)
{
    const auto artifact = shielded::BuildBridgeDataArtifact(statement,
                                                            kind,
                                                            uint256{static_cast<unsigned char>(seed + 6)},
                                                            uint256{static_cast<unsigned char>(seed + 7)},
                                                            payload_size_bytes,
                                                            auxiliary_data_size_bytes);
    assert(artifact.has_value());
    return *artifact;
}

shielded::BridgeAggregateArtifactBundle BuildArtifactBackedAggregateBundle()
{
    const auto statement = BuildStatement();
    const auto proof = shielded::BuildBridgeProofArtifact(statement,
                                                          BuildProofAdapter(0xe1, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA),
                                                          uint256{0xe2},
                                                          uint256{0xe3},
                                                          uint256{0xe4},
                                                          393216,
                                                          96,
                                                          2048);
    assert(proof.has_value());
    const std::array<shielded::BridgeProofArtifact, 1> proof_artifacts{{*proof}};
    const std::array<shielded::BridgeDataArtifact, 2> data_artifacts{{
        BuildDataArtifact(statement, 0xe5, shielded::BridgeDataArtifactKind::STATE_DIFF, 6080, 512),
        BuildDataArtifact(statement, 0xe6, shielded::BridgeDataArtifactKind::SNAPSHOT_APPENDIX, 2048, 256),
    }};
    const auto bundle = shielded::BuildBridgeAggregateArtifactBundle(
        statement,
        Span<const shielded::BridgeProofArtifact>{proof_artifacts.data(), proof_artifacts.size()},
        Span<const shielded::BridgeDataArtifact>{data_artifacts.data(), data_artifacts.size()});
    assert(bundle.has_value());
    return *bundle;
}

shielded::BridgeProofCompressionTarget BuildProofCompressionTarget()
{
    const auto statement = BuildStatement();
    const auto bundle = BuildArtifactBackedAggregateBundle();
    auto settlement = BuildAggregateSettlement();
    settlement.statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    settlement.proof_payload_bytes = bundle.proof_payload_bytes;
    settlement.data_availability_payload_bytes = bundle.data_availability_payload_bytes;
    settlement.auxiliary_offchain_bytes = bundle.proof_auxiliary_bytes + bundle.data_auxiliary_bytes;
    settlement.data_availability_location = shielded::BridgeAggregatePayloadLocation::OFFCHAIN;
    assert(settlement.IsValid());
    const auto target = shielded::BuildBridgeProofCompressionTarget(settlement,
                                                                    bundle,
                                                                    24'000'000,
                                                                    24'000'000,
                                                                    std::nullopt,
                                                                    12'288);
    assert(target.has_value());
    return *target;
}

shielded::BridgeShieldedStateProfile BuildShieldedStateProfile(uint64_t wallet_materialization_bytes = 0)
{
    shielded::BridgeShieldedStateProfile profile;
    profile.wallet_materialization_bytes = wallet_materialization_bytes;
    assert(profile.IsValid());
    return profile;
}

shielded::BridgeShieldedStateRetentionPolicy BuildShieldedStateRetentionPolicy(uint32_t wallet_l1_materialization_bps = shielded::BridgeShieldedStateRetentionPolicy::PRODUCTION_WALLET_L1_MATERIALIZATION_BPS,
                                                                                bool retain_commitment_index = false,
                                                                                bool retain_nullifier_index = true,
                                                                                bool snapshot_include_commitments = false,
                                                                                bool snapshot_include_nullifiers = true,
                                                                                uint64_t snapshot_target_bytes = shielded::BridgeShieldedStateRetentionPolicy::WEEKLY_SNAPSHOT_TARGET_BYTES)
{
    shielded::BridgeShieldedStateRetentionPolicy policy;
    policy.wallet_l1_materialization_bps = wallet_l1_materialization_bps;
    policy.retain_commitment_index = retain_commitment_index;
    policy.retain_nullifier_index = retain_nullifier_index;
    policy.snapshot_include_commitments = snapshot_include_commitments;
    policy.snapshot_include_nullifiers = snapshot_include_nullifiers;
    policy.snapshot_target_bytes = snapshot_target_bytes;
    assert(policy.IsValid());
    return policy;
}

shielded::BridgeBatchReceipt BuildReceipt(const shielded::BridgeBatchStatement& statement, PQAlgorithm algo, unsigned char seed)
{
    std::array<unsigned char, 32> seed_material{};
    seed_material.fill(seed);

    CPQKey key;
    assert(key.MakeDeterministicKey(algo, seed_material));

    shielded::BridgeBatchReceipt receipt;
    receipt.statement = statement;
    receipt.attestor = {algo, key.GetPubKey()};
    const uint256 receipt_hash = shielded::ComputeBridgeBatchReceiptHash(receipt);
    assert(!receipt_hash.IsNull());
    assert(key.Sign(receipt_hash, receipt.signature));
    assert(receipt.IsValid());
    return receipt;
}

shielded::BridgeVerificationBundle BuildVerificationBundle()
{
    shielded::BridgeVerificationBundle bundle;
    bundle.signed_receipt_root = uint256{0xc1};
    bundle.proof_receipt_root = uint256{0xc2};
    assert(bundle.IsValid());
    return bundle;
}

shielded::BridgeProofReceipt BuildProofReceipt(const shielded::BridgeBatchStatement& statement, unsigned char seed)
{
    shielded::BridgeProofReceipt receipt;
    receipt.statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    assert(!receipt.statement_hash.IsNull());
    receipt.proof_system_id = uint256{seed};
    receipt.verifier_key_hash = uint256{static_cast<unsigned char>(seed + 1)};
    receipt.public_values_hash = uint256{static_cast<unsigned char>(seed + 2)};
    receipt.proof_commitment = uint256{static_cast<unsigned char>(seed + 3)};
    assert(receipt.IsValid());
    return receipt;
}

shielded::BridgeProverProfile BuildProverProfile(const shielded::BridgeBatchStatement& statement,
                                                 unsigned char seed_base,
                                                 uint64_t native_millis,
                                                 uint64_t cpu_millis,
                                                 uint64_t gpu_millis,
                                                 uint64_t network_millis)
{
    const auto artifact_a = BuildProofArtifact(statement, static_cast<unsigned char>(seed_base + 0), shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    const auto artifact_b = BuildProofArtifact(statement, static_cast<unsigned char>(seed_base + 1), shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    const auto artifact_c = BuildProofArtifact(statement, static_cast<unsigned char>(seed_base + 2), shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    const auto sample_a = shielded::BuildBridgeProverSample(artifact_a, native_millis / 3, cpu_millis / 3, gpu_millis / 3, network_millis / 3, 900000000);
    const auto sample_b = shielded::BuildBridgeProverSample(artifact_b, native_millis / 3, cpu_millis / 3, gpu_millis / 3, network_millis / 3, 1100000000);
    const auto sample_c = shielded::BuildBridgeProverSample(artifact_c,
                                                            native_millis - (native_millis / 3) - (native_millis / 3),
                                                            cpu_millis - (cpu_millis / 3) - (cpu_millis / 3),
                                                            gpu_millis - (gpu_millis / 3) - (gpu_millis / 3),
                                                            network_millis - (network_millis / 3) - (network_millis / 3),
                                                            700000000);
    assert(sample_a.has_value());
    assert(sample_b.has_value());
    assert(sample_c.has_value());
    const std::array<shielded::BridgeProverSample, 3> samples{*sample_a, *sample_b, *sample_c};
    const auto profile = shielded::BuildBridgeProverProfile(samples);
    assert(profile.has_value());
    return *profile;
}

shielded::BridgeProofDescriptor BuildProofDescriptor(unsigned char seed)
{
    shielded::BridgeProofDescriptor descriptor;
    descriptor.proof_system_id = uint256{seed};
    descriptor.verifier_key_hash = uint256{static_cast<unsigned char>(seed + 1)};
    assert(descriptor.IsValid());
    return descriptor;
}

std::vector<shielded::BridgeProofDescriptor> BuildProofDescriptors(size_t count)
{
    std::vector<shielded::BridgeProofDescriptor> descriptors;
    descriptors.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        descriptors.push_back(BuildProofDescriptor(static_cast<unsigned char>(0xb0 + i)));
    }
    return descriptors;
}

shielded::BridgeAttestationMessage BuildAttestation(bool anchored)
{
    shielded::BridgeAttestationMessage message;
    message.version = anchored ? 3 : 2;
    message.genesis_hash = uint256{0x31};
    message.direction = shielded::BridgeDirection::BRIDGE_OUT;
    message.ids.bridge_id = uint256{0x32};
    message.ids.operation_id = uint256{0x33};
    message.ctv_hash = uint256{0x34};
    message.refund_lock_height = 144;
    message.batch_entry_count = 8;
    message.batch_total_amount = 12 * COIN;
    message.batch_root = uint256{0x35};
    if (anchored) {
        message.external_anchor.domain_id = uint256{0x36};
        message.external_anchor.source_epoch = 77;
        message.external_anchor.data_root = uint256{0x37};
        message.external_anchor.verification_root = uint256{0x38};
    }
    assert(shielded::IsWellFormedBridgeAttestation(message));
    return message;
}

static void BridgeBatchRoot32(benchmark::Bench& bench)
{
    const auto leaves = BuildLeaves(32);
    bench.batch(leaves.size()).unit("leaf").minEpochIterations(200).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeBatchRoot(leaves));
    });
}

static void BridgeBatchRoot256(benchmark::Bench& bench)
{
    const auto leaves = BuildLeaves(256);
    bench.batch(leaves.size()).unit("leaf").minEpochIterations(50).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeBatchRoot(leaves));
    });
}

static void BridgeBatchAuthorizationVerifyMLDSA44(benchmark::Bench& bench)
{
    const auto authorization = BuildAuthorization(PQAlgorithm::ML_DSA_44, 0x44);
    bench.minEpochIterations(20).run([&] {
        assert(shielded::VerifyBridgeBatchAuthorization(authorization));
    });
}

static void BridgeBatchAuthorizationVerifySLHDSA128S(benchmark::Bench& bench)
{
    const auto authorization = BuildAuthorization(PQAlgorithm::SLH_DSA_128S, 0x55);
    bench.minEpochIterations(5).run([&] {
        assert(shielded::VerifyBridgeBatchAuthorization(authorization));
    });
}

static void BridgeVerifierSetRoot32MLDSA44(benchmark::Bench& bench)
{
    const auto attestors = BuildAttestors(32);
    bench.batch(attestors.size()).unit("attestor").minEpochIterations(100).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeVerifierSetRoot(attestors));
    });
}

static void BridgeVerifierSetProofVerify32MLDSA44(benchmark::Bench& bench)
{
    const auto attestors = BuildAttestors(32);
    const auto verifier_set = shielded::BuildBridgeVerifierSetCommitment(attestors, 16);
    assert(verifier_set.has_value());
    const auto proof = shielded::BuildBridgeVerifierSetProof(attestors, attestors[9]);
    assert(proof.has_value());
    bench.minEpochIterations(100).run([&] {
        assert(shielded::VerifyBridgeVerifierSetProof(*verifier_set, attestors[9], *proof));
    });
}

static void BridgeProofPolicyRoot32(benchmark::Bench& bench)
{
    const auto descriptors = BuildProofDescriptors(32);
    bench.batch(descriptors.size()).unit("descriptor").minEpochIterations(100).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeProofPolicyRoot(descriptors));
    });
}

static void BridgeProofPolicyProofVerify32(benchmark::Bench& bench)
{
    const auto descriptors = BuildProofDescriptors(32);
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, 16);
    assert(proof_policy.has_value());
    const auto proof = shielded::BuildBridgeProofPolicyProof(descriptors, descriptors[9]);
    assert(proof.has_value());
    bench.minEpochIterations(100).run([&] {
        assert(shielded::VerifyBridgeProofPolicyProof(*proof_policy, descriptors[9], *proof));
    });
}

static void BridgeProofSystemIdHash(benchmark::Bench& bench)
{
    const auto profile = BuildProofSystemProfile(0xc8);
    bench.minEpochIterations(200).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeProofSystemId(profile));
    });
}

static void BridgeProofClaimHashSettlementMetadata(benchmark::Bench& bench)
{
    const auto statement = BuildStatement();
    const auto claim = BuildProofClaim(statement, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    bench.minEpochIterations(200).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeProofClaimHash(claim));
    });
}

static void BridgeProofClaimHashDataRootTuple(benchmark::Bench& bench)
{
    const auto statement = BuildStatement();
    const auto claim = BuildProofClaim(statement, shielded::BridgeProofClaimKind::DATA_ROOT_TUPLE);
    bench.minEpochIterations(200).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeProofClaimHash(claim));
    });
}

static void BridgeProofAdapterIdHash(benchmark::Bench& bench)
{
    const auto adapter = BuildProofAdapter(0xca, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    bench.minEpochIterations(200).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeProofAdapterId(adapter));
    });
}

static void BridgeProofArtifactIdHash(benchmark::Bench& bench)
{
    const auto statement = BuildStatement();
    const auto artifact = BuildProofArtifact(statement, 0xcb, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    bench.minEpochIterations(200).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeProofArtifactId(artifact));
    });
}

static void BridgeAttestationHashV2(benchmark::Bench& bench)
{
    const auto attestation = BuildAttestation(/*anchored=*/false);
    bench.minEpochIterations(50).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeAttestationHash(attestation));
    });
}

static void BridgeAttestationHashV3(benchmark::Bench& bench)
{
    const auto attestation = BuildAttestation(/*anchored=*/true);
    bench.minEpochIterations(50).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeAttestationHash(attestation));
    });
}

static void BridgeExternalAnchorFromReceipts8MLDSA44(benchmark::Bench& bench)
{
    const auto statement = BuildStatement();
    std::vector<shielded::BridgeBatchReceipt> receipts;
    receipts.reserve(8);
    for (unsigned char i = 0; i < 8; ++i) {
        receipts.push_back(BuildReceipt(statement, PQAlgorithm::ML_DSA_44, static_cast<unsigned char>(0x70 + i)));
    }
    bench.batch(receipts.size()).unit("receipt").minEpochIterations(20).run([&] {
        const auto anchor = shielded::BuildBridgeExternalAnchorFromStatement(statement, receipts);
        assert(anchor.has_value());
        ankerl::nanobench::doNotOptimizeAway(*anchor);
    });
}

static void BridgeProofReceiptRoot8(benchmark::Bench& bench)
{
    const auto statement = BuildStatement();
    std::vector<shielded::BridgeProofReceipt> receipts;
    receipts.reserve(8);
    for (unsigned char i = 0; i < 8; ++i) {
        receipts.push_back(BuildProofReceipt(statement, static_cast<unsigned char>(0x90 + i)));
    }
    bench.batch(receipts.size()).unit("receipt").minEpochIterations(200).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeProofReceiptRoot(receipts));
    });
}

static void BridgeExternalAnchorFromProofReceipts8(benchmark::Bench& bench)
{
    const auto statement = BuildStatement();
    std::vector<shielded::BridgeProofReceipt> receipts;
    receipts.reserve(8);
    for (unsigned char i = 0; i < 8; ++i) {
        receipts.push_back(BuildProofReceipt(statement, static_cast<unsigned char>(0xa0 + i)));
    }
    bench.batch(receipts.size()).unit("receipt").minEpochIterations(200).run([&] {
        const auto anchor = shielded::BuildBridgeExternalAnchorFromProofReceipts(statement, receipts);
        assert(anchor.has_value());
        ankerl::nanobench::doNotOptimizeAway(*anchor);
    });
}

static void BridgeVerificationBundleHash(benchmark::Bench& bench)
{
    const auto bundle = BuildVerificationBundle();
    bench.minEpochIterations(200).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeVerificationBundleHash(bundle));
    });
}

static void BridgeExternalAnchorFromHybridWitness8(benchmark::Bench& bench)
{
    const auto statement = BuildHybridStatement();
    std::vector<shielded::BridgeBatchReceipt> receipts;
    receipts.reserve(8);
    for (unsigned char i = 0; i < 8; ++i) {
        receipts.push_back(BuildReceipt(statement, PQAlgorithm::ML_DSA_44, static_cast<unsigned char>(0xd0 + i)));
    }

    std::vector<shielded::BridgeProofReceipt> proof_receipts;
    proof_receipts.reserve(8);
    for (unsigned char i = 0; i < 8; ++i) {
        proof_receipts.push_back(BuildProofReceipt(statement, static_cast<unsigned char>(0xe0 + i)));
    }

    bench.batch(receipts.size() + proof_receipts.size()).unit("witness").minEpochIterations(20).run([&] {
        const auto anchor = shielded::BuildBridgeExternalAnchorFromHybridWitness(statement, receipts, proof_receipts);
        assert(anchor.has_value());
        ankerl::nanobench::doNotOptimizeAway(*anchor);
    });
}

static void BridgeProverBenchmarkBuild5Profiles(benchmark::Bench& bench)
{
    const auto statement = BuildStatement();
    const std::array<shielded::BridgeProverProfile, 5> profiles{
        BuildProverProfile(statement, 0xd0, 620, 175000, 11500, 3800),
        BuildProverProfile(statement, 0xd3, 640, 178000, 11800, 3900),
        BuildProverProfile(statement, 0xd6, 650, 180000, 12000, 4000),
        BuildProverProfile(statement, 0xd9, 660, 182000, 12300, 4200),
        BuildProverProfile(statement, 0xdc, 700, 190000, 13000, 4500),
    };
    bench.batch(profiles.size()).unit("profile").minEpochIterations(100).run([&] {
        const auto benchmark = shielded::BuildBridgeProverBenchmark(profiles);
        assert(benchmark.has_value());
        ankerl::nanobench::doNotOptimizeAway(*benchmark);
    });
}

static void BridgeAggregateSettlementIdHash(benchmark::Bench& bench)
{
    const auto settlement = BuildAggregateSettlement();
    bench.minEpochIterations(200).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeAggregateSettlementId(settlement));
    });
}

static void BridgeAggregateSettlementFootprint(benchmark::Bench& bench)
{
    const auto settlement = BuildAggregateSettlement();
    bench.minEpochIterations(200).run([&] {
        const auto footprint = shielded::BuildBridgeAggregateSettlementFootprint(settlement);
        assert(footprint.has_value());
        ankerl::nanobench::doNotOptimizeAway(*footprint);
    });
}

static void BridgeShieldedStateProfileIdHash(benchmark::Bench& bench)
{
    const auto profile = BuildShieldedStateProfile(/*wallet_materialization_bytes=*/96);
    bench.minEpochIterations(200).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeShieldedStateProfileId(profile));
    });
}

static void BridgeShieldedStateGrowthEstimate(benchmark::Bench& bench)
{
    const auto settlement = BuildAggregateSettlement();
    const auto footprint = shielded::BuildBridgeAggregateSettlementFootprint(settlement);
    assert(footprint.has_value());
    const auto capacity = shielded::EstimateBridgeCapacity(*footprint, 24000000, 24000000, 786432);
    assert(capacity.has_value());
    const auto profile = BuildShieldedStateProfile(/*wallet_materialization_bytes=*/96);
    bench.unit("estimate").minEpochIterations(200).run([&] {
        const auto estimate = shielded::EstimateBridgeShieldedStateGrowth(settlement, profile, *capacity, 90000);
        assert(estimate.has_value());
        ankerl::nanobench::doNotOptimizeAway(*estimate);
    });
}

static void BridgeShieldedStateRetentionPolicyIdHash(benchmark::Bench& bench)
{
    const auto policy = BuildShieldedStateRetentionPolicy(/*wallet_l1_materialization_bps=*/2500,
                                                          /*retain_commitment_index=*/false,
                                                          /*retain_nullifier_index=*/true,
                                                          /*snapshot_include_commitments=*/false,
                                                          /*snapshot_include_nullifiers=*/true);
    bench.minEpochIterations(200).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeShieldedStateRetentionPolicyId(policy));
    });
}

static void BridgeShieldedStateRetentionEstimate(benchmark::Bench& bench)
{
    const auto settlement = BuildAggregateSettlement();
    const auto footprint = shielded::BuildBridgeAggregateSettlementFootprint(settlement);
    assert(footprint.has_value());
    const auto capacity = shielded::EstimateBridgeCapacity(*footprint, 24000000, 24000000, 786432);
    assert(capacity.has_value());
    const auto profile = BuildShieldedStateProfile(/*wallet_materialization_bytes=*/96);
    const auto state = shielded::EstimateBridgeShieldedStateGrowth(settlement, profile, *capacity, 90000);
    assert(state.has_value());
    const auto policy = BuildShieldedStateRetentionPolicy(/*wallet_l1_materialization_bps=*/2500,
                                                          /*retain_commitment_index=*/false,
                                                          /*retain_nullifier_index=*/true,
                                                          /*snapshot_include_commitments=*/false,
                                                          /*snapshot_include_nullifiers=*/true);
    bench.unit("estimate").minEpochIterations(200).run([&] {
        const auto estimate = shielded::EstimateBridgeShieldedStateRetention(*state, policy);
        assert(estimate.has_value());
        ankerl::nanobench::doNotOptimizeAway(*estimate);
    });
}

static void BridgeDataArtifactIdHash(benchmark::Bench& bench)
{
    const auto statement = BuildStatement();
    const auto artifact = BuildDataArtifact(statement, 0xe0, shielded::BridgeDataArtifactKind::STATE_DIFF);
    bench.minEpochIterations(200).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeDataArtifactId(artifact));
    });
}

static void BridgeAggregateArtifactBundleBuild(benchmark::Bench& bench)
{
    const auto statement = BuildStatement();
    const std::array<shielded::BridgeProofArtifact, 2> proof_artifacts{{
        BuildProofArtifact(statement, 0xe1, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA),
        BuildProofArtifact(statement, 0xe2, shielded::BridgeProofClaimKind::DATA_ROOT_TUPLE),
    }};
    const std::array<shielded::BridgeDataArtifact, 2> data_artifacts{{
        BuildDataArtifact(statement, 0xe3, shielded::BridgeDataArtifactKind::STATE_DIFF, 2048, 128),
        BuildDataArtifact(statement, 0xe4, shielded::BridgeDataArtifactKind::SNAPSHOT_APPENDIX, 1024, 64),
    }};
    bench.unit("bundle").minEpochIterations(200).run([&] {
        const auto bundle = shielded::BuildBridgeAggregateArtifactBundle(
            statement,
            Span<const shielded::BridgeProofArtifact>{proof_artifacts.data(), proof_artifacts.size()},
            Span<const shielded::BridgeDataArtifact>{data_artifacts.data(), data_artifacts.size()});
        assert(bundle.has_value());
        ankerl::nanobench::doNotOptimizeAway(*bundle);
    });
}

static void BridgeProofCompressionTargetIdHash(benchmark::Bench& bench)
{
    const auto target = BuildProofCompressionTarget();
    bench.minEpochIterations(200).run([&] {
        ankerl::nanobench::doNotOptimizeAway(shielded::ComputeBridgeProofCompressionTargetId(target));
    });
}

static void BridgeProofCompressionEstimate12288(benchmark::Bench& bench)
{
    const auto target = BuildProofCompressionTarget();
    bench.unit("estimate").minEpochIterations(200).run([&] {
        const auto estimate = shielded::EstimateBridgeProofCompression(target);
        assert(estimate.has_value());
        ankerl::nanobench::doNotOptimizeAway(*estimate);
    });
}

} // namespace

BENCHMARK(BridgeBatchRoot32, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeBatchRoot256, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeBatchAuthorizationVerifyMLDSA44, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeBatchAuthorizationVerifySLHDSA128S, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeVerifierSetRoot32MLDSA44, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeVerifierSetProofVerify32MLDSA44, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeProofPolicyRoot32, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeProofPolicyProofVerify32, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeProofSystemIdHash, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeProofClaimHashSettlementMetadata, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeProofClaimHashDataRootTuple, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeProofAdapterIdHash, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeProofArtifactIdHash, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeAttestationHashV2, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeAttestationHashV3, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeExternalAnchorFromReceipts8MLDSA44, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeProofReceiptRoot8, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeExternalAnchorFromProofReceipts8, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeVerificationBundleHash, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeExternalAnchorFromHybridWitness8, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeProverBenchmarkBuild5Profiles, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeAggregateSettlementIdHash, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeAggregateSettlementFootprint, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeShieldedStateProfileIdHash, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeShieldedStateGrowthEstimate, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeShieldedStateRetentionPolicyIdHash, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeShieldedStateRetentionEstimate, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeDataArtifactIdHash, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeAggregateArtifactBundleBuild, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeProofCompressionTargetIdHash, benchmark::PriorityLevel::HIGH);
BENCHMARK(BridgeProofCompressionEstimate12288, benchmark::PriorityLevel::HIGH);
