// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <hash.h>
#include <pqkey.h>
#include <script/interpreter.h>
#include <shielded/bridge.h>
#include <span.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace {

shielded::BridgeKeySpec MakeBridgeKey(unsigned char seed, PQAlgorithm algo = PQAlgorithm::ML_DSA_44)
{
    std::array<unsigned char, 32> material{};
    material.fill(seed);
    CPQKey key;
    BOOST_REQUIRE(key.MakeDeterministicKey(algo, material));
    return {algo, key.GetPubKey()};
}

shielded::BridgeAttestationMessage MakeAttestation()
{
    shielded::BridgeAttestationMessage message;
    message.version = 1;
    message.genesis_hash = uint256{1};
    message.direction = shielded::BridgeDirection::BRIDGE_OUT;
    message.ids.bridge_id = uint256{2};
    message.ids.operation_id = uint256{3};
    message.ctv_hash = uint256{4};
    message.refund_lock_height = 500;
    return message;
}

shielded::BridgeBatchLeaf MakeBatchLeaf(unsigned char seed, CAmount amount)
{
    shielded::BridgeBatchLeaf leaf;
    leaf.kind = shielded::BridgeBatchLeafKind::SHIELD_CREDIT;
    leaf.wallet_id = uint256{seed};
    leaf.destination_id = uint256{static_cast<unsigned char>(seed + 1)};
    leaf.amount = amount;
    leaf.authorization_hash = uint256{static_cast<unsigned char>(seed + 2)};
    return leaf;
}

shielded::BridgeBatchCommitment MakeBatchCommitment(shielded::BridgeDirection direction, CAmount total_amount)
{
    std::vector<shielded::BridgeBatchLeaf> leaves{
        MakeBatchLeaf(0x10, total_amount / 2),
        MakeBatchLeaf(0x20, total_amount - (total_amount / 2)),
    };
    shielded::BridgeBatchCommitment commitment;
    commitment.version = 1;
    commitment.direction = direction;
    commitment.ids.bridge_id = uint256{7};
    commitment.ids.operation_id = uint256{8};
    commitment.entry_count = leaves.size();
    commitment.total_amount = total_amount;
    commitment.batch_root = shielded::ComputeBridgeBatchRoot(leaves);
    return commitment;
}

shielded::BridgeBatchAggregateCommitment MakeAggregateCommitment(const uint256& action_root,
                                                                 const uint256& data_availability_root,
                                                                 const uint256& recovery_or_exit_root = uint256{},
                                                                 const uint256& policy_commitment = uint256{},
                                                                 uint32_t extension_flags = 0)
{
    shielded::BridgeBatchAggregateCommitment commitment;
    commitment.action_root = action_root;
    commitment.data_availability_root = data_availability_root;
    commitment.recovery_or_exit_root = recovery_or_exit_root;
    commitment.policy_commitment = policy_commitment;
    commitment.extension_flags = extension_flags;
    BOOST_REQUIRE(commitment.IsValid());
    return commitment;
}

shielded::BridgeExternalAnchor MakeExternalAnchor()
{
    shielded::BridgeExternalAnchor anchor;
    anchor.domain_id = uint256{0x90};
    anchor.source_epoch = 42;
    anchor.data_root = uint256{0x91};
    anchor.verification_root = uint256{0x92};
    return anchor;
}

shielded::BridgeVerifierSetCommitment MakeVerifierSetCommitment(unsigned char seed_base,
                                                                size_t count,
                                                                size_t required_signers)
{
    std::vector<shielded::BridgeKeySpec> attestors;
    attestors.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        attestors.push_back(MakeBridgeKey(static_cast<unsigned char>(seed_base + i)));
    }
    const auto verifier_set = shielded::BuildBridgeVerifierSetCommitment(attestors, required_signers);
    BOOST_REQUIRE(verifier_set.has_value());
    return *verifier_set;
}

std::vector<shielded::BridgeKeySpec> MakeVerifierSetAttestors(unsigned char seed_base, size_t count)
{
    std::vector<shielded::BridgeKeySpec> attestors;
    attestors.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        attestors.push_back(MakeBridgeKey(static_cast<unsigned char>(seed_base + i)));
    }
    return attestors;
}

shielded::BridgeProofDescriptor MakeProofDescriptor(unsigned char seed)
{
    shielded::BridgeProofDescriptor descriptor;
    descriptor.proof_system_id = uint256{seed};
    descriptor.verifier_key_hash = uint256{static_cast<unsigned char>(seed + 1)};
    BOOST_REQUIRE(descriptor.IsValid());
    return descriptor;
}

shielded::BridgeProofSystemProfile MakeProofSystemProfile(unsigned char seed)
{
    shielded::BridgeProofSystemProfile profile;
    profile.family_id = uint256{seed};
    profile.proof_type_id = uint256{static_cast<unsigned char>(seed + 1)};
    profile.claim_system_id = uint256{static_cast<unsigned char>(seed + 2)};
    BOOST_REQUIRE(profile.IsValid());
    return profile;
}

shielded::BridgeProofClaim MakeProofClaim(const shielded::BridgeBatchStatement& statement,
                                          shielded::BridgeProofClaimKind kind)
{
    const auto claim = shielded::BuildBridgeProofClaimFromStatement(statement, kind);
    BOOST_REQUIRE(claim.has_value());
    return *claim;
}

shielded::BridgeProofAdapter MakeProofAdapter(unsigned char seed,
                                              shielded::BridgeProofClaimKind kind)
{
    shielded::BridgeProofAdapter adapter;
    adapter.profile = MakeProofSystemProfile(seed);
    adapter.claim_kind = kind;
    BOOST_REQUIRE(adapter.IsValid());
    return adapter;
}

shielded::BridgeProofArtifact MakeProofArtifact(const shielded::BridgeBatchStatement& statement,
                                                unsigned char seed,
                                                shielded::BridgeProofClaimKind kind)
{
    const auto adapter = MakeProofAdapter(seed, kind);
    const auto artifact = shielded::BuildBridgeProofArtifact(statement,
                                                             adapter,
                                                             uint256{static_cast<unsigned char>(seed + 3)},
                                                             uint256{static_cast<unsigned char>(seed + 4)},
                                                             uint256{static_cast<unsigned char>(seed + 5)},
                                                             4096,
                                                             96,
                                                             512);
    BOOST_REQUIRE(artifact.has_value());
    return *artifact;
}

shielded::BridgeProofArtifact MakeProofArtifact(const shielded::BridgeBatchStatement& statement,
                                                unsigned char seed,
                                                shielded::BridgeProofClaimKind kind,
                                                uint32_t proof_size_bytes,
                                                uint32_t public_values_size_bytes,
                                                uint32_t auxiliary_data_size_bytes)
{
    const auto adapter = MakeProofAdapter(seed, kind);
    const auto artifact = shielded::BuildBridgeProofArtifact(statement,
                                                             adapter,
                                                             uint256{static_cast<unsigned char>(seed + 3)},
                                                             uint256{static_cast<unsigned char>(seed + 4)},
                                                             uint256{static_cast<unsigned char>(seed + 5)},
                                                             proof_size_bytes,
                                                             public_values_size_bytes,
                                                             auxiliary_data_size_bytes);
    BOOST_REQUIRE(artifact.has_value());
    return *artifact;
}

shielded::BridgeDataArtifact MakeDataArtifact(const shielded::BridgeBatchStatement& statement,
                                              unsigned char seed,
                                              shielded::BridgeDataArtifactKind kind,
                                              uint32_t payload_size_bytes,
                                              uint32_t auxiliary_data_size_bytes)
{
    const auto artifact = shielded::BuildBridgeDataArtifact(statement,
                                                            kind,
                                                            uint256{static_cast<unsigned char>(seed + 6)},
                                                            uint256{static_cast<unsigned char>(seed + 7)},
                                                            payload_size_bytes,
                                                            auxiliary_data_size_bytes);
    BOOST_REQUIRE(artifact.has_value());
    return *artifact;
}

shielded::BridgeCapacityFootprint MakeCapacityFootprint(uint64_t l1_serialized_bytes,
                                                        uint64_t l1_weight,
                                                        uint32_t batched_user_count,
                                                        uint64_t l1_data_availability_bytes = 0,
                                                        uint64_t control_plane_bytes = 0,
                                                        uint64_t offchain_storage_bytes = 0)
{
    shielded::BridgeCapacityFootprint footprint;
    footprint.l1_serialized_bytes = l1_serialized_bytes;
    footprint.l1_weight = l1_weight;
    footprint.l1_data_availability_bytes = l1_data_availability_bytes;
    footprint.control_plane_bytes = control_plane_bytes;
    footprint.offchain_storage_bytes = offchain_storage_bytes;
    footprint.batched_user_count = batched_user_count;
    BOOST_REQUIRE(footprint.IsValid());
    return footprint;
}

shielded::BridgeAggregateSettlement MakeAggregateSettlement(const shielded::BridgeBatchStatement& statement)
{
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
    BOOST_REQUIRE(settlement.IsValid());
    return settlement;
}

shielded::BridgeAggregateArtifactBundle MakeArtifactBackedAggregateBundle(const shielded::BridgeBatchStatement& statement)
{
    const auto proof = MakeProofArtifact(statement,
                                         0xe6,
                                         shielded::BridgeProofClaimKind::SETTLEMENT_METADATA,
                                         393216,
                                         96,
                                         2048);
    const auto state_diff = MakeDataArtifact(statement,
                                             0xe7,
                                             shielded::BridgeDataArtifactKind::STATE_DIFF,
                                             6080,
                                             512);
    const auto snapshot = MakeDataArtifact(statement,
                                           0xe8,
                                           shielded::BridgeDataArtifactKind::SNAPSHOT_APPENDIX,
                                           2048,
                                           256);
    const std::array<shielded::BridgeProofArtifact, 1> proof_artifacts{{proof}};
    const std::array<shielded::BridgeDataArtifact, 2> data_artifacts{{state_diff, snapshot}};
    const auto bundle = shielded::BuildBridgeAggregateArtifactBundle(
        statement,
        Span<const shielded::BridgeProofArtifact>{proof_artifacts.data(), proof_artifacts.size()},
        Span<const shielded::BridgeDataArtifact>{data_artifacts.data(), data_artifacts.size()});
    BOOST_REQUIRE(bundle.has_value());
    return *bundle;
}

shielded::BridgeProofCompressionTarget MakeProofCompressionTarget(const shielded::BridgeAggregateSettlement& settlement,
                                                                  const std::optional<shielded::BridgeAggregateArtifactBundle>& bundle,
                                                                  uint64_t target_users_per_block)
{
    const auto target = shielded::BuildBridgeProofCompressionTarget(settlement,
                                                                    bundle,
                                                                    MAX_BLOCK_SERIALIZED_SIZE,
                                                                    MAX_BLOCK_WEIGHT,
                                                                    786432,
                                                                    target_users_per_block);
    BOOST_REQUIRE(target.has_value());
    return *target;
}

shielded::BridgeShieldedStateProfile MakeShieldedStateProfile(uint64_t wallet_materialization_bytes = 0)
{
    shielded::BridgeShieldedStateProfile profile;
    profile.wallet_materialization_bytes = wallet_materialization_bytes;
    BOOST_REQUIRE(profile.IsValid());
    return profile;
}

shielded::BridgeShieldedStateRetentionPolicy MakeShieldedStateRetentionPolicy(uint32_t wallet_l1_materialization_bps = shielded::BridgeShieldedStateRetentionPolicy::PRODUCTION_WALLET_L1_MATERIALIZATION_BPS,
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
    BOOST_REQUIRE(policy.IsValid());
    return policy;
}

shielded::BridgeProverLane MakeProverLane(uint64_t millis_per_settlement,
                                          uint32_t workers,
                                          uint32_t parallel_jobs_per_worker = 1,
                                          uint64_t hourly_cost_cents = 0)
{
    shielded::BridgeProverLane lane;
    lane.millis_per_settlement = millis_per_settlement;
    lane.workers = workers;
    lane.parallel_jobs_per_worker = parallel_jobs_per_worker;
    lane.hourly_cost_cents = hourly_cost_cents;
    BOOST_REQUIRE(lane.IsValid());
    return lane;
}

shielded::BridgeProverSample MakeProverSample(const shielded::BridgeBatchStatement& statement,
                                              unsigned char seed,
                                              uint64_t native_millis,
                                              uint64_t cpu_millis,
                                              uint64_t gpu_millis,
                                              uint64_t network_millis,
                                              uint64_t peak_memory_bytes = 0)
{
    const auto artifact = MakeProofArtifact(statement, seed, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    const auto sample = shielded::BuildBridgeProverSample(artifact,
                                                          native_millis,
                                                          cpu_millis,
                                                          gpu_millis,
                                                          network_millis,
                                                          peak_memory_bytes);
    BOOST_REQUIRE(sample.has_value());
    return *sample;
}

shielded::BridgeProverProfile MakeProverProfile(const shielded::BridgeBatchStatement& statement,
                                                unsigned char seed_a,
                                                unsigned char seed_b,
                                                unsigned char seed_c,
                                                uint64_t native_total,
                                                uint64_t cpu_total,
                                                uint64_t gpu_total,
                                                uint64_t network_total,
                                                uint64_t peak_a,
                                                uint64_t peak_b,
                                                uint64_t peak_c)
{
    const auto sample_a = MakeProverSample(statement,
                                           seed_a,
                                           native_total / 3,
                                           cpu_total / 3,
                                           gpu_total / 3,
                                           network_total / 3,
                                           peak_a);
    const auto sample_b = MakeProverSample(statement,
                                           seed_b,
                                           native_total / 3,
                                           cpu_total / 3,
                                           gpu_total / 3,
                                           network_total / 3,
                                           peak_b);
    const auto sample_c = MakeProverSample(statement,
                                           seed_c,
                                           native_total - sample_a.native_millis - sample_b.native_millis,
                                           cpu_total - sample_a.cpu_millis - sample_b.cpu_millis,
                                           gpu_total - sample_a.gpu_millis - sample_b.gpu_millis,
                                           network_total - sample_a.network_millis - sample_b.network_millis,
                                           peak_c);
    const std::array<shielded::BridgeProverSample, 3> samples{sample_a, sample_b, sample_c};
    const auto profile = shielded::BuildBridgeProverProfile(samples);
    BOOST_REQUIRE(profile.has_value());
    return *profile;
}

shielded::BridgeBatchStatement MakeBatchStatement(shielded::BridgeDirection direction, CAmount total_amount)
{
    const auto commitment = MakeBatchCommitment(direction, total_amount);
    shielded::BridgeBatchStatement statement;
    statement.direction = direction;
    statement.ids = commitment.ids;
    statement.entry_count = commitment.entry_count;
    statement.total_amount = commitment.total_amount;
    statement.batch_root = commitment.batch_root;
    statement.domain_id = uint256{0xa0};
    statement.source_epoch = 11;
    statement.data_root = uint256{0xa1};
    return statement;
}

shielded::BridgeBatchStatement MakeBatchStatementWithVerifierSet(shielded::BridgeDirection direction,
                                                                 CAmount total_amount,
                                                                 const shielded::BridgeVerifierSetCommitment& verifier_set)
{
    auto statement = MakeBatchStatement(direction, total_amount);
    statement.version = 2;
    statement.verifier_set = verifier_set;
    BOOST_REQUIRE(statement.IsValid());
    return statement;
}

shielded::BridgeBatchStatement MakeBatchStatementWithProofPolicy(shielded::BridgeDirection direction,
                                                                 CAmount total_amount,
                                                                 const shielded::BridgeProofPolicyCommitment& proof_policy)
{
    auto statement = MakeBatchStatement(direction, total_amount);
    statement.version = 3;
    statement.proof_policy = proof_policy;
    BOOST_REQUIRE(statement.IsValid());
    return statement;
}

shielded::BridgeBatchStatement MakeBatchStatementWithVerifierSetAndProofPolicy(shielded::BridgeDirection direction,
                                                                                CAmount total_amount,
                                                                                const shielded::BridgeVerifierSetCommitment& verifier_set,
                                                                                const shielded::BridgeProofPolicyCommitment& proof_policy)
{
    auto statement = MakeBatchStatement(direction, total_amount);
    statement.version = 4;
    statement.verifier_set = verifier_set;
    statement.proof_policy = proof_policy;
    BOOST_REQUIRE(statement.IsValid());
    return statement;
}

shielded::BridgeBatchStatement MakeFutureProofedBatchStatement(
    shielded::BridgeDirection direction,
    CAmount total_amount,
    const std::optional<shielded::BridgeVerifierSetCommitment>& verifier_set = std::nullopt,
    const std::optional<shielded::BridgeProofPolicyCommitment>& proof_policy = std::nullopt)
{
    auto statement = MakeBatchStatement(direction, total_amount);
    if (verifier_set.has_value()) {
        statement.verifier_set = *verifier_set;
    }
    if (proof_policy.has_value()) {
        statement.proof_policy = *proof_policy;
    }
    const auto aggregate_commitment = shielded::BuildDefaultBridgeBatchAggregateCommitment(statement.batch_root,
                                                                                           statement.data_root,
                                                                                           statement.proof_policy);
    BOOST_REQUIRE(aggregate_commitment.has_value());
    statement.aggregate_commitment = *aggregate_commitment;
    statement.version = 5;
    BOOST_REQUIRE(statement.IsValid());
    return statement;
}

shielded::BridgeBatchCommitment MakeFutureProofedBatchCommitment(shielded::BridgeDirection direction,
                                                                 CAmount total_amount,
                                                                 const std::optional<shielded::BridgeExternalAnchor>& external_anchor = std::nullopt)
{
    auto commitment = MakeBatchCommitment(direction, total_amount);
    if (external_anchor.has_value()) {
        commitment.external_anchor = *external_anchor;
    }
    commitment.aggregate_commitment = MakeAggregateCommitment(commitment.batch_root,
                                                              external_anchor.has_value() ? external_anchor->data_root
                                                                                          : uint256{0xb0},
                                                              uint256{0xb1},
                                                              uint256{0xb2},
                                                              shielded::BridgeBatchAggregateCommitment::FLAG_HAS_RECOVERY_OR_EXIT_ROOT |
                                                                  shielded::BridgeBatchAggregateCommitment::FLAG_HAS_POLICY_COMMITMENT);
    commitment.version = 3;
    BOOST_REQUIRE(commitment.IsValid());
    return commitment;
}

shielded::BridgeBatchReceipt MakeSignedBatchReceipt(unsigned char seed,
                                                    const shielded::BridgeBatchStatement& statement,
                                                    PQAlgorithm algo = PQAlgorithm::ML_DSA_44)
{
    std::array<unsigned char, 32> material{};
    material.fill(seed);

    CPQKey key;
    BOOST_REQUIRE(key.MakeDeterministicKey(algo, material));

    shielded::BridgeBatchReceipt receipt;
    receipt.statement = statement;
    receipt.attestor = {algo, key.GetPubKey()};

    const uint256 receipt_hash = shielded::ComputeBridgeBatchReceiptHash(receipt);
    BOOST_REQUIRE(!receipt_hash.IsNull());
    BOOST_REQUIRE(key.Sign(receipt_hash, receipt.signature));
    BOOST_REQUIRE(receipt.IsValid());
    return receipt;
}

shielded::BridgeVerificationBundle MakeVerificationBundle(unsigned char seed)
{
    shielded::BridgeVerificationBundle bundle;
    bundle.signed_receipt_root = uint256{seed};
    bundle.proof_receipt_root = uint256{static_cast<unsigned char>(seed + 1)};
    BOOST_REQUIRE(bundle.IsValid());
    return bundle;
}

shielded::BridgeProofReceipt MakeProofReceipt(unsigned char seed,
                                              const shielded::BridgeBatchStatement& statement)
{
    shielded::BridgeProofReceipt receipt;
    receipt.statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    BOOST_REQUIRE(!receipt.statement_hash.IsNull());
    receipt.proof_system_id = uint256{seed};
    receipt.verifier_key_hash = uint256{static_cast<unsigned char>(seed + 1)};
    receipt.public_values_hash = uint256{static_cast<unsigned char>(seed + 2)};
    receipt.proof_commitment = uint256{static_cast<unsigned char>(seed + 3)};
    BOOST_REQUIRE(receipt.IsValid());
    return receipt;
}

shielded::BridgeBatchAuthorization MakeSignedBatchAuthorization(unsigned char seed,
                                                               shielded::BridgeDirection direction,
                                                               CAmount amount,
                                                               PQAlgorithm algo = PQAlgorithm::ML_DSA_44)
{
    std::array<unsigned char, 32> material{};
    material.fill(seed);

    CPQKey key;
    BOOST_REQUIRE(key.MakeDeterministicKey(algo, material));

    shielded::BridgeBatchAuthorization authorization;
    authorization.direction = direction;
    authorization.ids.bridge_id = uint256{static_cast<unsigned char>(seed + 10)};
    authorization.ids.operation_id = uint256{static_cast<unsigned char>(seed + 11)};
    authorization.kind = shielded::BridgeBatchLeafKind::TRANSPARENT_PAYOUT;
    authorization.wallet_id = uint256{static_cast<unsigned char>(seed + 1)};
    authorization.destination_id = uint256{static_cast<unsigned char>(seed + 2)};
    authorization.amount = amount;
    authorization.authorization_nonce = uint256{static_cast<unsigned char>(seed + 3)};
    authorization.authorizer = {algo, key.GetPubKey()};

    const uint256 authorization_hash = shielded::ComputeBridgeBatchAuthorizationHash(authorization);
    BOOST_REQUIRE(!authorization_hash.IsNull());
    BOOST_REQUIRE(key.Sign(authorization_hash, authorization.signature));
    BOOST_REQUIRE(authorization.IsValid());
    return authorization;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_bridge_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(shield_bridge_script_tree_structure)
{
    const auto tree = shielded::BuildShieldBridgeScriptTree(uint256{11}, MakeBridgeKey(0x11), 144, MakeBridgeKey(0x22, PQAlgorithm::SLH_DSA_128S));
    BOOST_REQUIRE(tree.has_value());
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(tree->kind), static_cast<uint8_t>(shielded::BridgeTemplateKind::SHIELD));
    BOOST_CHECK(!tree->merkle_root.IsNull());
    BOOST_CHECK(tree->normal_leaf_hash != tree->refund_leaf_hash);
}

BOOST_AUTO_TEST_CASE(unshield_bridge_script_tree_structure)
{
    const auto tree = shielded::BuildUnshieldBridgeScriptTree(uint256{12}, MakeBridgeKey(0x33), 288, MakeBridgeKey(0x44));
    BOOST_REQUIRE(tree.has_value());
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(tree->kind), static_cast<uint8_t>(shielded::BridgeTemplateKind::UNSHIELD));
    BOOST_CHECK(!tree->merkle_root.IsNull());
    BOOST_CHECK(tree->normal_leaf_hash != tree->refund_leaf_hash);
}

BOOST_AUTO_TEST_CASE(different_ctv_hash_produces_different_bridge_root)
{
    const auto tree_a = shielded::BuildShieldBridgeScriptTree(uint256{1}, MakeBridgeKey(0x55), 300, MakeBridgeKey(0x66));
    const auto tree_b = shielded::BuildShieldBridgeScriptTree(uint256{2}, MakeBridgeKey(0x55), 300, MakeBridgeKey(0x66));
    BOOST_REQUIRE(tree_a.has_value());
    BOOST_REQUIRE(tree_b.has_value());
    BOOST_CHECK(tree_a->merkle_root != tree_b->merkle_root);

    const auto unshield_a = shielded::BuildUnshieldBridgeScriptTree(uint256{3}, MakeBridgeKey(0x55), 300, MakeBridgeKey(0x66));
    const auto unshield_b = shielded::BuildUnshieldBridgeScriptTree(uint256{4}, MakeBridgeKey(0x55), 300, MakeBridgeKey(0x66));
    BOOST_REQUIRE(unshield_a.has_value());
    BOOST_REQUIRE(unshield_b.has_value());
    BOOST_CHECK(unshield_a->merkle_root != unshield_b->merkle_root);
}

BOOST_AUTO_TEST_CASE(bridge_script_tree_is_deterministic)
{
    const auto tree_a = shielded::BuildShieldBridgeScriptTree(uint256{7}, MakeBridgeKey(0x77), 600, MakeBridgeKey(0x88));
    const auto tree_b = shielded::BuildShieldBridgeScriptTree(uint256{7}, MakeBridgeKey(0x77), 600, MakeBridgeKey(0x88));
    BOOST_REQUIRE(tree_a.has_value());
    BOOST_REQUIRE(tree_b.has_value());
    BOOST_CHECK(tree_a->merkle_root == tree_b->merkle_root);
    BOOST_CHECK(tree_a->normal_leaf_hash == tree_b->normal_leaf_hash);
    BOOST_CHECK(tree_a->refund_leaf_hash == tree_b->refund_leaf_hash);
    BOOST_CHECK(tree_a->normal_control_block == tree_b->normal_control_block);
    BOOST_CHECK(tree_a->refund_control_block == tree_b->refund_control_block);
}

BOOST_AUTO_TEST_CASE(bridge_control_block_verifies_leaf_commitment)
{
    const auto tree = shielded::BuildShieldBridgeScriptTree(uint256{17}, MakeBridgeKey(0x99), 720, MakeBridgeKey(0xaa));
    BOOST_REQUIRE(tree.has_value());
    const Span<const unsigned char> program{tree->merkle_root.begin(), tree->merkle_root.size()};
    BOOST_CHECK(VerifyP2MRCommitment(tree->normal_control_block, program, tree->normal_leaf_hash));
    BOOST_CHECK(VerifyP2MRCommitment(tree->refund_control_block, program, tree->refund_leaf_hash));
}

BOOST_AUTO_TEST_CASE(bridge_script_tree_rejects_invalid_pubkey_or_timeout_inputs)
{
    shielded::BridgeKeySpec invalid_key{PQAlgorithm::ML_DSA_44, {0x01, 0x02}};
    BOOST_CHECK(!shielded::BuildShieldBridgeScriptTree(uint256{1}, invalid_key, 100, MakeBridgeKey(0xbb)).has_value());
    BOOST_CHECK(!shielded::BuildUnshieldBridgeScriptTree(uint256{5}, MakeBridgeKey(0xcc), 0, MakeBridgeKey(0xdd)).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_attestation_serialization_is_deterministic)
{
    const auto bytes_a = shielded::SerializeBridgeAttestationMessage(MakeAttestation());
    const auto bytes_b = shielded::SerializeBridgeAttestationMessage(MakeAttestation());
    BOOST_CHECK(bytes_a == bytes_b);
    BOOST_CHECK_EQUAL(bytes_a.size(), 134U);
}

BOOST_AUTO_TEST_CASE(bridge_attestation_hash_changes_when_any_field_changes)
{
    auto base = MakeAttestation();
    const uint256 base_hash = shielded::ComputeBridgeAttestationHash(base);
    base.ids.operation_id = uint256{9};
    BOOST_CHECK(shielded::ComputeBridgeAttestationHash(base) != base_hash);
}

BOOST_AUTO_TEST_CASE(bridge_attestation_rejects_zero_or_invalid_direction)
{
    auto message = MakeAttestation();
    message.direction = static_cast<shielded::BridgeDirection>(0);
    BOOST_CHECK(!shielded::IsWellFormedBridgeAttestation(message));
}

BOOST_AUTO_TEST_CASE(bridge_attestation_rejects_missing_ctv_hash)
{
    auto message = MakeAttestation();
    message.ctv_hash.SetNull();
    BOOST_CHECK(!shielded::IsWellFormedBridgeAttestation(message));
}

BOOST_AUTO_TEST_CASE(bridge_attestation_rejects_wrong_network_domain)
{
    const auto message = MakeAttestation();
    BOOST_CHECK(shielded::IsWellFormedBridgeAttestation(message));
    BOOST_CHECK(!shielded::DoesBridgeAttestationMatchGenesis(message, uint256{42}));
}

BOOST_AUTO_TEST_CASE(bridge_attestation_hash_roundtrips_with_csfs_domain)
{
    const auto message = MakeAttestation();
    const auto serialized = shielded::SerializeBridgeAttestationMessage(message);
    HashWriter hasher = HASHER_CSFS;
    hasher.write(AsBytes(Span<const uint8_t>{serialized.data(), serialized.size()}));
    BOOST_CHECK(shielded::ComputeBridgeAttestationHash(message) == hasher.GetSHA256());

    const auto decoded = shielded::DeserializeBridgeAttestationMessage(serialized);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(decoded->ctv_hash == message.ctv_hash);
    BOOST_CHECK(decoded->ids.operation_id == message.ids.operation_id);
}

BOOST_AUTO_TEST_CASE(bridge_batch_leaf_hash_is_deterministic)
{
    const auto leaf = MakeBatchLeaf(0x33, 5 * COIN);
    BOOST_CHECK(leaf.IsValid());
    const uint256 hash_a = shielded::ComputeBridgeBatchLeafHash(leaf);
    const uint256 hash_b = shielded::ComputeBridgeBatchLeafHash(leaf);
    BOOST_CHECK(!hash_a.IsNull());
    BOOST_CHECK(hash_a == hash_b);
}

BOOST_AUTO_TEST_CASE(bridge_batch_root_changes_with_leaf_order)
{
    const std::vector<shielded::BridgeBatchLeaf> leaves_a{
        MakeBatchLeaf(0x01, COIN),
        MakeBatchLeaf(0x02, 2 * COIN),
        MakeBatchLeaf(0x03, 3 * COIN),
    };
    const std::vector<shielded::BridgeBatchLeaf> leaves_b{
        leaves_a[1],
        leaves_a[0],
        leaves_a[2],
    };
    const uint256 root_a = shielded::ComputeBridgeBatchRoot(leaves_a);
    const uint256 root_b = shielded::ComputeBridgeBatchRoot(leaves_b);
    BOOST_CHECK(!root_a.IsNull());
    BOOST_CHECK(!root_b.IsNull());
    BOOST_CHECK(root_a != root_b);
}

BOOST_AUTO_TEST_CASE(bridge_batch_commitment_roundtrips_and_hashes)
{
    const auto commitment = MakeBatchCommitment(shielded::BridgeDirection::BRIDGE_IN, 6 * COIN);
    BOOST_REQUIRE(commitment.IsValid());
    const auto bytes = shielded::SerializeBridgeBatchCommitment(commitment);
    BOOST_CHECK(!bytes.empty());
    const auto decoded = shielded::DeserializeBridgeBatchCommitment(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(decoded->batch_root == commitment.batch_root);
    BOOST_CHECK_EQUAL(decoded->entry_count, commitment.entry_count);
    BOOST_CHECK_EQUAL(decoded->total_amount, commitment.total_amount);
    BOOST_CHECK(!shielded::ComputeBridgeBatchCommitmentHash(commitment).IsNull());
}

BOOST_AUTO_TEST_CASE(bridge_attestation_v2_carries_batch_commitment_fields)
{
    auto message = MakeAttestation();
    const auto commitment = MakeBatchCommitment(shielded::BridgeDirection::BRIDGE_OUT, 9 * COIN);
    message.version = 2;
    message.batch_entry_count = commitment.entry_count;
    message.batch_total_amount = commitment.total_amount;
    message.batch_root = commitment.batch_root;
    BOOST_REQUIRE(shielded::IsWellFormedBridgeAttestation(message));

    const auto bytes = shielded::SerializeBridgeAttestationMessage(message);
    BOOST_CHECK_EQUAL(bytes.size(), 178U);

    const auto decoded = shielded::DeserializeBridgeAttestationMessage(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->version, 2U);
    BOOST_CHECK_EQUAL(decoded->batch_entry_count, commitment.entry_count);
    BOOST_CHECK_EQUAL(decoded->batch_total_amount, commitment.total_amount);
    BOOST_CHECK(decoded->batch_root == commitment.batch_root);
}

BOOST_AUTO_TEST_CASE(bridge_batch_commitment_v2_carries_external_anchor)
{
    auto commitment = MakeBatchCommitment(shielded::BridgeDirection::BRIDGE_OUT, 9 * COIN);
    commitment.version = 2;
    commitment.external_anchor = MakeExternalAnchor();
    BOOST_REQUIRE(commitment.IsValid());

    const auto bytes = shielded::SerializeBridgeBatchCommitment(commitment);
    BOOST_CHECK_EQUAL(bytes.size(), 211U);

    const auto decoded = shielded::DeserializeBridgeBatchCommitment(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->version, 2U);
    BOOST_CHECK(decoded->external_anchor.domain_id == commitment.external_anchor.domain_id);
    BOOST_CHECK_EQUAL(decoded->external_anchor.source_epoch, commitment.external_anchor.source_epoch);
    BOOST_CHECK(decoded->external_anchor.data_root == commitment.external_anchor.data_root);
    BOOST_CHECK(decoded->external_anchor.verification_root == commitment.external_anchor.verification_root);
}

BOOST_AUTO_TEST_CASE(bridge_batch_aggregate_commitment_roundtrips_and_hashes)
{
    const auto commitment = MakeAggregateCommitment(uint256{0xc0},
                                                    uint256{0xc1},
                                                    uint256{0xc2},
                                                    uint256{0xc3},
                                                    shielded::BridgeBatchAggregateCommitment::FLAG_HAS_RECOVERY_OR_EXIT_ROOT |
                                                        shielded::BridgeBatchAggregateCommitment::FLAG_HAS_POLICY_COMMITMENT);
    const auto bytes = shielded::SerializeBridgeBatchAggregateCommitment(commitment);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeBatchAggregateCommitment(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(decoded->action_root == commitment.action_root);
    BOOST_CHECK(decoded->data_availability_root == commitment.data_availability_root);
    BOOST_CHECK(decoded->recovery_or_exit_root == commitment.recovery_or_exit_root);
    BOOST_CHECK_EQUAL(decoded->extension_flags, commitment.extension_flags);
    BOOST_CHECK(decoded->policy_commitment == commitment.policy_commitment);

    const uint256 base_hash = shielded::ComputeBridgeBatchAggregateCommitmentHash(commitment);
    BOOST_CHECK(!base_hash.IsNull());
    auto mutated = commitment;
    mutated.recovery_or_exit_root = uint256{0xc4};
    BOOST_CHECK(shielded::ComputeBridgeBatchAggregateCommitmentHash(mutated) != base_hash);
}

BOOST_AUTO_TEST_CASE(bridge_batch_aggregate_commitment_rejects_inconsistent_optional_fields)
{
    shielded::BridgeBatchAggregateCommitment recovery_missing_flag;
    recovery_missing_flag.action_root = uint256{0xd0};
    recovery_missing_flag.data_availability_root = uint256{0xd1};
    recovery_missing_flag.recovery_or_exit_root = uint256{0xd2};
    BOOST_CHECK(!recovery_missing_flag.IsValid());

    shielded::BridgeBatchAggregateCommitment recovery_missing_value;
    recovery_missing_value.action_root = uint256{0xd3};
    recovery_missing_value.data_availability_root = uint256{0xd4};
    recovery_missing_value.extension_flags =
        shielded::BridgeBatchAggregateCommitment::FLAG_HAS_RECOVERY_OR_EXIT_ROOT;
    BOOST_CHECK(!recovery_missing_value.IsValid());

    shielded::BridgeBatchAggregateCommitment policy_missing_flag;
    policy_missing_flag.action_root = uint256{0xd5};
    policy_missing_flag.data_availability_root = uint256{0xd6};
    policy_missing_flag.policy_commitment = uint256{0xd7};
    BOOST_CHECK(!policy_missing_flag.IsValid());

    shielded::BridgeBatchAggregateCommitment policy_missing_value;
    policy_missing_value.action_root = uint256{0xd8};
    policy_missing_value.data_availability_root = uint256{0xd9};
    policy_missing_value.extension_flags =
        shielded::BridgeBatchAggregateCommitment::FLAG_HAS_POLICY_COMMITMENT;
    BOOST_CHECK(!policy_missing_value.IsValid());
}

BOOST_AUTO_TEST_CASE(bridge_batch_commitment_v3_carries_future_proofed_aggregate_commitment)
{
    const auto commitment = MakeFutureProofedBatchCommitment(shielded::BridgeDirection::BRIDGE_OUT,
                                                             9 * COIN,
                                                             MakeExternalAnchor());
    const auto bytes = shielded::SerializeBridgeBatchCommitment(commitment);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeBatchCommitment(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->version, 3U);
    BOOST_CHECK(decoded->aggregate_commitment.action_root == commitment.aggregate_commitment.action_root);
    BOOST_CHECK(decoded->aggregate_commitment.data_availability_root ==
                commitment.aggregate_commitment.data_availability_root);
    BOOST_CHECK(decoded->aggregate_commitment.recovery_or_exit_root ==
                commitment.aggregate_commitment.recovery_or_exit_root);
    BOOST_CHECK_EQUAL(decoded->aggregate_commitment.extension_flags,
                      commitment.aggregate_commitment.extension_flags);
    BOOST_CHECK(decoded->aggregate_commitment.policy_commitment ==
                commitment.aggregate_commitment.policy_commitment);
}

BOOST_AUTO_TEST_CASE(bridge_batch_statement_roundtrips_and_hashes)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 9 * COIN);
    BOOST_REQUIRE(statement.IsValid());
    const auto bytes = shielded::SerializeBridgeBatchStatement(statement);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeBatchStatement(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->entry_count, statement.entry_count);
    BOOST_CHECK_EQUAL(decoded->total_amount, statement.total_amount);
    BOOST_CHECK(decoded->batch_root == statement.batch_root);
    BOOST_CHECK(decoded->domain_id == statement.domain_id);
    BOOST_CHECK_EQUAL(decoded->source_epoch, statement.source_epoch);
    BOOST_CHECK(decoded->data_root == statement.data_root);
    BOOST_CHECK(!shielded::ComputeBridgeBatchStatementHash(statement).IsNull());
}

BOOST_AUTO_TEST_CASE(bridge_batch_statement_v5_roundtrips_with_future_proofed_aggregate_commitment)
{
    const auto verifier_set = MakeVerifierSetCommitment(0x94, 3, 2);
    const std::vector<shielded::BridgeProofDescriptor> descriptors{
        MakeProofDescriptor(0x95),
        MakeProofDescriptor(0x96),
    };
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, 1);
    BOOST_REQUIRE(proof_policy.has_value());

    const auto statement = MakeFutureProofedBatchStatement(shielded::BridgeDirection::BRIDGE_OUT,
                                                           9 * COIN,
                                                           verifier_set,
                                                           *proof_policy);
    const auto bytes = shielded::SerializeBridgeBatchStatement(statement);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeBatchStatement(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->version, 5U);
    BOOST_CHECK(decoded->aggregate_commitment.action_root == statement.aggregate_commitment.action_root);
    BOOST_CHECK(decoded->aggregate_commitment.data_availability_root ==
                statement.aggregate_commitment.data_availability_root);
    BOOST_CHECK_EQUAL(decoded->aggregate_commitment.extension_flags,
                      statement.aggregate_commitment.extension_flags);
    BOOST_CHECK(decoded->aggregate_commitment.policy_commitment ==
                statement.aggregate_commitment.policy_commitment);
}

BOOST_AUTO_TEST_CASE(bridge_batch_statement_and_claim_hash_change_when_aggregate_commitment_changes)
{
    auto statement = MakeFutureProofedBatchStatement(shielded::BridgeDirection::BRIDGE_IN, 7 * COIN);
    const auto claim = MakeProofClaim(statement, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    const uint256 statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    const uint256 claim_hash = shielded::ComputeBridgeProofClaimHash(claim);
    BOOST_CHECK(!statement_hash.IsNull());
    BOOST_CHECK(!claim_hash.IsNull());

    statement.aggregate_commitment.recovery_or_exit_root = uint256{0xd0};
    statement.aggregate_commitment.extension_flags |=
        shielded::BridgeBatchAggregateCommitment::FLAG_HAS_RECOVERY_OR_EXIT_ROOT;
    BOOST_REQUIRE(statement.IsValid());
    const auto mutated_claim = MakeProofClaim(statement, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    BOOST_CHECK(shielded::ComputeBridgeBatchStatementHash(statement) != statement_hash);
    BOOST_CHECK(shielded::ComputeBridgeProofClaimHash(mutated_claim) != claim_hash);
}

BOOST_AUTO_TEST_CASE(bridge_verifier_set_commitment_is_order_independent)
{
    const auto key_a = MakeBridgeKey(0x71);
    const auto key_b = MakeBridgeKey(0x72);
    const auto key_c = MakeBridgeKey(0x73);

    const std::vector<shielded::BridgeKeySpec> attestors_a{key_a, key_b, key_c};
    const std::vector<shielded::BridgeKeySpec> attestors_b{key_c, key_a, key_b};

    const auto verifier_set_a = shielded::BuildBridgeVerifierSetCommitment(attestors_a, 2);
    const auto verifier_set_b = shielded::BuildBridgeVerifierSetCommitment(attestors_b, 2);
    BOOST_REQUIRE(verifier_set_a.has_value());
    BOOST_REQUIRE(verifier_set_b.has_value());
    BOOST_CHECK(verifier_set_a->attestor_root == verifier_set_b->attestor_root);
    BOOST_CHECK_EQUAL(verifier_set_a->attestor_count, 3U);
    BOOST_CHECK_EQUAL(verifier_set_a->required_signers, 2U);
}

BOOST_AUTO_TEST_CASE(bridge_verifier_set_commitment_rejects_duplicates)
{
    const auto key = MakeBridgeKey(0x74);
    const std::vector<shielded::BridgeKeySpec> attestors{key, key};
    BOOST_CHECK(!shielded::BuildBridgeVerifierSetCommitment(attestors, 1).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_verifier_set_proof_roundtrips_and_verifies)
{
    const auto attestors = MakeVerifierSetAttestors(0x75, 4);
    const auto verifier_set = shielded::BuildBridgeVerifierSetCommitment(attestors, 2);
    BOOST_REQUIRE(verifier_set.has_value());

    const auto proof = shielded::BuildBridgeVerifierSetProof(attestors, attestors[2]);
    BOOST_REQUIRE(proof.has_value());
    BOOST_CHECK(shielded::VerifyBridgeVerifierSetProof(*verifier_set, attestors[2], *proof));

    const auto bytes = shielded::SerializeBridgeVerifierSetProof(*proof);
    BOOST_CHECK(!bytes.empty());
    const auto decoded = shielded::DeserializeBridgeVerifierSetProof(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(shielded::VerifyBridgeVerifierSetProof(*verifier_set, attestors[2], *decoded));
}

BOOST_AUTO_TEST_CASE(bridge_verifier_set_proof_rejects_wrong_attestor)
{
    const auto attestors = MakeVerifierSetAttestors(0x80, 4);
    const auto verifier_set = shielded::BuildBridgeVerifierSetCommitment(attestors, 2);
    BOOST_REQUIRE(verifier_set.has_value());

    const auto proof = shielded::BuildBridgeVerifierSetProof(attestors, attestors[1]);
    BOOST_REQUIRE(proof.has_value());
    BOOST_CHECK(!shielded::VerifyBridgeVerifierSetProof(*verifier_set, attestors[2], *proof));
}

BOOST_AUTO_TEST_CASE(bridge_proof_policy_commitment_is_order_independent)
{
    const auto descriptor_a = MakeProofDescriptor(0x81);
    const auto descriptor_b = MakeProofDescriptor(0x82);
    const auto descriptor_c = MakeProofDescriptor(0x83);

    const std::vector<shielded::BridgeProofDescriptor> descriptors_a{descriptor_a, descriptor_b, descriptor_c};
    const std::vector<shielded::BridgeProofDescriptor> descriptors_b{descriptor_c, descriptor_a, descriptor_b};

    const auto proof_policy_a = shielded::BuildBridgeProofPolicyCommitment(descriptors_a, 2);
    const auto proof_policy_b = shielded::BuildBridgeProofPolicyCommitment(descriptors_b, 2);
    BOOST_REQUIRE(proof_policy_a.has_value());
    BOOST_REQUIRE(proof_policy_b.has_value());
    BOOST_CHECK(proof_policy_a->descriptor_root == proof_policy_b->descriptor_root);
    BOOST_CHECK_EQUAL(proof_policy_a->descriptor_count, 3U);
    BOOST_CHECK_EQUAL(proof_policy_a->required_receipts, 2U);
}

BOOST_AUTO_TEST_CASE(bridge_proof_policy_commitment_rejects_duplicates)
{
    const auto descriptor = MakeProofDescriptor(0x84);
    const std::vector<shielded::BridgeProofDescriptor> descriptors{descriptor, descriptor};
    BOOST_CHECK(!shielded::BuildBridgeProofPolicyCommitment(descriptors, 1).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_proof_policy_commitment_allows_threshold_above_descriptor_count)
{
    const std::vector<shielded::BridgeProofDescriptor> descriptors{MakeProofDescriptor(0x8d)};
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, 2);
    BOOST_REQUIRE(proof_policy.has_value());
    BOOST_CHECK_EQUAL(proof_policy->descriptor_count, 1U);
    BOOST_CHECK_EQUAL(proof_policy->required_receipts, 2U);
}

BOOST_AUTO_TEST_CASE(bridge_proof_policy_proof_roundtrips_and_verifies)
{
    const std::vector<shielded::BridgeProofDescriptor> descriptors{
        MakeProofDescriptor(0x85),
        MakeProofDescriptor(0x86),
        MakeProofDescriptor(0x87),
        MakeProofDescriptor(0x88),
    };
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, 2);
    BOOST_REQUIRE(proof_policy.has_value());

    const auto proof = shielded::BuildBridgeProofPolicyProof(descriptors, descriptors[2]);
    BOOST_REQUIRE(proof.has_value());
    BOOST_CHECK(shielded::VerifyBridgeProofPolicyProof(*proof_policy, descriptors[2], *proof));

    const auto bytes = shielded::SerializeBridgeProofPolicyProof(*proof);
    BOOST_CHECK(!bytes.empty());
    const auto decoded = shielded::DeserializeBridgeProofPolicyProof(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(shielded::VerifyBridgeProofPolicyProof(*proof_policy, descriptors[2], *decoded));
}

BOOST_AUTO_TEST_CASE(bridge_proof_policy_proof_rejects_wrong_descriptor)
{
    const std::vector<shielded::BridgeProofDescriptor> descriptors{
        MakeProofDescriptor(0x89),
        MakeProofDescriptor(0x8a),
        MakeProofDescriptor(0x8b),
        MakeProofDescriptor(0x8c),
    };
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, 2);
    BOOST_REQUIRE(proof_policy.has_value());

    const auto proof = shielded::BuildBridgeProofPolicyProof(descriptors, descriptors[1]);
    BOOST_REQUIRE(proof.has_value());
    BOOST_CHECK(!shielded::VerifyBridgeProofPolicyProof(*proof_policy, descriptors[2], *proof));
}

BOOST_AUTO_TEST_CASE(bridge_proof_system_profile_roundtrips_and_hashes)
{
    const auto profile = MakeProofSystemProfile(0x70);
    const auto bytes = shielded::SerializeBridgeProofSystemProfile(profile);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeProofSystemProfile(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(decoded->family_id == profile.family_id);
    BOOST_CHECK(decoded->proof_type_id == profile.proof_type_id);
    BOOST_CHECK(decoded->claim_system_id == profile.claim_system_id);
    BOOST_CHECK(!shielded::ComputeBridgeProofSystemId(profile).IsNull());
}

BOOST_AUTO_TEST_CASE(bridge_proof_descriptor_builds_from_profile)
{
    const auto profile = MakeProofSystemProfile(0x74);
    const uint256 verifier_key_hash{0x77};
    const auto descriptor = shielded::BuildBridgeProofDescriptorFromProfile(profile, verifier_key_hash);
    BOOST_REQUIRE(descriptor.has_value());
    BOOST_CHECK(descriptor->proof_system_id == shielded::ComputeBridgeProofSystemId(profile));
    BOOST_CHECK(descriptor->verifier_key_hash == verifier_key_hash);
}

BOOST_AUTO_TEST_CASE(bridge_batch_statement_v2_roundtrips_with_verifier_set)
{
    const auto verifier_set = MakeVerifierSetCommitment(0x75, 3, 2);
    const auto statement = MakeBatchStatementWithVerifierSet(shielded::BridgeDirection::BRIDGE_OUT, 9 * COIN, verifier_set);

    const auto bytes = shielded::SerializeBridgeBatchStatement(statement);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeBatchStatement(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->version, 2U);
    BOOST_CHECK_EQUAL(decoded->verifier_set.attestor_count, verifier_set.attestor_count);
    BOOST_CHECK_EQUAL(decoded->verifier_set.required_signers, verifier_set.required_signers);
    BOOST_CHECK(decoded->verifier_set.attestor_root == verifier_set.attestor_root);
}

BOOST_AUTO_TEST_CASE(bridge_batch_statement_v3_roundtrips_with_proof_policy)
{
    const std::vector<shielded::BridgeProofDescriptor> descriptors{
        MakeProofDescriptor(0x8d),
        MakeProofDescriptor(0x8e),
        MakeProofDescriptor(0x8f),
    };
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, 2);
    BOOST_REQUIRE(proof_policy.has_value());

    const auto statement = MakeBatchStatementWithProofPolicy(shielded::BridgeDirection::BRIDGE_OUT, 9 * COIN, *proof_policy);
    const auto bytes = shielded::SerializeBridgeBatchStatement(statement);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeBatchStatement(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->version, 3U);
    BOOST_CHECK_EQUAL(decoded->proof_policy.descriptor_count, proof_policy->descriptor_count);
    BOOST_CHECK_EQUAL(decoded->proof_policy.required_receipts, proof_policy->required_receipts);
    BOOST_CHECK(decoded->proof_policy.descriptor_root == proof_policy->descriptor_root);
}

BOOST_AUTO_TEST_CASE(bridge_batch_statement_v4_roundtrips_with_verifier_set_and_proof_policy)
{
    const auto verifier_set = MakeVerifierSetCommitment(0x90, 3, 2);
    const std::vector<shielded::BridgeProofDescriptor> descriptors{
        MakeProofDescriptor(0x91),
        MakeProofDescriptor(0x92),
        MakeProofDescriptor(0x93),
    };
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, 2);
    BOOST_REQUIRE(proof_policy.has_value());

    const auto statement = MakeBatchStatementWithVerifierSetAndProofPolicy(shielded::BridgeDirection::BRIDGE_OUT,
                                                                           9 * COIN,
                                                                           verifier_set,
                                                                           *proof_policy);
    const auto bytes = shielded::SerializeBridgeBatchStatement(statement);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeBatchStatement(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->version, 4U);
    BOOST_CHECK(decoded->verifier_set.attestor_root == verifier_set.attestor_root);
    BOOST_CHECK(decoded->proof_policy.descriptor_root == proof_policy->descriptor_root);
}

BOOST_AUTO_TEST_CASE(bridge_batch_receipt_roundtrips_and_builds_external_anchor)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 7 * COIN);
    const auto receipt_a = MakeSignedBatchReceipt(0x61, statement);
    const auto receipt_b = MakeSignedBatchReceipt(0x62, statement, PQAlgorithm::SLH_DSA_128S);

    const auto bytes = shielded::SerializeBridgeBatchReceipt(receipt_a);
    BOOST_CHECK(!bytes.empty());
    const auto decoded = shielded::DeserializeBridgeBatchReceipt(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(decoded->statement.batch_root == statement.batch_root);
    BOOST_CHECK(decoded->attestor.pubkey == receipt_a.attestor.pubkey);
    BOOST_CHECK(!shielded::ComputeBridgeBatchReceiptHash(receipt_a).IsNull());

    const std::vector<shielded::BridgeBatchReceipt> receipts{receipt_a, receipt_b};
    const auto anchor = shielded::BuildBridgeExternalAnchorFromStatement(statement, receipts);
    BOOST_REQUIRE(anchor.has_value());
    BOOST_CHECK(anchor->domain_id == statement.domain_id);
    BOOST_CHECK_EQUAL(anchor->source_epoch, statement.source_epoch);
    BOOST_CHECK(anchor->data_root == statement.data_root);
    BOOST_CHECK(anchor->verification_root == shielded::ComputeBridgeBatchReceiptRoot(receipts));
}

BOOST_AUTO_TEST_CASE(bridge_batch_receipt_root_is_order_independent)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 7 * COIN);
    const auto receipt_a = MakeSignedBatchReceipt(0x64, statement);
    const auto receipt_b = MakeSignedBatchReceipt(0x65, statement, PQAlgorithm::SLH_DSA_128S);
    const auto receipt_c = MakeSignedBatchReceipt(0x66, statement);

    const std::vector<shielded::BridgeBatchReceipt> receipts_a{receipt_a, receipt_b, receipt_c};
    const std::vector<shielded::BridgeBatchReceipt> receipts_b{receipt_c, receipt_a, receipt_b};

    BOOST_CHECK(shielded::ComputeBridgeBatchReceiptRoot(receipts_a) ==
                shielded::ComputeBridgeBatchReceiptRoot(receipts_b));
}

BOOST_AUTO_TEST_CASE(bridge_batch_receipt_rejects_mismatched_statement)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 5 * COIN);
    auto other_statement = statement;
    other_statement.source_epoch += 1;
    const auto receipt = MakeSignedBatchReceipt(0x63, other_statement);
    const std::vector<shielded::BridgeBatchReceipt> receipts{receipt};
    BOOST_CHECK(!shielded::BuildBridgeExternalAnchorFromStatement(statement, receipts).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_batch_receipt_rejects_duplicate_attestor)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 6 * COIN);
    const auto receipt = MakeSignedBatchReceipt(0x67, statement);
    const std::vector<shielded::BridgeBatchReceipt> receipts{receipt, receipt};

    BOOST_CHECK_EQUAL(shielded::CountDistinctBridgeBatchReceiptAttestors(receipts), 1U);
    BOOST_CHECK(!shielded::BuildBridgeExternalAnchorFromStatement(statement, receipts).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_proof_receipt_roundtrips_and_builds_external_anchor)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 8 * COIN);
    const auto receipt_a = MakeProofReceipt(0x90, statement);
    const auto receipt_b = MakeProofReceipt(0xa0, statement);

    const auto bytes = shielded::SerializeBridgeProofReceipt(receipt_a);
    BOOST_CHECK(!bytes.empty());
    const auto decoded = shielded::DeserializeBridgeProofReceipt(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(decoded->statement_hash == receipt_a.statement_hash);
    BOOST_CHECK(decoded->proof_system_id == receipt_a.proof_system_id);
    BOOST_CHECK(!shielded::ComputeBridgeProofReceiptHash(receipt_a).IsNull());

    const std::vector<shielded::BridgeProofReceipt> receipts{receipt_a, receipt_b};
    const auto anchor = shielded::BuildBridgeExternalAnchorFromProofReceipts(statement, receipts);
    BOOST_REQUIRE(anchor.has_value());
    BOOST_CHECK(anchor->domain_id == statement.domain_id);
    BOOST_CHECK_EQUAL(anchor->source_epoch, statement.source_epoch);
    BOOST_CHECK(anchor->data_root == statement.data_root);
    BOOST_CHECK(anchor->verification_root == shielded::ComputeBridgeProofReceiptRoot(receipts));
}

BOOST_AUTO_TEST_CASE(bridge_proof_claim_builds_external_anchor)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 8 * COIN);
    const auto claim = MakeProofClaim(statement, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);

    const auto anchor = shielded::BuildBridgeExternalAnchorFromClaim(statement, claim);
    BOOST_REQUIRE(anchor.has_value());
    BOOST_CHECK(anchor->domain_id == statement.domain_id);
    BOOST_CHECK_EQUAL(anchor->source_epoch, statement.source_epoch);
    BOOST_CHECK(anchor->data_root == statement.data_root);
    BOOST_CHECK(anchor->verification_root == shielded::ComputeBridgeProofClaimHash(claim));
}

BOOST_AUTO_TEST_CASE(bridge_proof_receipt_root_is_order_independent)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 8 * COIN);
    const auto receipt_a = MakeProofReceipt(0xb0, statement);
    const auto receipt_b = MakeProofReceipt(0xc0, statement);
    const auto receipt_c = MakeProofReceipt(0xd0, statement);

    const std::vector<shielded::BridgeProofReceipt> receipts_a{receipt_a, receipt_b, receipt_c};
    const std::vector<shielded::BridgeProofReceipt> receipts_b{receipt_c, receipt_a, receipt_b};

    BOOST_CHECK(shielded::ComputeBridgeProofReceiptRoot(receipts_a) ==
                shielded::ComputeBridgeProofReceiptRoot(receipts_b));
}

BOOST_AUTO_TEST_CASE(bridge_proof_receipt_rejects_mismatched_statement)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 8 * COIN);
    auto other_statement = statement;
    other_statement.source_epoch += 1;
    const auto receipt = MakeProofReceipt(0xe0, other_statement);
    const std::vector<shielded::BridgeProofReceipt> receipts{receipt};
    BOOST_CHECK(!shielded::BuildBridgeExternalAnchorFromProofReceipts(statement, receipts).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_proof_receipt_rejects_duplicates)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 8 * COIN);
    const auto receipt = MakeProofReceipt(0xf0, statement);
    const std::vector<shielded::BridgeProofReceipt> receipts{receipt, receipt};

    BOOST_CHECK_EQUAL(shielded::CountDistinctBridgeProofReceipts(receipts), 1U);
    BOOST_CHECK(!shielded::BuildBridgeExternalAnchorFromProofReceipts(statement, receipts).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_proof_claim_roundtrips_and_hashes)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 7 * COIN);
    const auto claim = MakeProofClaim(statement, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    const auto bytes = shielded::SerializeBridgeProofClaim(claim);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeProofClaim(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(decoded->kind == claim.kind);
    BOOST_CHECK(decoded->statement_hash == claim.statement_hash);
    BOOST_CHECK(decoded->batch_root == claim.batch_root);
    BOOST_CHECK(decoded->domain_id == claim.domain_id);
    BOOST_CHECK(!shielded::ComputeBridgeProofClaimHash(claim).IsNull());
}

BOOST_AUTO_TEST_CASE(bridge_proof_claim_builds_expected_variants)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 9 * COIN);
    const auto batch_tuple = MakeProofClaim(statement, shielded::BridgeProofClaimKind::BATCH_TUPLE);
    BOOST_CHECK(batch_tuple.domain_id.IsNull());
    BOOST_CHECK_EQUAL(batch_tuple.source_epoch, 0U);
    BOOST_CHECK(batch_tuple.data_root.IsNull());
    BOOST_CHECK(batch_tuple.ids.bridge_id == statement.ids.bridge_id);
    BOOST_CHECK(batch_tuple.ids.operation_id == statement.ids.operation_id);
    BOOST_CHECK_EQUAL(batch_tuple.entry_count, statement.entry_count);

    const auto settlement = MakeProofClaim(statement, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    BOOST_CHECK(settlement.ids.bridge_id == statement.ids.bridge_id);
    BOOST_CHECK(settlement.ids.operation_id == statement.ids.operation_id);
    BOOST_CHECK_EQUAL(settlement.entry_count, statement.entry_count);
    BOOST_CHECK_EQUAL(settlement.total_amount, statement.total_amount);
    BOOST_CHECK(settlement.batch_root == statement.batch_root);
    BOOST_CHECK(settlement.domain_id == statement.domain_id);
    BOOST_CHECK_EQUAL(settlement.source_epoch, statement.source_epoch);
    BOOST_CHECK(settlement.data_root == statement.data_root);

    const auto data_root_tuple = MakeProofClaim(statement, shielded::BridgeProofClaimKind::DATA_ROOT_TUPLE);
    BOOST_CHECK(!data_root_tuple.ids.IsValid());
    BOOST_CHECK_EQUAL(data_root_tuple.entry_count, 0U);
    BOOST_CHECK_EQUAL(data_root_tuple.total_amount, 0);
    BOOST_CHECK(data_root_tuple.batch_root.IsNull());
    BOOST_CHECK(data_root_tuple.domain_id == statement.domain_id);
    BOOST_CHECK_EQUAL(data_root_tuple.source_epoch, statement.source_epoch);
    BOOST_CHECK(data_root_tuple.data_root == statement.data_root);
}

BOOST_AUTO_TEST_CASE(bridge_proof_adapter_roundtrips_and_hashes)
{
    const auto adapter = MakeProofAdapter(0xf4, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    const auto bytes = shielded::SerializeBridgeProofAdapter(adapter);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeProofAdapter(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(decoded->profile.family_id == adapter.profile.family_id);
    BOOST_CHECK(decoded->profile.proof_type_id == adapter.profile.proof_type_id);
    BOOST_CHECK(decoded->profile.claim_system_id == adapter.profile.claim_system_id);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(decoded->claim_kind), static_cast<uint8_t>(adapter.claim_kind));
    BOOST_CHECK(!shielded::ComputeBridgeProofAdapterId(adapter).IsNull());
}

BOOST_AUTO_TEST_CASE(bridge_proof_artifact_roundtrips_and_hashes)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 7 * COIN);
    const auto artifact = MakeProofArtifact(statement, 0xf5, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    const auto bytes = shielded::SerializeBridgeProofArtifact(artifact);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeProofArtifact(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(decoded->adapter.profile.family_id == artifact.adapter.profile.family_id);
    BOOST_CHECK(decoded->statement_hash == artifact.statement_hash);
    BOOST_CHECK(decoded->artifact_commitment == artifact.artifact_commitment);
    BOOST_CHECK_EQUAL(decoded->proof_size_bytes, artifact.proof_size_bytes);
    BOOST_CHECK_EQUAL(decoded->public_values_size_bytes, artifact.public_values_size_bytes);
    BOOST_CHECK_EQUAL(decoded->auxiliary_data_size_bytes, artifact.auxiliary_data_size_bytes);
    BOOST_CHECK_EQUAL(shielded::GetBridgeProofArtifactStorageBytes(artifact), 4704U);
    BOOST_CHECK(!shielded::ComputeBridgeProofArtifactId(artifact).IsNull());
}

BOOST_AUTO_TEST_CASE(bridge_data_artifact_roundtrips_and_hashes)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 7 * COIN);
    const auto artifact = MakeDataArtifact(statement,
                                           0xe1,
                                           shielded::BridgeDataArtifactKind::STATE_DIFF,
                                           2048,
                                           128);
    const auto bytes = shielded::SerializeBridgeDataArtifact(artifact);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeDataArtifact(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(decoded->kind), static_cast<uint8_t>(artifact.kind));
    BOOST_CHECK(decoded->statement_hash == artifact.statement_hash);
    BOOST_CHECK(decoded->data_root == artifact.data_root);
    BOOST_CHECK(decoded->artifact_commitment == artifact.artifact_commitment);
    BOOST_CHECK_EQUAL(decoded->payload_size_bytes, artifact.payload_size_bytes);
    BOOST_CHECK_EQUAL(decoded->auxiliary_data_size_bytes, artifact.auxiliary_data_size_bytes);
    BOOST_CHECK_EQUAL(shielded::GetBridgeDataArtifactStorageBytes(artifact), 2176U);
    BOOST_CHECK(shielded::DoesBridgeDataArtifactMatchStatement(artifact, statement));
    BOOST_CHECK(!shielded::ComputeBridgeDataArtifactId(artifact).IsNull());

    auto other_statement = statement;
    other_statement.source_epoch += 1;
    BOOST_CHECK(!shielded::DoesBridgeDataArtifactMatchStatement(artifact, other_statement));
}

BOOST_AUTO_TEST_CASE(bridge_aggregate_artifact_bundle_aggregates_proof_and_data_bytes)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 64 * COIN);
    const auto proof_a = MakeProofArtifact(statement, 0xe2, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    const auto proof_b = MakeProofArtifact(statement,
                                           0xe3,
                                           shielded::BridgeProofClaimKind::DATA_ROOT_TUPLE,
                                           2048,
                                           64,
                                           256);
    const auto data_a = MakeDataArtifact(statement,
                                         0xe4,
                                         shielded::BridgeDataArtifactKind::STATE_DIFF,
                                         2048,
                                         128);
    const auto data_b = MakeDataArtifact(statement,
                                         0xe5,
                                         shielded::BridgeDataArtifactKind::SNAPSHOT_APPENDIX,
                                         1024,
                                         64);
    const std::array<shielded::BridgeProofArtifact, 2> proof_artifacts{{proof_a, proof_b}};
    const std::array<shielded::BridgeDataArtifact, 2> data_artifacts{{data_a, data_b}};
    const auto bundle = shielded::BuildBridgeAggregateArtifactBundle(
        statement,
        Span<const shielded::BridgeProofArtifact>{proof_artifacts.data(), proof_artifacts.size()},
        Span<const shielded::BridgeDataArtifact>{data_artifacts.data(), data_artifacts.size()});
    BOOST_REQUIRE(bundle.has_value());
    BOOST_CHECK(bundle->statement_hash == shielded::ComputeBridgeBatchStatementHash(statement));
    BOOST_CHECK(!bundle->proof_artifact_root.IsNull());
    BOOST_CHECK(!bundle->data_artifact_root.IsNull());
    BOOST_CHECK_EQUAL(bundle->proof_artifact_count, 2U);
    BOOST_CHECK_EQUAL(bundle->data_artifact_count, 2U);
    BOOST_CHECK_EQUAL(bundle->proof_payload_bytes, 6304U);
    BOOST_CHECK_EQUAL(bundle->proof_auxiliary_bytes, 768U);
    BOOST_CHECK_EQUAL(bundle->data_availability_payload_bytes, 3072U);
    BOOST_CHECK_EQUAL(bundle->data_auxiliary_bytes, 192U);
    BOOST_CHECK_EQUAL(shielded::GetBridgeAggregateArtifactBundleStorageBytes(*bundle), 10336U);

    const auto bytes = shielded::SerializeBridgeAggregateArtifactBundle(*bundle);
    BOOST_CHECK(!bytes.empty());
    const auto decoded = shielded::DeserializeBridgeAggregateArtifactBundle(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(decoded->proof_artifact_root == bundle->proof_artifact_root);
    BOOST_CHECK(decoded->data_artifact_root == bundle->data_artifact_root);
    BOOST_CHECK_EQUAL(decoded->proof_payload_bytes, bundle->proof_payload_bytes);
    BOOST_CHECK_EQUAL(decoded->data_availability_payload_bytes, bundle->data_availability_payload_bytes);
    BOOST_CHECK(!shielded::ComputeBridgeAggregateArtifactBundleId(*bundle).IsNull());

    auto other_statement = statement;
    other_statement.source_epoch += 1;
    BOOST_CHECK(!shielded::BuildBridgeAggregateArtifactBundle(
        other_statement,
        Span<const shielded::BridgeProofArtifact>{proof_artifacts.data(), proof_artifacts.size()},
        Span<const shielded::BridgeDataArtifact>{data_artifacts.data(), data_artifacts.size()}).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_proof_compression_target_roundtrips_and_hashes)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 64 * COIN);
    const auto bundle = MakeArtifactBackedAggregateBundle(statement);
    auto settlement = MakeAggregateSettlement(statement);
    settlement.proof_payload_bytes = bundle.proof_payload_bytes;
    settlement.data_availability_payload_bytes = bundle.data_availability_payload_bytes;
    settlement.auxiliary_offchain_bytes = bundle.proof_auxiliary_bytes + bundle.data_auxiliary_bytes;
    BOOST_REQUIRE(settlement.IsValid());

    const auto target = MakeProofCompressionTarget(settlement, bundle, 12288);
    BOOST_CHECK_EQUAL(target.current_proof_payload_bytes, 393312U);
    BOOST_CHECK_EQUAL(target.current_proof_auxiliary_bytes, 2048U);
    BOOST_CHECK_EQUAL(target.fixed_l1_serialized_bytes, 3692U);
    BOOST_CHECK_EQUAL(target.fixed_l1_weight, 6968U);
    BOOST_CHECK_EQUAL(target.fixed_l1_data_availability_bytes, 8128U);
    BOOST_CHECK_EQUAL(target.target_settlements_per_block, 192U);
    BOOST_CHECK_EQUAL(target.proof_artifact_count, 1U);

    const auto bytes = shielded::SerializeBridgeProofCompressionTarget(target);
    BOOST_CHECK(!bytes.empty());
    const auto decoded = shielded::DeserializeBridgeProofCompressionTarget(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(decoded->settlement_id == target.settlement_id);
    BOOST_CHECK_EQUAL(decoded->target_users_per_block, 12288U);
    BOOST_CHECK_EQUAL(decoded->fixed_l1_serialized_bytes, 3692U);
    BOOST_CHECK(!shielded::ComputeBridgeProofCompressionTargetId(target).IsNull());
}

BOOST_AUTO_TEST_CASE(bridge_proof_compression_target_detects_da_lane_ceiling)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 64 * COIN);
    const auto bundle = MakeArtifactBackedAggregateBundle(statement);
    auto settlement = MakeAggregateSettlement(statement);
    settlement.proof_payload_bytes = bundle.proof_payload_bytes;
    settlement.data_availability_payload_bytes = bundle.data_availability_payload_bytes;
    settlement.auxiliary_offchain_bytes = bundle.proof_auxiliary_bytes + bundle.data_auxiliary_bytes;
    BOOST_REQUIRE(settlement.IsValid());

    const auto target = MakeProofCompressionTarget(settlement, bundle, 8418);
    const auto estimate = shielded::EstimateBridgeProofCompression(target);
    BOOST_REQUIRE(estimate.has_value());
    BOOST_CHECK(!estimate->achievable);
    BOOST_CHECK_EQUAL(estimate->current_capacity.users_per_block, 3776U);
    BOOST_CHECK_EQUAL(estimate->zero_proof_capacity.users_per_block, 6144U);
    BOOST_CHECK_EQUAL(estimate->zero_proof_capacity.binding_limit, shielded::BridgeCapacityBinding::DATA_AVAILABILITY);
    BOOST_CHECK(!estimate->required_max_proof_payload_bytes.has_value());
    BOOST_CHECK(!estimate->required_proof_payload_reduction_bytes.has_value());
}

BOOST_AUTO_TEST_CASE(bridge_proof_compression_target_quantifies_validium_envelope)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 64 * COIN);
    const auto bundle = MakeArtifactBackedAggregateBundle(statement);
    auto settlement = MakeAggregateSettlement(statement);
    settlement.proof_payload_bytes = bundle.proof_payload_bytes;
    settlement.data_availability_payload_bytes = bundle.data_availability_payload_bytes;
    settlement.auxiliary_offchain_bytes = bundle.proof_auxiliary_bytes + bundle.data_auxiliary_bytes;
    settlement.data_availability_location = shielded::BridgeAggregatePayloadLocation::OFFCHAIN;
    BOOST_REQUIRE(settlement.IsValid());

    const auto target = MakeProofCompressionTarget(settlement, bundle, 12288);
    const auto estimate = shielded::EstimateBridgeProofCompression(target);
    BOOST_REQUIRE(estimate.has_value());
    BOOST_REQUIRE(estimate->achievable);
    BOOST_REQUIRE(estimate->required_max_proof_payload_bytes.has_value());
    BOOST_REQUIRE(estimate->required_proof_payload_reduction_bytes.has_value());
    BOOST_REQUIRE(estimate->modeled_target_capacity.has_value());
    BOOST_REQUIRE(estimate->max_proof_payload_bytes_by_serialized_size.has_value());
    BOOST_REQUIRE(estimate->max_proof_payload_bytes_by_weight.has_value());
    BOOST_CHECK_EQUAL(estimate->current_capacity.users_per_block, 3776U);
    BOOST_CHECK_EQUAL(estimate->zero_proof_capacity.users_per_block, 220416U);
    BOOST_CHECK_EQUAL(*estimate->required_max_proof_payload_bytes, 118032U);
    BOOST_CHECK_EQUAL(*estimate->required_proof_payload_reduction_bytes, 275280U);
    BOOST_CHECK_EQUAL(*estimate->max_proof_payload_bytes_by_serialized_size, 121308U);
    BOOST_CHECK_EQUAL(*estimate->max_proof_payload_bytes_by_weight, 118032U);
    BOOST_CHECK_EQUAL(estimate->target_binding_limit, shielded::BridgeCapacityBinding::WEIGHT);
    BOOST_CHECK_EQUAL(estimate->modeled_target_capacity->max_settlements_per_block, 192U);
    BOOST_CHECK_EQUAL(estimate->modeled_target_capacity->users_per_block, 12288U);
}

BOOST_AUTO_TEST_CASE(bridge_proof_descriptor_builds_from_adapter)
{
    const auto adapter = MakeProofAdapter(0xf5, shielded::BridgeProofClaimKind::BATCH_TUPLE);
    const auto descriptor = shielded::BuildBridgeProofDescriptorFromAdapter(adapter, uint256{0xf6});
    BOOST_REQUIRE(descriptor.has_value());
    BOOST_CHECK(descriptor->proof_system_id == shielded::ComputeBridgeProofSystemId(adapter.profile));
    BOOST_CHECK_EQUAL(descriptor->verifier_key_hash, uint256{0xf6});
}

BOOST_AUTO_TEST_CASE(bridge_proof_descriptor_builds_from_artifact)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 7 * COIN);
    const auto artifact = MakeProofArtifact(statement, 0xf6, shielded::BridgeProofClaimKind::BATCH_TUPLE);
    const auto descriptor = shielded::BuildBridgeProofDescriptorFromArtifact(artifact);
    BOOST_REQUIRE(descriptor.has_value());
    BOOST_CHECK(descriptor->proof_system_id == shielded::ComputeBridgeProofSystemId(artifact.adapter.profile));
    BOOST_CHECK(descriptor->verifier_key_hash == artifact.verifier_key_hash);
}

BOOST_AUTO_TEST_CASE(bridge_proof_receipt_builds_from_profile)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 7 * COIN);
    const auto profile = MakeProofSystemProfile(0xf0);
    const auto receipt = shielded::BuildBridgeProofReceiptFromProfile(statement,
                                                                      profile,
                                                                      uint256{0xf3},
                                                                      uint256{0xf4},
                                                                      uint256{0xf5});
    BOOST_REQUIRE(receipt.has_value());
    BOOST_CHECK(receipt->statement_hash == shielded::ComputeBridgeBatchStatementHash(statement));
    BOOST_CHECK(receipt->proof_system_id == shielded::ComputeBridgeProofSystemId(profile));
    BOOST_CHECK_EQUAL(receipt->verifier_key_hash, uint256{0xf3});
}

BOOST_AUTO_TEST_CASE(bridge_proof_receipt_builds_from_profile_and_claim)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 7 * COIN);
    const auto profile = MakeProofSystemProfile(0xf6);
    const auto claim = MakeProofClaim(statement, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    const auto receipt = shielded::BuildBridgeProofReceiptFromProfile(statement,
                                                                      profile,
                                                                      uint256{0xf7},
                                                                      claim,
                                                                      uint256{0xf8});
    BOOST_REQUIRE(receipt.has_value());
    BOOST_CHECK_EQUAL(receipt->public_values_hash, shielded::ComputeBridgeProofClaimHash(claim));

    auto other_statement = statement;
    other_statement.source_epoch += 1;
    BOOST_CHECK(!shielded::BuildBridgeProofReceiptFromProfile(other_statement,
                                                              profile,
                                                              uint256{0xf7},
                                                              claim,
                                                              uint256{0xf8}).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_proof_receipt_builds_from_adapter)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 7 * COIN);
    const auto adapter = MakeProofAdapter(0xf9, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    const auto receipt = shielded::BuildBridgeProofReceiptFromAdapter(statement, adapter, uint256{0xfa}, uint256{0xfb});
    BOOST_REQUIRE(receipt.has_value());
    BOOST_CHECK(receipt->proof_system_id == shielded::ComputeBridgeProofSystemId(adapter.profile));

    const auto claim = shielded::BuildBridgeProofClaimFromAdapter(statement, adapter);
    BOOST_REQUIRE(claim.has_value());
    BOOST_CHECK_EQUAL(receipt->public_values_hash, shielded::ComputeBridgeProofClaimHash(*claim));
}

BOOST_AUTO_TEST_CASE(bridge_proof_receipt_builds_from_artifact)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 7 * COIN);
    const auto artifact = MakeProofArtifact(statement, 0xfa, shielded::BridgeProofClaimKind::SETTLEMENT_METADATA);
    const auto receipt = shielded::BuildBridgeProofReceiptFromArtifact(artifact);
    BOOST_REQUIRE(receipt.has_value());
    BOOST_CHECK(receipt->statement_hash == artifact.statement_hash);
    BOOST_CHECK(receipt->verifier_key_hash == artifact.verifier_key_hash);
    BOOST_CHECK(receipt->public_values_hash == artifact.public_values_hash);
    BOOST_CHECK(receipt->proof_commitment == artifact.proof_commitment);
    BOOST_CHECK(shielded::DoesBridgeProofArtifactMatchStatement(artifact, statement));

    auto other_statement = statement;
    other_statement.source_epoch += 1;
    BOOST_CHECK(!shielded::DoesBridgeProofArtifactMatchStatement(artifact, other_statement));
}

BOOST_AUTO_TEST_CASE(bridge_aggregate_settlement_roundtrips_and_derives_footprint)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 64 * COIN);
    const auto settlement = MakeAggregateSettlement(statement);
    const auto bytes = shielded::SerializeBridgeAggregateSettlement(settlement);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeAggregateSettlement(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(decoded->statement_hash == settlement.statement_hash);
    BOOST_CHECK_EQUAL(decoded->batched_user_count, settlement.batched_user_count);
    BOOST_CHECK_EQUAL(decoded->new_wallet_count, settlement.new_wallet_count);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(decoded->proof_payload_location),
                      static_cast<uint8_t>(settlement.proof_payload_location));
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(decoded->data_availability_location),
                      static_cast<uint8_t>(settlement.data_availability_location));
    BOOST_CHECK(!shielded::ComputeBridgeAggregateSettlementId(settlement).IsNull());

    const auto footprint = shielded::BuildBridgeAggregateSettlementFootprint(settlement);
    BOOST_REQUIRE(footprint.has_value());
    BOOST_CHECK_EQUAL(footprint->l1_serialized_bytes, 20076U);
    BOOST_CHECK_EQUAL(footprint->l1_weight, 23352U);
    BOOST_CHECK_EQUAL(footprint->l1_data_availability_bytes, 4096U);
    BOOST_CHECK_EQUAL(footprint->control_plane_bytes, 320U);
    BOOST_CHECK_EQUAL(footprint->offchain_storage_bytes, 1024U);
    BOOST_CHECK_EQUAL(footprint->batched_user_count, 64U);
}

BOOST_AUTO_TEST_CASE(bridge_capacity_estimate_respects_weight_limit)
{
    const auto native = MakeCapacityFootprint(/*l1_serialized_bytes=*/586196,
                                              /*l1_weight=*/2344784,
                                              /*batched_user_count=*/1);
    const auto estimate = shielded::EstimateBridgeCapacity(native, 24000000, 24000000);
    BOOST_REQUIRE(estimate.has_value());
    BOOST_CHECK_EQUAL(estimate->fit_by_serialized_size, 40U);
    BOOST_CHECK_EQUAL(estimate->fit_by_weight, 10U);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(estimate->binding_limit),
                      static_cast<uint8_t>(shielded::BridgeCapacityBinding::WEIGHT));
    BOOST_CHECK_EQUAL(estimate->max_settlements_per_block, 10U);
    BOOST_CHECK_EQUAL(estimate->users_per_block, 10U);
    BOOST_CHECK_EQUAL(estimate->total_l1_serialized_bytes, 5861960U);
    BOOST_CHECK_EQUAL(estimate->total_l1_weight, 23447840U);
}

BOOST_AUTO_TEST_CASE(bridge_capacity_estimate_scales_batched_users_and_offchain_storage)
{
    const auto footprint = MakeCapacityFootprint(/*l1_serialized_bytes=*/2800,
                                                 /*l1_weight=*/11200,
                                                 /*batched_user_count=*/3,
                                                 /*l1_data_availability_bytes=*/0,
                                                 /*control_plane_bytes=*/661,
                                                 /*offchain_storage_bytes=*/801000);
    const auto estimate = shielded::EstimateBridgeCapacity(footprint, 24000000, 24000000);
    BOOST_REQUIRE(estimate.has_value());
    BOOST_CHECK_EQUAL(estimate->fit_by_serialized_size, 8571U);
    BOOST_CHECK_EQUAL(estimate->fit_by_weight, 2142U);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(estimate->binding_limit),
                      static_cast<uint8_t>(shielded::BridgeCapacityBinding::WEIGHT));
    BOOST_CHECK_EQUAL(estimate->max_settlements_per_block, 2142U);
    BOOST_CHECK_EQUAL(estimate->users_per_block, 6426U);
    BOOST_CHECK_EQUAL(estimate->total_l1_serialized_bytes, 5997600U);
    BOOST_CHECK_EQUAL(estimate->total_l1_weight, 23990400U);
    BOOST_CHECK_EQUAL(estimate->total_control_plane_bytes, 1415862U);
    BOOST_CHECK_EQUAL(estimate->total_offchain_storage_bytes, 1715742000U);
}

BOOST_AUTO_TEST_CASE(bridge_capacity_estimate_supports_data_availability_limit)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 64 * COIN);
    const auto settlement = MakeAggregateSettlement(statement);
    const auto footprint = shielded::BuildBridgeAggregateSettlementFootprint(settlement);
    BOOST_REQUIRE(footprint.has_value());

    BOOST_CHECK(!shielded::EstimateBridgeCapacity(*footprint, 24000000, 24000000).has_value());

    const auto estimate = shielded::EstimateBridgeCapacity(*footprint, 24000000, 24000000, 786432);
    BOOST_REQUIRE(estimate.has_value());
    BOOST_REQUIRE(estimate->fit_by_data_availability.has_value());
    BOOST_CHECK_EQUAL(estimate->fit_by_serialized_size, 1195U);
    BOOST_CHECK_EQUAL(estimate->fit_by_weight, 1027U);
    BOOST_CHECK_EQUAL(*estimate->fit_by_data_availability, 192U);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(estimate->binding_limit),
                      static_cast<uint8_t>(shielded::BridgeCapacityBinding::DATA_AVAILABILITY));
    BOOST_CHECK_EQUAL(estimate->max_settlements_per_block, 192U);
    BOOST_CHECK_EQUAL(estimate->users_per_block, 12288U);
    BOOST_CHECK_EQUAL(estimate->total_l1_data_availability_bytes, 786432U);
    BOOST_CHECK_EQUAL(estimate->total_l1_serialized_bytes, 3854592U);
    BOOST_CHECK_EQUAL(estimate->total_l1_weight, 4483584U);
}

BOOST_AUTO_TEST_CASE(bridge_shielded_state_profile_roundtrips_and_hashes)
{
    const auto profile = MakeShieldedStateProfile(/*wallet_materialization_bytes=*/96);
    const auto bytes = shielded::SerializeBridgeShieldedStateProfile(profile);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeShieldedStateProfile(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->commitment_index_key_bytes, profile.commitment_index_key_bytes);
    BOOST_CHECK_EQUAL(decoded->nullifier_cache_bytes, profile.nullifier_cache_bytes);
    BOOST_CHECK_EQUAL(decoded->wallet_materialization_bytes, 96U);
    BOOST_CHECK(!shielded::ComputeBridgeShieldedStateProfileId(profile).IsNull());
}

BOOST_AUTO_TEST_CASE(bridge_shielded_state_growth_estimate_tracks_persistent_snapshot_and_cache_pressure)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 64 * COIN);
    const auto settlement = MakeAggregateSettlement(statement);
    const auto footprint = shielded::BuildBridgeAggregateSettlementFootprint(settlement);
    BOOST_REQUIRE(footprint.has_value());
    const auto capacity = shielded::EstimateBridgeCapacity(*footprint, 24000000, 24000000, 786432);
    BOOST_REQUIRE(capacity.has_value());
    BOOST_CHECK_EQUAL(capacity->max_settlements_per_block, 192U);

    const auto default_profile = MakeShieldedStateProfile();
    const auto default_estimate = shielded::EstimateBridgeShieldedStateGrowth(settlement,
                                                                              default_profile,
                                                                              *capacity,
                                                                              90000);
    BOOST_REQUIRE(default_estimate.has_value());
    BOOST_CHECK_EQUAL(default_estimate->note_commitments_per_settlement, 64U);
    BOOST_CHECK_EQUAL(default_estimate->nullifiers_per_settlement, 64U);
    BOOST_CHECK_EQUAL(default_estimate->new_wallets_per_settlement, 24U);
    BOOST_CHECK_EQUAL(default_estimate->commitment_index_bytes_per_settlement, 2624U);
    BOOST_CHECK_EQUAL(default_estimate->nullifier_index_bytes_per_settlement, 2176U);
    BOOST_CHECK_EQUAL(default_estimate->snapshot_appendix_bytes_per_settlement, 4096U);
    BOOST_CHECK_EQUAL(default_estimate->wallet_materialization_bytes_per_settlement, 0U);
    BOOST_CHECK_EQUAL(default_estimate->persistent_state_bytes_per_settlement, 4800U);
    BOOST_CHECK_EQUAL(default_estimate->hot_cache_bytes_per_settlement, 6144U);
    BOOST_CHECK_EQUAL(default_estimate->bounded_state_bytes, 800U);
    BOOST_CHECK_EQUAL(default_estimate->note_commitments_per_block, 12288U);
    BOOST_CHECK_EQUAL(default_estimate->nullifiers_per_block, 12288U);
    BOOST_CHECK_EQUAL(default_estimate->new_wallets_per_block, 4608U);
    BOOST_CHECK_EQUAL(default_estimate->persistent_state_bytes_per_block, 921600U);
    BOOST_CHECK_EQUAL(default_estimate->snapshot_appendix_bytes_per_block, 786432U);
    BOOST_CHECK_EQUAL(default_estimate->hot_cache_bytes_per_block, 1179648U);
    BOOST_CHECK_EQUAL(default_estimate->note_commitments_per_hour, 491520U);
    BOOST_CHECK_EQUAL(default_estimate->nullifiers_per_hour, 491520U);
    BOOST_CHECK_EQUAL(default_estimate->new_wallets_per_hour, 184320U);
    BOOST_CHECK_EQUAL(default_estimate->persistent_state_bytes_per_hour, 36864000U);
    BOOST_CHECK_EQUAL(default_estimate->snapshot_appendix_bytes_per_hour, 31457280U);
    BOOST_CHECK_EQUAL(default_estimate->hot_cache_bytes_per_hour, 47185920U);
    BOOST_CHECK_EQUAL(default_estimate->persistent_state_bytes_per_day, 884736000U);
    BOOST_CHECK_EQUAL(default_estimate->snapshot_appendix_bytes_per_day, 754974720U);
    BOOST_CHECK_EQUAL(default_estimate->hot_cache_bytes_per_day, 1132462080U);

    const auto materialized_profile = MakeShieldedStateProfile(/*wallet_materialization_bytes=*/96);
    const auto materialized_estimate = shielded::EstimateBridgeShieldedStateGrowth(settlement,
                                                                                   materialized_profile,
                                                                                   *capacity,
                                                                                   90000);
    BOOST_REQUIRE(materialized_estimate.has_value());
    BOOST_CHECK_EQUAL(materialized_estimate->wallet_materialization_bytes_per_settlement, 2304U);
    BOOST_CHECK_EQUAL(materialized_estimate->persistent_state_bytes_per_settlement, 7104U);
    BOOST_CHECK_EQUAL(materialized_estimate->persistent_state_bytes_per_block, 1363968U);
    BOOST_CHECK_EQUAL(materialized_estimate->persistent_state_bytes_per_hour, 54558720U);
    BOOST_CHECK_EQUAL(materialized_estimate->persistent_state_bytes_per_day, 1309409280U);
}

BOOST_AUTO_TEST_CASE(bridge_shielded_state_retention_policy_roundtrips_and_hashes)
{
    const auto policy = MakeShieldedStateRetentionPolicy(/*wallet_l1_materialization_bps=*/2500,
                                                         /*retain_commitment_index=*/false,
                                                         /*retain_nullifier_index=*/true,
                                                         /*snapshot_include_commitments=*/false,
                                                         /*snapshot_include_nullifiers=*/true);
    const auto bytes = shielded::SerializeBridgeShieldedStateRetentionPolicy(policy);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeShieldedStateRetentionPolicy(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->wallet_l1_materialization_bps, 2500U);
    BOOST_CHECK_EQUAL(decoded->retain_commitment_index, false);
    BOOST_CHECK_EQUAL(decoded->snapshot_include_commitments, false);
    BOOST_CHECK(!shielded::ComputeBridgeShieldedStateRetentionPolicyId(policy).IsNull());
}

BOOST_AUTO_TEST_CASE(bridge_shielded_state_retention_policy_defaults_match_production_externalized_profile)
{
    const shielded::BridgeShieldedStateRetentionPolicy policy;
    BOOST_CHECK_EQUAL(policy.retain_commitment_index, false);
    BOOST_CHECK_EQUAL(policy.retain_nullifier_index, true);
    BOOST_CHECK_EQUAL(policy.snapshot_include_commitments, false);
    BOOST_CHECK_EQUAL(policy.snapshot_include_nullifiers, true);
    BOOST_CHECK_EQUAL(policy.wallet_l1_materialization_bps,
                      shielded::BridgeShieldedStateRetentionPolicy::PRODUCTION_WALLET_L1_MATERIALIZATION_BPS);
    BOOST_CHECK_EQUAL(policy.snapshot_target_bytes,
                      shielded::BridgeShieldedStateRetentionPolicy::WEEKLY_SNAPSHOT_TARGET_BYTES);
}

BOOST_AUTO_TEST_CASE(bridge_shielded_state_retention_estimate_tracks_full_and_externalized_modes)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 64 * COIN);
    const auto settlement = MakeAggregateSettlement(statement);
    const auto footprint = shielded::BuildBridgeAggregateSettlementFootprint(settlement);
    BOOST_REQUIRE(footprint.has_value());
    const auto capacity = shielded::EstimateBridgeCapacity(*footprint, 24000000, 24000000, 786432);
    BOOST_REQUIRE(capacity.has_value());
    const auto profile = MakeShieldedStateProfile(/*wallet_materialization_bytes=*/96);
    const auto state = shielded::EstimateBridgeShieldedStateGrowth(settlement, profile, *capacity, 90000);
    BOOST_REQUIRE(state.has_value());

    const auto full_policy = MakeShieldedStateRetentionPolicy(/*wallet_l1_materialization_bps=*/10'000,
                                                              /*retain_commitment_index=*/true,
                                                              /*retain_nullifier_index=*/true,
                                                              /*snapshot_include_commitments=*/true,
                                                              /*snapshot_include_nullifiers=*/true,
                                                              /*snapshot_target_bytes=*/4ULL * 1024ULL * 1024ULL * 1024ULL);
    const auto full_retention = shielded::EstimateBridgeShieldedStateRetention(*state, full_policy);
    BOOST_REQUIRE(full_retention.has_value());
    BOOST_CHECK_EQUAL(full_retention->materialized_wallets_per_settlement, 24U);
    BOOST_CHECK_EQUAL(full_retention->deferred_wallets_per_settlement, 0U);
    BOOST_CHECK_EQUAL(full_retention->retained_persistent_state_bytes_per_settlement, 7104U);
    BOOST_CHECK_EQUAL(full_retention->externalized_persistent_state_bytes_per_settlement, 0U);
    BOOST_CHECK_EQUAL(full_retention->deferred_wallet_materialization_bytes_per_settlement, 0U);
    BOOST_CHECK_EQUAL(full_retention->snapshot_export_bytes_per_settlement, 4096U);
    BOOST_CHECK_EQUAL(full_retention->externalized_snapshot_bytes_per_settlement, 0U);
    BOOST_CHECK_EQUAL(full_retention->runtime_hot_cache_bytes_per_settlement, 6144U);
    BOOST_CHECK_EQUAL(full_retention->bounded_snapshot_bytes, 800U);
    BOOST_CHECK_EQUAL(full_retention->retained_persistent_state_bytes_per_block, 1363968U);
    BOOST_CHECK_EQUAL(full_retention->snapshot_export_bytes_per_block, 786432U);
    BOOST_CHECK_EQUAL(full_retention->runtime_hot_cache_bytes_per_block, 1179648U);
    BOOST_CHECK_EQUAL(full_retention->retained_persistent_state_bytes_per_day, 1309409280U);
    BOOST_CHECK_EQUAL(full_retention->snapshot_export_bytes_per_day, 754974720U);
    BOOST_REQUIRE(full_retention->blocks_to_snapshot_target.has_value());
    BOOST_REQUIRE(full_retention->hours_to_snapshot_target.has_value());
    BOOST_REQUIRE(full_retention->days_to_snapshot_target.has_value());
    BOOST_REQUIRE(full_retention->users_to_snapshot_target.has_value());
    BOOST_CHECK_EQUAL(*full_retention->blocks_to_snapshot_target, 5461U);
    BOOST_CHECK_EQUAL(*full_retention->hours_to_snapshot_target, 136U);
    BOOST_CHECK_EQUAL(*full_retention->days_to_snapshot_target, 5U);
    BOOST_CHECK_EQUAL(*full_retention->users_to_snapshot_target, 67104768U);

    const auto externalized_policy = MakeShieldedStateRetentionPolicy();
    const auto externalized_retention = shielded::EstimateBridgeShieldedStateRetention(*state, externalized_policy);
    BOOST_REQUIRE(externalized_retention.has_value());
    BOOST_CHECK_EQUAL(externalized_retention->materialized_wallets_per_settlement, 6U);
    BOOST_CHECK_EQUAL(externalized_retention->deferred_wallets_per_settlement, 18U);
    BOOST_CHECK_EQUAL(externalized_retention->retained_persistent_state_bytes_per_settlement, 2752U);
    BOOST_CHECK_EQUAL(externalized_retention->externalized_persistent_state_bytes_per_settlement, 4352U);
    BOOST_CHECK_EQUAL(externalized_retention->deferred_wallet_materialization_bytes_per_settlement, 1728U);
    BOOST_CHECK_EQUAL(externalized_retention->snapshot_export_bytes_per_settlement, 2048U);
    BOOST_CHECK_EQUAL(externalized_retention->externalized_snapshot_bytes_per_settlement, 2048U);
    BOOST_CHECK_EQUAL(externalized_retention->runtime_hot_cache_bytes_per_settlement, 6144U);
    BOOST_CHECK_EQUAL(externalized_retention->retained_persistent_state_bytes_per_block, 528384U);
    BOOST_CHECK_EQUAL(externalized_retention->externalized_persistent_state_bytes_per_block, 835584U);
    BOOST_CHECK_EQUAL(externalized_retention->deferred_wallet_materialization_bytes_per_block, 331776U);
    BOOST_CHECK_EQUAL(externalized_retention->snapshot_export_bytes_per_block, 393216U);
    BOOST_CHECK_EQUAL(externalized_retention->externalized_snapshot_bytes_per_block, 393216U);
    BOOST_CHECK_EQUAL(externalized_retention->retained_persistent_state_bytes_per_day, 507248640U);
    BOOST_CHECK_EQUAL(externalized_retention->externalized_persistent_state_bytes_per_day, 802160640U);
    BOOST_CHECK_EQUAL(externalized_retention->snapshot_export_bytes_per_day, 377487360U);
    BOOST_REQUIRE(externalized_retention->blocks_to_snapshot_target.has_value());
    BOOST_REQUIRE(externalized_retention->hours_to_snapshot_target.has_value());
    BOOST_REQUIRE(externalized_retention->days_to_snapshot_target.has_value());
    BOOST_REQUIRE(externalized_retention->users_to_snapshot_target.has_value());
    BOOST_CHECK_EQUAL(*externalized_retention->blocks_to_snapshot_target, 6720U);
    BOOST_CHECK_EQUAL(*externalized_retention->hours_to_snapshot_target, 168U);
    BOOST_CHECK_EQUAL(*externalized_retention->days_to_snapshot_target, 7U);
    BOOST_CHECK_EQUAL(*externalized_retention->users_to_snapshot_target, 82575360U);
}

BOOST_AUTO_TEST_CASE(bridge_prover_capacity_estimate_identifies_l1_and_prover_bottlenecks)
{
    const auto footprint = MakeCapacityFootprint(/*l1_serialized_bytes=*/1000,
                                                 /*l1_weight=*/1000,
                                                 /*batched_user_count=*/2);
    const auto l1_capacity = shielded::EstimateBridgeCapacity(footprint, 100000, 100000);
    BOOST_REQUIRE(l1_capacity.has_value());
    BOOST_CHECK_EQUAL(l1_capacity->max_settlements_per_block, 100U);
    BOOST_CHECK_EQUAL(l1_capacity->users_per_block, 200U);

    shielded::BridgeProverFootprint prover;
    prover.block_interval_millis = 10000;
    prover.cpu = MakeProverLane(/*millis_per_settlement=*/500, /*workers=*/1, /*parallel_jobs_per_worker=*/1, /*hourly_cost_cents=*/250);
    prover.gpu = MakeProverLane(/*millis_per_settlement=*/25, /*workers=*/1, /*parallel_jobs_per_worker=*/4, /*hourly_cost_cents=*/1200);
    BOOST_REQUIRE(prover.IsValid());

    const auto estimate = shielded::EstimateBridgeProverCapacity(*l1_capacity, prover);
    BOOST_REQUIRE(estimate.has_value());
    BOOST_CHECK_EQUAL(estimate->l1_settlements_per_hour_limit, 36000U);
    BOOST_CHECK_EQUAL(estimate->l1_users_per_hour_limit, 72000U);

    BOOST_REQUIRE(estimate->cpu.has_value());
    BOOST_CHECK_EQUAL(estimate->cpu->settlements_per_block_interval, 20U);
    BOOST_CHECK_EQUAL(estimate->cpu->users_per_block_interval, 40U);
    BOOST_CHECK_EQUAL(estimate->cpu->sustainable_settlements_per_block, 20U);
    BOOST_CHECK_EQUAL(estimate->cpu->sustainable_users_per_block, 40U);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(estimate->cpu->binding_limit),
                      static_cast<uint8_t>(shielded::BridgeThroughputBinding::PROVER));
    BOOST_CHECK_EQUAL(estimate->cpu->required_parallel_jobs_to_fill_l1_capacity, 5U);
    BOOST_CHECK_EQUAL(estimate->cpu->required_workers_to_fill_l1_capacity, 5U);
    BOOST_CHECK_EQUAL(estimate->cpu->worker_gap_to_fill_l1_capacity, 4U);
    BOOST_CHECK_EQUAL(estimate->cpu->millis_to_fill_l1_capacity, 50000U);
    BOOST_CHECK_EQUAL(estimate->cpu->current_hourly_cost_cents, 250U);
    BOOST_CHECK_EQUAL(estimate->cpu->required_hourly_cost_cents, 1250U);

    BOOST_REQUIRE(estimate->gpu.has_value());
    BOOST_CHECK_EQUAL(estimate->gpu->effective_parallel_jobs, 4U);
    BOOST_CHECK_EQUAL(estimate->gpu->settlements_per_block_interval, 1600U);
    BOOST_CHECK_EQUAL(estimate->gpu->sustainable_settlements_per_block, 100U);
    BOOST_CHECK_EQUAL(estimate->gpu->sustainable_users_per_block, 200U);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(estimate->gpu->binding_limit),
                      static_cast<uint8_t>(shielded::BridgeThroughputBinding::L1));
    BOOST_CHECK_EQUAL(estimate->gpu->required_parallel_jobs_to_fill_l1_capacity, 1U);
    BOOST_CHECK_EQUAL(estimate->gpu->required_workers_to_fill_l1_capacity, 1U);
    BOOST_CHECK_EQUAL(estimate->gpu->worker_gap_to_fill_l1_capacity, 0U);
    BOOST_CHECK_EQUAL(estimate->gpu->millis_to_fill_l1_capacity, 625U);
    BOOST_CHECK_EQUAL(estimate->gpu->current_hourly_cost_cents, 1200U);
    BOOST_CHECK_EQUAL(estimate->gpu->required_hourly_cost_cents, 1200U);
}

BOOST_AUTO_TEST_CASE(bridge_prover_sample_roundtrips_and_hashes)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 5 * COIN);
    const auto sample = MakeProverSample(statement,
                                         0xab,
                                         /*native_millis=*/220,
                                         /*cpu_millis=*/60000,
                                         /*gpu_millis=*/4500,
                                         /*network_millis=*/1500,
                                         /*peak_memory_bytes=*/1073741824);
    const auto bytes = shielded::SerializeBridgeProverSample(sample);
    BOOST_CHECK(!bytes.empty());
    const auto decoded = shielded::DeserializeBridgeProverSample(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(decoded->statement_hash == sample.statement_hash);
    BOOST_CHECK(decoded->proof_artifact_id == sample.proof_artifact_id);
    BOOST_CHECK_EQUAL(decoded->artifact_storage_bytes, sample.artifact_storage_bytes);
    BOOST_CHECK_EQUAL(decoded->cpu_millis, sample.cpu_millis);
    BOOST_CHECK_EQUAL(decoded->peak_memory_bytes, sample.peak_memory_bytes);
    BOOST_CHECK(!shielded::ComputeBridgeProverSampleId(sample).IsNull());
}

BOOST_AUTO_TEST_CASE(bridge_prover_profile_aggregates_samples_and_rejects_duplicates)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 6 * COIN);
    const auto sample_a = MakeProverSample(statement,
                                           0xac,
                                           /*native_millis=*/220,
                                           /*cpu_millis=*/60000,
                                           /*gpu_millis=*/4500,
                                           /*network_millis=*/1500,
                                           /*peak_memory_bytes=*/1073741824);
    const auto sample_b = MakeProverSample(statement,
                                           0xad,
                                           /*native_millis=*/180,
                                           /*cpu_millis=*/72000,
                                           /*gpu_millis=*/4200,
                                           /*network_millis=*/1200,
                                           /*peak_memory_bytes=*/1610612736);
    const auto sample_c = MakeProverSample(statement,
                                           0xae,
                                           /*native_millis=*/250,
                                           /*cpu_millis=*/48000,
                                           /*gpu_millis=*/3300,
                                           /*network_millis=*/1300,
                                           /*peak_memory_bytes=*/805306368);

    const std::array<shielded::BridgeProverSample, 3> samples{sample_a, sample_b, sample_c};
    const auto profile = shielded::BuildBridgeProverProfile(samples);
    BOOST_REQUIRE(profile.has_value());
    BOOST_CHECK_EQUAL(profile->sample_count, 3U);
    BOOST_CHECK(profile->statement_hash == sample_a.statement_hash);
    BOOST_CHECK_EQUAL(profile->native_millis_per_settlement, 650U);
    BOOST_CHECK_EQUAL(profile->cpu_millis_per_settlement, 180000U);
    BOOST_CHECK_EQUAL(profile->gpu_millis_per_settlement, 12000U);
    BOOST_CHECK_EQUAL(profile->network_millis_per_settlement, 4000U);
    BOOST_CHECK_EQUAL(profile->total_peak_memory_bytes, 3489660928U);
    BOOST_CHECK_EQUAL(profile->max_peak_memory_bytes, 1610612736U);
    BOOST_CHECK_EQUAL(profile->total_artifact_storage_bytes,
                      sample_a.artifact_storage_bytes + sample_b.artifact_storage_bytes + sample_c.artifact_storage_bytes);
    BOOST_CHECK(!profile->sample_root.IsNull());
    BOOST_CHECK(!shielded::ComputeBridgeProverProfileId(*profile).IsNull());

    const auto profile_bytes = shielded::SerializeBridgeProverProfile(*profile);
    BOOST_CHECK(!profile_bytes.empty());
    const auto decoded = shielded::DeserializeBridgeProverProfile(profile_bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->cpu_millis_per_settlement, profile->cpu_millis_per_settlement);

    const std::array<shielded::BridgeProverSample, 2> duplicate_samples{sample_a, sample_a};
    BOOST_CHECK(!shielded::BuildBridgeProverProfile(duplicate_samples).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_prover_benchmark_aggregates_profiles_and_selects_percentiles)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 7 * COIN);
    const auto profile_a = MakeProverProfile(statement, 0xb1, 0xb2, 0xb3, 620, 175000, 11500, 3800, 900000000, 1100000000, 700000000);
    const auto profile_b = MakeProverProfile(statement, 0xb4, 0xb5, 0xb6, 640, 178000, 11800, 3900, 920000000, 1110000000, 710000000);
    const auto profile_c = MakeProverProfile(statement, 0xb7, 0xb8, 0xb9, 650, 180000, 12000, 4000, 940000000, 1120000000, 720000000);
    const auto profile_d = MakeProverProfile(statement, 0xba, 0xbb, 0xbc, 660, 182000, 12300, 4200, 960000000, 1130000000, 730000000);
    const auto profile_e = MakeProverProfile(statement, 0xbd, 0xbe, 0xbf, 700, 190000, 13000, 4500, 980000000, 1140000000, 740000000);

    const std::array<shielded::BridgeProverProfile, 5> profiles{profile_a, profile_b, profile_c, profile_d, profile_e};
    const auto benchmark = shielded::BuildBridgeProverBenchmark(profiles);
    BOOST_REQUIRE(benchmark.has_value());
    BOOST_CHECK_EQUAL(benchmark->profile_count, 5U);
    BOOST_CHECK_EQUAL(benchmark->sample_count_per_profile, 3U);
    BOOST_CHECK_EQUAL(benchmark->artifact_storage_bytes_per_profile, profile_a.total_artifact_storage_bytes);
    BOOST_CHECK(!benchmark->profile_root.IsNull());
    BOOST_CHECK_EQUAL(benchmark->native_millis_per_settlement.min, 620U);
    BOOST_CHECK_EQUAL(benchmark->native_millis_per_settlement.p50, 650U);
    BOOST_CHECK_EQUAL(benchmark->native_millis_per_settlement.p90, 700U);
    BOOST_CHECK_EQUAL(benchmark->native_millis_per_settlement.max, 700U);
    BOOST_CHECK_EQUAL(benchmark->cpu_millis_per_settlement.p50, 180000U);
    BOOST_CHECK_EQUAL(benchmark->cpu_millis_per_settlement.p90, 190000U);
    BOOST_CHECK_EQUAL(benchmark->gpu_millis_per_settlement.p50, 12000U);
    BOOST_CHECK_EQUAL(benchmark->gpu_millis_per_settlement.p90, 13000U);
    BOOST_CHECK_EQUAL(benchmark->network_millis_per_settlement.p50, 4000U);
    BOOST_CHECK_EQUAL(benchmark->network_millis_per_settlement.p90, 4500U);
    BOOST_CHECK_EQUAL(shielded::SelectBridgeProverMetric(benchmark->cpu_millis_per_settlement,
                                                         shielded::BridgeProverBenchmarkStatistic::P50),
                      180000U);
    BOOST_CHECK_EQUAL(shielded::SelectBridgeProverMetric(benchmark->cpu_millis_per_settlement,
                                                         shielded::BridgeProverBenchmarkStatistic::P90),
                      190000U);
    BOOST_CHECK(!shielded::ComputeBridgeProverBenchmarkId(*benchmark).IsNull());

    const auto bytes = shielded::SerializeBridgeProverBenchmark(*benchmark);
    BOOST_CHECK(!bytes.empty());
    const auto decoded = shielded::DeserializeBridgeProverBenchmark(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->profile_count, benchmark->profile_count);
    BOOST_CHECK_EQUAL(decoded->network_millis_per_settlement.max, benchmark->network_millis_per_settlement.max);

    const std::array<shielded::BridgeProverProfile, 2> duplicate_profiles{profile_a, profile_a};
    BOOST_CHECK(!shielded::BuildBridgeProverBenchmark(duplicate_profiles).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_prover_capacity_estimate_tracks_parallel_remote_lane)
{
    const auto footprint = MakeCapacityFootprint(/*l1_serialized_bytes=*/4276,
                                                 /*l1_weight=*/4816,
                                                 /*batched_user_count=*/3,
                                                 /*l1_data_availability_bytes=*/0,
                                                 /*control_plane_bytes=*/661,
                                                 /*offchain_storage_bytes=*/801000);
    const auto l1_capacity = shielded::EstimateBridgeCapacity(footprint, 24000000, 24000000);
    BOOST_REQUIRE(l1_capacity.has_value());
    BOOST_CHECK_EQUAL(l1_capacity->max_settlements_per_block, 4983U);
    BOOST_CHECK_EQUAL(l1_capacity->users_per_block, 14949U);

    shielded::BridgeProverFootprint prover;
    prover.block_interval_millis = 90000;
    prover.network = MakeProverLane(/*millis_per_settlement=*/4000, /*workers=*/16, /*parallel_jobs_per_worker=*/8, /*hourly_cost_cents=*/1600);
    BOOST_REQUIRE(prover.IsValid());

    const auto estimate = shielded::EstimateBridgeProverCapacity(*l1_capacity, prover);
    BOOST_REQUIRE(estimate.has_value());
    BOOST_CHECK_EQUAL(estimate->l1_settlements_per_hour_limit, 199320U);
    BOOST_CHECK_EQUAL(estimate->l1_users_per_hour_limit, 597960U);

    BOOST_REQUIRE(estimate->network.has_value());
    BOOST_CHECK_EQUAL(estimate->network->effective_parallel_jobs, 128U);
    BOOST_CHECK_EQUAL(estimate->network->settlements_per_block_interval, 2880U);
    BOOST_CHECK_EQUAL(estimate->network->settlements_per_hour, 115200U);
    BOOST_CHECK_EQUAL(estimate->network->users_per_block_interval, 8640U);
    BOOST_CHECK_EQUAL(estimate->network->users_per_hour, 345600U);
    BOOST_CHECK_EQUAL(estimate->network->sustainable_settlements_per_block, 2880U);
    BOOST_CHECK_EQUAL(estimate->network->sustainable_settlements_per_hour, 115200U);
    BOOST_CHECK_EQUAL(estimate->network->sustainable_users_per_block, 8640U);
    BOOST_CHECK_EQUAL(estimate->network->sustainable_users_per_hour, 345600U);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(estimate->network->binding_limit),
                      static_cast<uint8_t>(shielded::BridgeThroughputBinding::PROVER));
    BOOST_CHECK_EQUAL(estimate->network->required_parallel_jobs_to_fill_l1_capacity, 222U);
    BOOST_CHECK_EQUAL(estimate->network->required_workers_to_fill_l1_capacity, 28U);
    BOOST_CHECK_EQUAL(estimate->network->worker_gap_to_fill_l1_capacity, 12U);
    BOOST_CHECK_EQUAL(estimate->network->millis_to_fill_l1_capacity, 155719U);
    BOOST_CHECK_EQUAL(estimate->network->current_hourly_cost_cents, 25600U);
    BOOST_CHECK_EQUAL(estimate->network->required_hourly_cost_cents, 44800U);
}

BOOST_AUTO_TEST_CASE(bridge_verification_bundle_roundtrips_and_hashes)
{
    const auto bundle = MakeVerificationBundle(0xf2);
    const auto bytes = shielded::SerializeBridgeVerificationBundle(bundle);
    BOOST_CHECK(!bytes.empty());
    const auto decoded = shielded::DeserializeBridgeVerificationBundle(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(decoded->signed_receipt_root == bundle.signed_receipt_root);
    BOOST_CHECK(decoded->proof_receipt_root == bundle.proof_receipt_root);
    BOOST_CHECK(!shielded::ComputeBridgeVerificationBundleHash(bundle).IsNull());
}

BOOST_AUTO_TEST_CASE(bridge_verification_bundle_builds_from_signed_and_proof_receipts)
{
    const auto statement = MakeBatchStatement(shielded::BridgeDirection::BRIDGE_OUT, 8 * COIN);
    const auto receipt_a = MakeSignedBatchReceipt(0x91, statement);
    const auto receipt_b = MakeSignedBatchReceipt(0x92, statement);
    const auto proof_receipt_a = MakeProofReceipt(0x93, statement);
    const auto proof_receipt_b = MakeProofReceipt(0x94, statement);
    const std::vector<shielded::BridgeBatchReceipt> signed_receipts{receipt_a, receipt_b};
    const std::vector<shielded::BridgeProofReceipt> proof_receipts{proof_receipt_a, proof_receipt_b};

    const auto bundle = shielded::BuildBridgeVerificationBundle(
        Span<const shielded::BridgeBatchReceipt>{signed_receipts.data(), signed_receipts.size()},
        Span<const shielded::BridgeProofReceipt>{proof_receipts.data(), proof_receipts.size()});
    BOOST_REQUIRE(bundle.has_value());
    BOOST_CHECK(bundle->signed_receipt_root == shielded::ComputeBridgeBatchReceiptRoot(signed_receipts));
    BOOST_CHECK(bundle->proof_receipt_root == shielded::ComputeBridgeProofReceiptRoot(proof_receipts));
}

BOOST_AUTO_TEST_CASE(bridge_hybrid_anchor_builds_from_signed_and_proof_receipts)
{
    const auto verifier_set = MakeVerifierSetCommitment(0x94, 3, 2);
    const std::vector<shielded::BridgeProofDescriptor> descriptors{
        MakeProofDescriptor(0x95),
        MakeProofDescriptor(0x96),
        MakeProofDescriptor(0x97),
    };
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, 2);
    BOOST_REQUIRE(proof_policy.has_value());

    const auto statement = MakeBatchStatementWithVerifierSetAndProofPolicy(shielded::BridgeDirection::BRIDGE_OUT,
                                                                           8 * COIN,
                                                                           verifier_set,
                                                                           *proof_policy);
    const auto receipt_a = MakeSignedBatchReceipt(0x98, statement);
    const auto receipt_b = MakeSignedBatchReceipt(0x99, statement);
    const auto proof_receipt_a = MakeProofReceipt(0x9a, statement);
    const auto proof_receipt_b = MakeProofReceipt(0x9b, statement);

    const std::vector<shielded::BridgeBatchReceipt> receipts{receipt_a, receipt_b};
    const std::vector<shielded::BridgeProofReceipt> proof_receipts{proof_receipt_a, proof_receipt_b};
    const auto anchor = shielded::BuildBridgeExternalAnchorFromHybridWitness(statement, receipts, proof_receipts);
    BOOST_REQUIRE(anchor.has_value());

    shielded::BridgeVerificationBundle bundle;
    bundle.signed_receipt_root = shielded::ComputeBridgeBatchReceiptRoot(receipts);
    bundle.proof_receipt_root = shielded::ComputeBridgeProofReceiptRoot(proof_receipts);
    BOOST_REQUIRE(bundle.IsValid());
    BOOST_CHECK(anchor->verification_root == shielded::ComputeBridgeVerificationBundleHash(bundle));
}

BOOST_AUTO_TEST_CASE(bridge_pure_anchor_builders_reject_hybrid_statement)
{
    const auto verifier_set = MakeVerifierSetCommitment(0x9c, 3, 2);
    const std::vector<shielded::BridgeProofDescriptor> descriptors{
        MakeProofDescriptor(0x9d),
        MakeProofDescriptor(0x9e),
    };
    const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, 1);
    BOOST_REQUIRE(proof_policy.has_value());

    const auto statement = MakeBatchStatementWithVerifierSetAndProofPolicy(shielded::BridgeDirection::BRIDGE_OUT,
                                                                           8 * COIN,
                                                                           verifier_set,
                                                                           *proof_policy);
    const auto receipt = MakeSignedBatchReceipt(0x9f, statement);
    const auto proof_receipt = MakeProofReceipt(0xa0, statement);
    BOOST_CHECK(!shielded::BuildBridgeExternalAnchorFromStatement(statement, std::vector<shielded::BridgeBatchReceipt>{receipt}).has_value());
    BOOST_CHECK(!shielded::BuildBridgeExternalAnchorFromProofReceipts(statement, std::vector<shielded::BridgeProofReceipt>{proof_receipt}).has_value());
}

BOOST_AUTO_TEST_CASE(bridge_attestation_v3_carries_external_anchor)
{
    auto message = MakeAttestation();
    const auto commitment = MakeBatchCommitment(shielded::BridgeDirection::BRIDGE_OUT, 9 * COIN);
    message.version = 3;
    message.batch_entry_count = commitment.entry_count;
    message.batch_total_amount = commitment.total_amount;
    message.batch_root = commitment.batch_root;
    message.external_anchor = MakeExternalAnchor();
    BOOST_REQUIRE(shielded::IsWellFormedBridgeAttestation(message));

    const auto bytes = shielded::SerializeBridgeAttestationMessage(message);
    BOOST_CHECK_EQUAL(bytes.size(), 279U);

    const auto decoded = shielded::DeserializeBridgeAttestationMessage(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(decoded->version, 3U);
    BOOST_CHECK(decoded->external_anchor.domain_id == message.external_anchor.domain_id);
    BOOST_CHECK_EQUAL(decoded->external_anchor.source_epoch, message.external_anchor.source_epoch);
    BOOST_CHECK(decoded->external_anchor.data_root == message.external_anchor.data_root);
    BOOST_CHECK(decoded->external_anchor.verification_root == message.external_anchor.verification_root);
}

BOOST_AUTO_TEST_CASE(bridge_batch_authorization_roundtrips_and_derives_leaf)
{
    const auto authorization = MakeSignedBatchAuthorization(0x41, shielded::BridgeDirection::BRIDGE_OUT, 7 * COIN);
    const auto bytes = shielded::SerializeBridgeBatchAuthorization(authorization);
    BOOST_CHECK(!bytes.empty());

    const auto decoded = shielded::DeserializeBridgeBatchAuthorization(bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(decoded->direction == authorization.direction);
    BOOST_CHECK(decoded->ids.bridge_id == authorization.ids.bridge_id);
    BOOST_CHECK(decoded->authorization_nonce == authorization.authorization_nonce);

    const uint256 authorization_hash = shielded::ComputeBridgeBatchAuthorizationHash(authorization);
    BOOST_CHECK(!authorization_hash.IsNull());
    BOOST_CHECK(shielded::VerifyBridgeBatchAuthorization(authorization));

    const auto leaf = shielded::BuildBridgeBatchLeafFromAuthorization(authorization);
    BOOST_REQUIRE(leaf.has_value());
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(leaf->kind), static_cast<uint8_t>(authorization.kind));
    BOOST_CHECK(leaf->wallet_id == authorization.wallet_id);
    BOOST_CHECK(leaf->destination_id == authorization.destination_id);
    BOOST_CHECK_EQUAL(leaf->amount, authorization.amount);
    BOOST_CHECK(leaf->authorization_hash == authorization_hash);
}

BOOST_AUTO_TEST_CASE(bridge_batch_authorization_hash_excludes_signature_bytes)
{
    const auto authorization = MakeSignedBatchAuthorization(0x51, shielded::BridgeDirection::BRIDGE_IN, 3 * COIN);
    const uint256 base_hash = shielded::ComputeBridgeBatchAuthorizationHash(authorization);
    BOOST_CHECK(!base_hash.IsNull());

    auto mutated = authorization;
    BOOST_REQUIRE(!mutated.signature.empty());
    mutated.signature.assign(mutated.signature.size(), 0x00);

    BOOST_CHECK(base_hash == shielded::ComputeBridgeBatchAuthorizationHash(mutated));
    BOOST_CHECK(!shielded::VerifyBridgeBatchAuthorization(mutated));
    BOOST_CHECK(!mutated.IsValid());
}

BOOST_AUTO_TEST_CASE(bridge_batch_authorization_tags_leaf_ids_after_activation)
{
    const auto authorization = MakeSignedBatchAuthorization(0x61, shielded::BridgeDirection::BRIDGE_OUT, 5 * COIN);
    const int32_t activation_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;

    const auto pre_activation_leaf = shielded::BuildBridgeBatchLeafFromAuthorization(
        authorization,
        activation_height - 1);
    BOOST_REQUIRE(pre_activation_leaf.has_value());
    BOOST_CHECK(pre_activation_leaf->wallet_id == authorization.wallet_id);
    BOOST_CHECK(pre_activation_leaf->destination_id == authorization.destination_id);

    const auto post_activation_leaf = shielded::BuildBridgeBatchLeafFromAuthorization(
        authorization,
        activation_height);
    BOOST_REQUIRE(post_activation_leaf.has_value());
    BOOST_CHECK(post_activation_leaf->wallet_id != authorization.wallet_id);
    BOOST_CHECK(post_activation_leaf->destination_id != authorization.destination_id);
    BOOST_CHECK(post_activation_leaf->wallet_id ==
                shielded::ComputeBridgeBatchLeafWalletTag(authorization, activation_height));
    BOOST_CHECK(post_activation_leaf->destination_id ==
                shielded::ComputeBridgeBatchLeafDestinationTag(authorization, activation_height));
}

BOOST_AUTO_TEST_SUITE_END()
