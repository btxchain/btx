// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rpc/register.h>

#include <chain.h>
#include <kernel/chainstatemanager_opts.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/matmul_trusted_attestations.h>
#include <protocol.h>
#include <pubkey.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <streams.h>
#include <sync.h>
#include <util/strencodings.h>
#include <validation.h>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

using node::NodeContext;

namespace {

UniValue PubKeysJSON(const std::vector<CPubKey>& pubkeys)
{
    UniValue keys{UniValue::VARR};
    for (const auto& pubkey : pubkeys) {
        keys.push_back(HexStr(pubkey));
    }
    return keys;
}

UniValue TrustedSignerPubKeysJSON()
{
    return PubKeysJSON(node::matmul_trusted::TrustedSigners());
}

CPubKey ParseCompressedPubKeyHex(const std::string& encoded)
{
    if (!IsHex(encoded)) {
        throw JSONRPCError(
            RPC_INVALID_ADDRESS_OR_KEY,
            "Pubkey must be compressed secp256k1 hex");
    }
    const CPubKey pubkey{ParseHex(encoded)};
    if (!pubkey.IsCompressed() || !pubkey.IsFullyValid()) {
        throw JSONRPCError(
            RPC_INVALID_ADDRESS_OR_KEY,
            "Pubkey must be a valid compressed secp256k1 key");
    }
    return pubkey;
}

UniValue BlocklistStatusJSON()
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("blocked_pubkeys",
                  PubKeysJSON(node::matmul_trusted::BlockedSigners()));
    result.pushKV(
        "unblocked_pin_members",
        static_cast<uint64_t>(node::matmul_trusted::UnblockedPinMembers()));
    result.pushKV(
        "threshold",
        static_cast<uint64_t>(node::matmul_trusted::Threshold()));
    result.pushKV("pin_quorum_reachable",
                  node::matmul_trusted::PinQuorumReachable());
    result.pushKV("fail_closed", true);
    result.pushKV("persisted", node::matmul_trusted::PersistenceEnabled());
    return result;
}

std::string EncodeAttestation(
    const matmul::trusted::ExactReplayAttestation& attestation)
{
    DataStream encoded;
    encoded << attestation;
    return HexStr(encoded);
}

bool DecodeAttestation(
    const std::string& hex,
    matmul::trusted::ExactReplayAttestation& attestation)
{
    if (!IsHex(hex)) return false;
    try {
        DataStream encoded{ParseHex(hex)};
        encoded >> attestation;
        return encoded.empty();
    } catch (const std::ios_base::failure&) {
        return false;
    }
}

struct KnownAttestationBlock {
    int32_t height{-1};
    bool local_exact{false};
    bool on_active_chain{false};
};

std::optional<KnownAttestationBlock> LookupAttestationBlock(
    ChainstateManager& chainman, const uint256& hash)
{
    LOCK(cs_main);
    const CBlockIndex* index{
        chainman.m_blockman.LookupBlockIndex(hash)};
    if (index == nullptr ||
        (index->nStatus & BLOCK_FAILED_MASK) ||
        !chainman.GetConsensus().IsMatMulTrustedReplayAttestationActive(
            index->nHeight)) {
        return std::nullopt;
    }
    return KnownAttestationBlock{
        index->nHeight,
        (index->nStatus &
         BLOCK_EXACT_REPLAY_VERIFIED) != 0,
        chainman.ActiveChain().Contains(index)};
}

RPCHelpMan getmatmultrustedstatus()
{
    return RPCHelpMan{
        "getmatmultrustedstatus",
        "Return trusted ExactReplay signer/quorum and bounded-store status.\n"
        "A trusted mirror validates normal block bodies/scripts but is not an "
        "independent MatMul consensus validator.",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "configured", ""},
                {RPCResult::Type::STR, "matmul_validation_mode", /*optional=*/true, "consensus, trusted, relay, economic, or spv when chainstate is available"},
                {RPCResult::Type::BOOL, "trusted_mirror", ""},
                {RPCResult::Type::BOOL, "discovery_relay", "True when -matmulvalidation=relay: ADDR introduction only, not MatMul authority"},
                {RPCResult::Type::BOOL, "chain_oracle", "True only for consensus and trusted modes. False on a discovery relay."},
                {RPCResult::Type::BOOL, "serves_attestations", ""},
                {RPCResult::Type::BOOL, "local_signer", ""},
                {RPCResult::Type::BOOL, "single_key_pin", "True when configured M<2 or N<2. On a trusted mirror this is ExactReplay-skip authority; on consensus+pin it is telemetry only."},
                {RPCResult::Type::BOOL, "single_key_trusted_authority", "Trusted mirror whose quorum can skip ExactReplay with one key (N<2 or M<2)"},
                {RPCResult::Type::BOOL, "collocated_signer_pin", "Local attestation WIF is also a pin member in a single-key or trusted-mirror topology (stolen keyfile amplifier)"},
                {RPCResult::Type::NUM, "attestation_version", ""},
                {RPCResult::Type::STR_HEX, "replay_authority_context", /*optional=*/true, "Versioned ExactReplay authority context for this configuration"},
                {RPCResult::Type::NUM, "threshold", ""},
                {RPCResult::Type::NUM, "trusted_signers", ""},
                {RPCResult::Type::ARR, "trusted_signer_pubkeys", "Configured compressed secp256k1 pubkeys this node currently trusts (the pin). Always sufficient for quorum when M-of-N is met.",
                    {{RPCResult::Type::STR_HEX, "", "Compressed pubkey hex"}}},
                {RPCResult::Type::BOOL, "open_attestors", "Whether valid-unpinned attestations are heard and may be admitted after co-signing a pin-quorum hash"},
                {RPCResult::Type::NUM, "open_threshold", "Distinct pinned-or-admitted unfrozen votes required for open quorum (0 when open attestors are disabled)"},
                {RPCResult::Type::ARR, "admitted_open_pubkeys", "Open keys admitted locally after co-signing a pin-quorum hash",
                    {{RPCResult::Type::STR_HEX, "", "Compressed pubkey hex"}}},
                {RPCResult::Type::ARR, "frozen_open_pubkeys", "Open keys frozen for equivocation (same height, two hashes)",
                    {{RPCResult::Type::STR_HEX, "", "Compressed pubkey hex"}}},
                {RPCResult::Type::ARR, "blocked_pubkeys", "Operator attestation blocklist; inert even if still in the pin",
                    {{RPCResult::Type::STR_HEX, "", "Compressed pubkey hex"}}},
                {RPCResult::Type::NUM, "unblocked_pin_members", "Pin members not on the blocklist"},
                {RPCResult::Type::BOOL, "pin_quorum_reachable", "Whether unblocked pin members still meet M"},
                {RPCResult::Type::NUM, "heard_attestations", "Valid-unpinned statements retained as directory, not authority"},
                {RPCResult::Type::NUM, "log_tree_size", "Append-only attestation transparency-log leaf count (hot cache)"},
                {RPCResult::Type::STR_HEX, "log_root", /*optional=*/true, "Merkle root of the local attestation transparency log"},
                {RPCResult::Type::NUM, "stored_blocks", ""},
                {RPCResult::Type::NUM, "stored_attestations", ""},
                {RPCResult::Type::NUM, "blocks_with_quorum", ""},
                {RPCResult::Type::NUM, "accepted", ""},
                {RPCResult::Type::NUM, "duplicates", ""},
                {RPCResult::Type::NUM, "rejected", ""},
                {RPCResult::Type::NUM, "capacity_rejections", ""},
                {RPCResult::Type::NUM, "evicted_blocks", ""},
                {RPCResult::Type::NUM, "expired_blocks", ""},
                {RPCResult::Type::NUM, "quorum_transitions", ""},
                {RPCResult::Type::NUM, "wait_timeouts", ""},
                {RPCResult::Type::OBJ, "attested_tip", /*optional=*/true,
                 "Highest-work block this node currently has a quorum for (also getmatmulattestedtip)",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "Attested block hash"},
                        {RPCResult::Type::NUM, "height", "Attested block height"},
                        {RPCResult::Type::BOOL, "on_active_chain", "Whether that block is an ancestor of (or is) the active tip"},
                        {RPCResult::Type::BOOL, "active_tip_has_quorum", "Whether the active tip itself currently has quorum"},
                    }},
                {RPCResult::Type::STR, "warning", ""},
            }},
        RPCExamples{HelpExampleCli("getmatmultrustedstatus", "")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) {
            UniValue result{UniValue::VOBJ};
            const auto stats{
                node::matmul_trusted::Stats()};
            result.pushKV(
                "configured",
                node::matmul_trusted::IsConfigured());
            result.pushKV(
                "trusted_mirror",
                node::matmul_trusted::IsTrustedMirror());
            {
                NodeContext& node = EnsureAnyNodeContext(request.context);
                if (node.chainman) {
                    const auto mode{node.chainman->GetMatMulValidationMode()};
                    result.pushKV("matmul_validation_mode",
                                  kernel::MatMulValidationModeName(mode));
                    result.pushKV(
                        "discovery_relay",
                        kernel::MatMulModeIsDiscoveryRelay(mode));
                    result.pushKV(
                        "chain_oracle",
                        kernel::MatMulModeIsChainAuthority(mode));
                } else {
                    result.pushKV("discovery_relay", false);
                    result.pushKV("chain_oracle", false);
                }
            }
            result.pushKV(
                "serves_attestations",
                node::matmul_trusted::ServesAttestations());
            result.pushKV(
                "local_signer",
                node::matmul_trusted::HasLocalSigner());
            const size_t n_signers{node::matmul_trusted::TrustedSigners().size()};
            const size_t threshold{node::matmul_trusted::Threshold()};
            const bool trusted_mirror{node::matmul_trusted::IsTrustedMirror()};
            const bool configured{node::matmul_trusted::IsConfigured()};
            bool signer_in_pin{false};
            if (const auto local{node::matmul_trusted::LocalSigner()}) {
                signer_in_pin = node::matmul_trusted::IsAuthoritySigner(*local);
            }
            result.pushKV(
                "single_key_pin",
                configured && (n_signers < 2 || threshold < 2));
            result.pushKV(
                "single_key_trusted_authority",
                node::matmul_trusted::TrustedMirrorIsSingleKeyAuthority(
                    trusted_mirror, n_signers, threshold));
            result.pushKV(
                "collocated_signer_pin",
                node::matmul_trusted::CollocatedSignerPinIsHijackAmplifier(
                    trusted_mirror,
                    node::matmul_trusted::HasLocalSigner(),
                    signer_in_pin,
                    n_signers,
                    threshold));
            result.pushKV(
                "attestation_version",
                matmul::trusted::ExactReplayStatement::CURRENT_VERSION);
            if (const auto context{
                    node::matmul_trusted::ReplayAuthorityContext()}) {
                result.pushKV(
                    "replay_authority_context", context->GetHex());
            }
            result.pushKV(
                "threshold",
                static_cast<uint64_t>(
                    node::matmul_trusted::Threshold()));
            result.pushKV(
                "trusted_signers",
                static_cast<uint64_t>(
                    node::matmul_trusted::TrustedSigners().size()));
            result.pushKV("trusted_signer_pubkeys", TrustedSignerPubKeysJSON());
            result.pushKV(
                "open_attestors",
                node::matmul_trusted::OpenAttestorsEnabled());
            result.pushKV(
                "open_threshold",
                static_cast<uint64_t>(
                    node::matmul_trusted::OpenThreshold()));
            result.pushKV(
                "admitted_open_pubkeys",
                PubKeysJSON(node::matmul_trusted::AdmittedOpenSigners()));
            result.pushKV(
                "frozen_open_pubkeys",
                PubKeysJSON(node::matmul_trusted::FrozenOpenSigners()));
            result.pushKV(
                "blocked_pubkeys",
                PubKeysJSON(node::matmul_trusted::BlockedSigners()));
            result.pushKV(
                "unblocked_pin_members",
                static_cast<uint64_t>(
                    node::matmul_trusted::UnblockedPinMembers()));
            result.pushKV(
                "pin_quorum_reachable",
                node::matmul_trusted::PinQuorumReachable());
            result.pushKV(
                "heard_attestations",
                static_cast<uint64_t>(stats.heard_attestations));
            {
                const auto log_head{node::matmul_trusted::LogHead()};
                result.pushKV("log_tree_size", log_head.tree_size);
                if (log_head.tree_size != 0) {
                    result.pushKV("log_root", log_head.root.GetHex());
                }
            }
            result.pushKV(
                "stored_blocks",
                static_cast<uint64_t>(stats.stored_blocks));
            result.pushKV(
                "stored_attestations",
                static_cast<uint64_t>(
                    stats.stored_attestations));
            result.pushKV(
                "blocks_with_quorum",
                static_cast<uint64_t>(
                    stats.blocks_with_quorum));
            result.pushKV("accepted", stats.accepted);
            result.pushKV("duplicates", stats.duplicates);
            result.pushKV("rejected", stats.rejected);
            result.pushKV(
                "capacity_rejections",
                stats.capacity_rejections);
            result.pushKV("evicted_blocks", stats.evicted_blocks);
            result.pushKV("expired_blocks", stats.expired_blocks);
            result.pushKV(
                "quorum_transitions",
                stats.quorum_transitions);
            result.pushKV(
                "wait_timeouts", stats.wait_timeouts);
            if (node::matmul_trusted::IsConfigured()) {
                ChainstateManager& chainman{
                    EnsureAnyChainman(request.context)};
                LOCK(cs_main);
                const CBlockIndex* const tip{chainman.ActiveChain().Tip()};
                const CBlockIndex* const attested{
                    chainman.FindBestKnownAttestedIndex()};
                if (attested != nullptr) {
                    UniValue attested_tip{UniValue::VOBJ};
                    attested_tip.pushKV("hash", attested->GetBlockHash().GetHex());
                    attested_tip.pushKV("height", attested->nHeight);
                    attested_tip.pushKV(
                        "on_active_chain",
                        tip != nullptr &&
                            tip->GetAncestor(attested->nHeight) == attested);
                    attested_tip.pushKV(
                        "active_tip_has_quorum",
                        tip != nullptr &&
                            node::matmul_trusted::HasQuorum(
                                tip->GetBlockHash(), tip->nHeight));
                    result.pushKV("attested_tip", std::move(attested_tip));
                }
            }
            result.pushKV(
                "warning",
                node::matmul_trusted::TrustedMirrorIsSingleKeyAuthority(
                    node::matmul_trusted::IsTrustedMirror(),
                    node::matmul_trusted::TrustedSigners().size(),
                    node::matmul_trusted::Threshold())
                    ? "Single-key trusted mirror: the attestation quorum replaces ExactReplay. A stolen WIF can make this node accept MatMul-invalid blocks. Mainnet requires M=2 unless -allowsinglekeytrustedmirror=1."
                    : (node::matmul_trusted::IsTrustedMirror()
                           ? "Operator-trusted mirror: signed M-of-N attestations replace local ExactReplay; this is not independent full validation."
                           : ""));
            return result;
        }};
}

RPCHelpMan getmatmulattestedtip()
{
    return RPCHelpMan{
        "getmatmulattestedtip",
        "Return the highest-work block this node currently has a configured "
        "attestation quorum for. Telemetry for trusted-mirror and archive "
        "operators. Consensus miners mine the ExactReplay-valid tip; do not "
        "treat this hash as a requirement to abandon a heavier unattested "
        "fork. Requires -matmultrustedpubkey (and typically "
        "-matmultrustedthreshold). "
        "On a quiet linear chain the signer often attests ~1 behind the active "
        "tip, so this may lag getbestblockhash by one block.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "configured", "Whether a trusted-signer set is configured"},
                {RPCResult::Type::STR_HEX, "hash", /*optional=*/true, "Attested block hash"},
                {RPCResult::Type::NUM, "height", /*optional=*/true, "Attested block height"},
                {RPCResult::Type::BOOL, "on_active_chain", /*optional=*/true, "Whether that HAVE_DATA attested block is an ancestor of (or is) the active tip"},
                {RPCResult::Type::BOOL, "active_tip_has_quorum", /*optional=*/true, "Whether the active tip itself currently has quorum"},
                {RPCResult::Type::STR_HEX, "active_tip_hash", /*optional=*/true, "Active chain tip hash"},
                {RPCResult::Type::NUM, "active_tip_height", /*optional=*/true, "Active chain tip height"},
                {RPCResult::Type::OBJ, "signed_frontier", /*optional=*/true,
                 "Highest stored quorum height, including hashes without HAVE_DATA. A stranded fork keeps hash/on_active_chain healthy while blocks_behind climbs.",
                    {
                        {RPCResult::Type::NUM, "height", "Highest stored quorum height"},
                        {RPCResult::Type::STR_HEX, "hash", /*optional=*/true, "Hash recorded for that height, if known"},
                        {RPCResult::Type::BOOL, "on_active_chain", "Whether that hash is an ancestor of (or is) the active tip"},
                        {RPCResult::Type::NUM, "on_chain_attested_height", "Highest quorum ancestor of the active tip, or -1 if none"},
                        {RPCResult::Type::NUM, "blocks_behind", "max(0, height - on_chain_attested_height)"},
                    }},
            }},
        RPCExamples{HelpExampleCli("getmatmulattestedtip", "")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) {
            UniValue result{UniValue::VOBJ};
            result.pushKV("configured", node::matmul_trusted::IsConfigured());
            if (!node::matmul_trusted::IsConfigured()) {
                return result;
            }
            ChainstateManager& chainman{EnsureAnyChainman(request.context)};
            LOCK(cs_main);
            const CBlockIndex* const tip{chainman.ActiveChain().Tip()};
            if (tip != nullptr) {
                result.pushKV("active_tip_hash", tip->GetBlockHash().GetHex());
                result.pushKV("active_tip_height", tip->nHeight);
                result.pushKV(
                    "active_tip_has_quorum",
                    node::matmul_trusted::HasQuorum(
                        tip->GetBlockHash(), tip->nHeight));
            }
            if (const CBlockIndex* attested{
                    chainman.FindBestKnownAttestedIndex()}) {
                result.pushKV("hash", attested->GetBlockHash().GetHex());
                result.pushKV("height", attested->nHeight);
                result.pushKV(
                    "on_active_chain",
                    tip != nullptr &&
                        tip->GetAncestor(attested->nHeight) == attested);
            }
            if (const auto frontier{chainman.GetSignedFrontierStatus()};
                frontier.available) {
                UniValue signed_frontier{UniValue::VOBJ};
                signed_frontier.pushKV("height", frontier.height);
                if (frontier.hash_known) {
                    signed_frontier.pushKV("hash", frontier.hash.GetHex());
                }
                signed_frontier.pushKV(
                    "on_active_chain", frontier.on_active_chain);
                signed_frontier.pushKV(
                    "on_chain_attested_height",
                    frontier.on_chain_attested_height);
                signed_frontier.pushKV("blocks_behind", frontier.blocks_behind);
                result.pushKV("signed_frontier", std::move(signed_frontier));
            }
            return result;
        }};
}

RPCHelpMan getmatmulattestations()
{
    return RPCHelpMan{
        "getmatmulattestations",
        "Get/export retained signed ExactReplay attestations for a known "
        "Profile-1 block. An archive may regenerate its own statement only "
        "after a persisted local ExactReplay success.",
        {
            {"blockhash", RPCArg::Type::STR_HEX,
             RPCArg::Optional::NO, "Known block hash"},
        },
        RPCResult{RPCResult::Type::ARR, "", "",
            {{RPCResult::Type::STR_HEX, "", "Serialized attestation"}}},
        RPCExamples{
            HelpExampleCli(
                "getmatmulattestations", "\"blockhash\"")},
        [](const RPCHelpMan& self,
           const JSONRPCRequest& request) {
            ChainstateManager& chainman{
                EnsureAnyChainman(request.context)};
            const uint256 hash{
                ParseHashV(request.params[0], "blockhash")};
            const auto known{
                LookupAttestationBlock(chainman, hash)};
            if (!known) {
                throw JSONRPCError(
                    RPC_INVALID_ADDRESS_OR_KEY,
                    "Unknown or non-Profile-1 block");
            }
            if (known->local_exact &&
                known->on_active_chain &&
                node::matmul_trusted::HasLocalSigner()) {
                const auto sign_result{
                    node::matmul_trusted::SignAuthoritative(
                        hash, known->height)};
                if (sign_result !=
                        matmul::trusted::AddResult::Accepted &&
                    sign_result !=
                        matmul::trusted::AddResult::Duplicate) {
                    throw JSONRPCError(
                        RPC_INTERNAL_ERROR,
                        strprintf(
                            "Attestation signing failed: %s",
                            matmul::trusted::AddResultName(
                                sign_result)));
                }
            }
            UniValue out{UniValue::VARR};
            for (const auto& attestation :
                 node::matmul_trusted::Get(
                     hash, known->height)) {
                out.push_back(
                    EncodeAttestation(attestation));
            }
            return out;
        }};
}

RPCHelpMan clearlocalmatmulattestation()
{
    return RPCHelpMan{
        "clearlocalmatmulattestation",
        "Emergency local signer recovery. Freshly ExactReplay the stored, "
        "fully validated active-chain replacement, then remove every locally "
        "retained attestation for the off-active-chain block occupying that "
        "height. The occupied block may be failed or otherwise valid; this "
        "RPC never changes block validity, disconnects blocks, activates a "
        "chain, or runs reconsiderblock. This only clears local attestation "
        "state: any previously published signature remains valid and signing "
        "the replacement is same-key equivocation under the current "
        "attestation context. The RPC itself does not sign the replacement; "
        "after a successful clear, an eligible P2P GETMMATTEST or a later "
        "getmatmulattestations call may do so.\n",
        {
            {"attestedblockhash|failedblockhash", RPCArg::Type::STR_HEX,
             RPCArg::Optional::NO,
             "Off-active-chain block whose local attestation state occupies "
             "the height and will be erased"},
            {"replacementblockhash", RPCArg::Type::STR_HEX,
             RPCArg::Optional::NO,
             "Stored, fully validated active-chain block at the same height; "
             "a fresh local ExactReplay is performed before any attestation "
             "is erased"},
            {"acknowledge_equivocation", RPCArg::Type::BOOL,
             RPCArg::Optional::NO,
             "Must be true to acknowledge that published signatures cannot "
             "be revoked"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "cleared_blockhash", ""},
                {RPCResult::Type::NUM, "height", ""},
                {RPCResult::Type::BOOL, "cleared_block_was_failed", ""},
                {RPCResult::Type::NUM, "removed_attestations", ""},
                {RPCResult::Type::BOOL, "replacement_on_active_chain", ""},
                {RPCResult::Type::BOOL, "replacement_exact_replay_performed", "True: a fresh local ExactReplay was performed"},
                {RPCResult::Type::BOOL, "replacement_exact_replay_previously_verified", ""},
                {RPCResult::Type::BOOL, "replacement_exact_replay_verified", ""},
                {RPCResult::Type::STR_HEX, "replacement_blockhash", ""},
                {RPCResult::Type::STR_HEX, "tip_before", ""},
                {RPCResult::Type::NUM, "tip_height_before", ""},
                {RPCResult::Type::STR_HEX, "tip_after", ""},
                {RPCResult::Type::NUM, "tip_height_after", ""},
                {RPCResult::Type::BOOL, "block_validity_changed", "Always false: no failed status is added or removed"},
                {RPCResult::Type::BOOL, "chain_selection_operation_performed", "Always false: no disconnect, activation, invalidation, or reconsiderblock is run"},
                {RPCResult::Type::STR, "next_command", ""},
                {RPCResult::Type::STR, "warning", ""},
            }},
        RPCExamples{HelpExampleCli(
            "clearlocalmatmulattestation",
            "\"offchainhash\" \"activehash\" true")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) {
            if (!request.params[2].get_bool()) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "acknowledge_equivocation must be true");
            }
            if (!node::matmul_trusted::HasLocalSigner()) {
                throw JSONRPCError(
                    RPC_MISC_ERROR,
                    "No local MatMul attestation signer is configured");
            }

            ChainstateManager& chainman{EnsureAnyChainman(request.context)};
            const uint256 attested_hash{
                ParseHashV(request.params[0], "attestedblockhash")};
            const uint256 replacement_hash{
                ParseHashV(request.params[1], "replacementblockhash")};
            int32_t height{-1};
            bool cleared_block_was_failed{false};
            {
                LOCK(cs_main);
                const CBlockIndex* const attested{
                    chainman.m_blockman.LookupBlockIndex(attested_hash)};
                const CBlockIndex* const replacement{
                    chainman.m_blockman.LookupBlockIndex(replacement_hash)};
                if (attested == nullptr) {
                    throw JSONRPCError(
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "Unknown attestedblockhash");
                }
                if (replacement == nullptr) {
                    throw JSONRPCError(
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "Unknown replacementblockhash");
                }
                if (chainman.ActiveChain().Contains(attested)) {
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "attestedblockhash is on the active chain");
                }
                if (attested->nHeight != replacement->nHeight) {
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "Replacement block is at a different height");
                }
                if (!chainman.ActiveChain().Contains(replacement)) {
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "replacementblockhash is not on the active chain");
                }
                if ((replacement->nStatus & BLOCK_FAILED_MASK) ||
                    !(replacement->nStatus & BLOCK_HAVE_DATA) ||
                    !replacement->IsValid(BLOCK_VALID_SCRIPTS)) {
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "replacementblockhash does not have a fully validated "
                        "stored block body");
                }
                if (!chainman.GetConsensus()
                         .IsMatMulTrustedReplayAttestationActive(
                             replacement->nHeight)) {
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "Replacement height is outside the MatMul "
                        "attestation regime");
                }
                if (chainman.GetMatMulValidationMode() !=
                    kernel::MatMulValidationMode::CONSENSUS) {
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "Fresh ExactReplay recovery requires consensus MatMul "
                        "validation mode");
                }
                height = attested->nHeight;
                cleared_block_was_failed =
                    (attested->nStatus & BLOCK_FAILED_MASK) != 0;
            }

            const auto local_signer{node::matmul_trusted::LocalSigner()};
            const auto retained{
                node::matmul_trusted::Get(attested_hash, height)};
            if (!local_signer.has_value() ||
                std::none_of(
                    retained.begin(), retained.end(),
                    [&](const auto& attestation) {
                        return attestation.signer == *local_signer;
                    })) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "The local signer has no retained attestation for "
                    "attestedblockhash");
            }

            ChainstateManager::MatMulExactReplayRecoveryResult replay_result;
            BlockValidationState replay_state;
            {
                LOCK(cs_main);
                if (!chainman.ExactReplayActiveMatMulBlock(
                        replacement_hash, replay_state, replay_result)) {
                    throw JSONRPCError(
                        RPC_MISC_ERROR,
                        strprintf(
                            "Fresh replacement ExactReplay failed: %s",
                            replay_state.ToString()));
                }
            }

            // ExactReplay released cs_main. Re-check both hashes immediately
            // before mutating the attestation store; a concurrent reorg must
            // not turn this into a clear of the newly active hash.
            {
                LOCK(cs_main);
                const CBlockIndex* const attested{
                    chainman.m_blockman.LookupBlockIndex(attested_hash)};
                const CBlockIndex* const replacement{
                    chainman.m_blockman.LookupBlockIndex(replacement_hash)};
                if (attested == nullptr || replacement == nullptr ||
                    chainman.ActiveChain().Contains(attested) ||
                    chainman.ActiveChain()[height] != replacement ||
                    (replacement->nStatus & BLOCK_FAILED_MASK) != 0 ||
                    (replacement->nStatus &
                     BLOCK_EXACT_REPLAY_VERIFIED) == 0) {
                    throw JSONRPCError(
                        RPC_MISC_ERROR,
                        "Chainstate changed before attestation clear; no "
                        "attestation was removed");
                }
            }

            size_t removed_attestations{0};
            std::string error;
            if (!node::matmul_trusted::ClearLocalAttestation(
                    attested_hash, height, removed_attestations, error)) {
                throw JSONRPCError(RPC_MISC_ERROR, error);
            }

            UniValue result{UniValue::VOBJ};
            result.pushKV("cleared_blockhash", attested_hash.GetHex());
            result.pushKV("height", height);
            result.pushKV("cleared_block_was_failed",
                          cleared_block_was_failed);
            result.pushKV("removed_attestations",
                          static_cast<uint64_t>(removed_attestations));
            result.pushKV("replacement_on_active_chain", true);
            result.pushKV("replacement_exact_replay_performed", true);
            result.pushKV(
                "replacement_exact_replay_previously_verified",
                replay_result.previously_verified);
            result.pushKV("replacement_exact_replay_verified", true);
            result.pushKV("replacement_blockhash",
                          replacement_hash.GetHex());
            result.pushKV("tip_before", replay_result.tip_before.GetHex());
            result.pushKV("tip_height_before",
                          replay_result.tip_height_before);
            result.pushKV("tip_after", replay_result.tip_after.GetHex());
            result.pushKV("tip_height_after",
                          replay_result.tip_height_after);
            result.pushKV("block_validity_changed", false);
            result.pushKV("chain_selection_operation_performed", false);
            result.pushKV(
                "next_command",
                strprintf("getmatmulattestations %s",
                          replacement_hash.GetHex()));
            result.pushKV(
                "warning",
                "Local state was cleared, but previously published "
                "signatures remain valid. A later eligible P2P GETMMATTEST "
                "or getmatmulattestations call may sign the replacement, "
                "creating same-key equivocation in the current authority "
                "context.");
            return result;
        }};
}

RPCHelpMan submitmatmulattestations()
{
    return RPCHelpMan{
        "submitmatmulattestations",
        "Submit/import a bounded batch of signed ExactReplay attestations. "
        "Each statement is checked against the local block index and current "
        "configured chain, replay authority context, signer set, and "
        "threshold.",
        {
            {"attestations", RPCArg::Type::ARR,
             RPCArg::Optional::NO, "Serialized attestations (maximum 16)",
                {
                    {"attestation", RPCArg::Type::STR_HEX,
                     RPCArg::Optional::OMITTED, ""},
                }},
        },
        RPCResult{RPCResult::Type::ARR, "", "",
            {{RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "blockhash", ""},
                    {RPCResult::Type::NUM, "height", ""},
                    {RPCResult::Type::STR, "result", ""},
                    {RPCResult::Type::BOOL, "quorum", ""},
                }}}},
        RPCExamples{
            HelpExampleCli(
                "submitmatmulattestations", "'[\"hex\"]'")},
        [](const RPCHelpMan& self,
           const JSONRPCRequest& request) {
            ChainstateManager& chainman{
                EnsureAnyChainman(request.context)};
            const UniValue& values{request.params[0]};
            if (!values.isArray() || values.empty() ||
                values.size() > 16) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "attestations must contain 1..16 items");
            }
            UniValue out{UniValue::VARR};
            for (const auto& value : values.getValues()) {
                matmul::trusted::ExactReplayAttestation
                    attestation;
                if (!value.isStr() ||
                    value.get_str().size() > 32 * 1024 ||
                    !DecodeAttestation(
                        value.get_str(), attestation)) {
                    throw JSONRPCError(
                        RPC_DESERIALIZATION_ERROR,
                        "Malformed trusted ExactReplay attestation");
                }
                const uint256 hash{
                    attestation.statement.block_hash};
                const auto known{
                    LookupAttestationBlock(chainman, hash)};
                if (!known) {
                    throw JSONRPCError(
                        RPC_INVALID_ADDRESS_OR_KEY,
                        strprintf(
                            "Unknown or non-Profile-1 block %s",
                            hash.ToString()));
                }
                const auto add_result{
                    node::matmul_trusted::Add(
                        attestation, hash, known->height)};
                UniValue item{UniValue::VOBJ};
                item.pushKV("blockhash", hash.GetHex());
                item.pushKV("height", known->height);
                item.pushKV(
                    "result",
                    matmul::trusted::AddResultName(
                        add_result));
                item.pushKV(
                    "quorum",
                    node::matmul_trusted::HasQuorum(
                        hash, known->height));
                out.push_back(std::move(item));
            }
            return out;
        }};
}

RPCHelpMan getmatmulattestors()
{
    return RPCHelpMan{
        "getmatmulattestors",
        "Directory of this node's pin, admitted open attestors, frozen keys, "
        "and heard-but-unpinned GPU statements. Heard keys are not trust. "
        "Never apply a peer's key list as membership.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "configured", ""},
                {RPCResult::Type::BOOL, "open_attestors", ""},
                {RPCResult::Type::NUM, "threshold", "Pin M-of-N threshold"},
                {RPCResult::Type::NUM, "open_threshold", ""},
                {RPCResult::Type::ARR, "pinned_pubkeys", "Local -matmultrustedpubkey set",
                    {{RPCResult::Type::STR_HEX, "", "Compressed pubkey hex"}}},
                {RPCResult::Type::ARR, "admitted_open_pubkeys", "Admitted after co-signing a pin-quorum hash",
                    {{RPCResult::Type::STR_HEX, "", "Compressed pubkey hex"}}},
                {RPCResult::Type::ARR, "frozen_open_pubkeys", "Equivocating open keys",
                    {{RPCResult::Type::STR_HEX, "", "Compressed pubkey hex"}}},
                {RPCResult::Type::ARR, "blocked_pubkeys", "Operator attestation blocklist",
                    {{RPCResult::Type::STR_HEX, "", "Compressed pubkey hex"}}},
                {RPCResult::Type::NUM, "unblocked_pin_members", "Pin members not on the blocklist"},
                {RPCResult::Type::BOOL, "pin_quorum_reachable", "Whether unblocked pin members still meet M"},
                {RPCResult::Type::ARR, "heard_pubkeys", "Valid-unpinned keys not yet admitted",
                    {{RPCResult::Type::STR_HEX, "", "Compressed pubkey hex"}}},
                {RPCResult::Type::NUM, "log_tree_size", ""},
                {RPCResult::Type::STR_HEX, "log_root", /*optional=*/true, ""},
            }},
        RPCExamples{HelpExampleCli("getmatmulattestors", "")},
        [](const RPCHelpMan&, const JSONRPCRequest&) {
            UniValue result{UniValue::VOBJ};
            result.pushKV("configured", node::matmul_trusted::IsConfigured());
            result.pushKV(
                "open_attestors",
                node::matmul_trusted::OpenAttestorsEnabled());
            result.pushKV(
                "threshold",
                static_cast<uint64_t>(node::matmul_trusted::Threshold()));
            result.pushKV(
                "open_threshold",
                static_cast<uint64_t>(node::matmul_trusted::OpenThreshold()));
            result.pushKV("pinned_pubkeys", TrustedSignerPubKeysJSON());
            result.pushKV(
                "admitted_open_pubkeys",
                PubKeysJSON(node::matmul_trusted::AdmittedOpenSigners()));
            result.pushKV(
                "frozen_open_pubkeys",
                PubKeysJSON(node::matmul_trusted::FrozenOpenSigners()));
            result.pushKV(
                "blocked_pubkeys",
                PubKeysJSON(node::matmul_trusted::BlockedSigners()));
            result.pushKV(
                "unblocked_pin_members",
                static_cast<uint64_t>(
                    node::matmul_trusted::UnblockedPinMembers()));
            result.pushKV(
                "pin_quorum_reachable",
                node::matmul_trusted::PinQuorumReachable());
            std::set<CPubKey> heard_keys;
            for (const auto& attestation :
                 node::matmul_trusted::HeardAttestations()) {
                heard_keys.insert(attestation.signer);
            }
            result.pushKV(
                "heard_pubkeys",
                PubKeysJSON({heard_keys.begin(), heard_keys.end()}));
            const auto log_head{node::matmul_trusted::LogHead()};
            result.pushKV("log_tree_size", log_head.tree_size);
            if (log_head.tree_size != 0) {
                result.pushKV("log_root", log_head.root.GetHex());
            }
            return result;
        }};
}

RPCHelpMan submitmatmulrefutation()
{
    return RPCHelpMan{
        "submitmatmulrefutation",
        "Submit a watchtower ExactReplay-failed statement. A pin-member "
        "refutation blocks open quorum on that hash; pin quorum is unchanged.\n",
        {
            {"refutation", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Serialized ExactReplayRefutation hex"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "result", "Add result name"},
                {RPCResult::Type::BOOL, "quorum", "Whether the hash still has authority quorum"},
            }},
        RPCExamples{HelpExampleCli("submitmatmulrefutation", "\"hex\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) {
            if (!node::matmul_trusted::IsConfigured()) {
                throw JSONRPCError(
                    RPC_MISC_ERROR,
                    "MatMul attestation store is not configured");
            }
            const std::string hex{self.Arg<std::string>("refutation")};
            matmul::trusted::ExactReplayRefutation refutation;
            if (!IsHex(hex)) {
                throw JSONRPCError(
                    RPC_DESERIALIZATION_ERROR, "Malformed refutation");
            }
            try {
                DataStream encoded{ParseHex(hex)};
                encoded >> refutation;
                if (!encoded.empty()) {
                    throw JSONRPCError(
                        RPC_DESERIALIZATION_ERROR, "Malformed refutation");
                }
            } catch (const std::ios_base::failure&) {
                throw JSONRPCError(
                    RPC_DESERIALIZATION_ERROR, "Malformed refutation");
            }
            const uint256 hash{refutation.statement.block_hash};
            ChainstateManager& chainman{EnsureAnyChainman(request.context)};
            bool known_profile1{false};
            {
                LOCK(cs_main);
                const CBlockIndex* const index{
                    chainman.m_blockman.LookupBlockIndex(hash)};
                const bool have_index{index != nullptr};
                const bool failed{
                    have_index &&
                    (index->nStatus & BLOCK_FAILED_MASK) != 0};
                const bool profile1{
                    have_index &&
                    chainman.GetConsensus()
                        .IsMatMulTrustedReplayAttestationActive(
                            index->nHeight)};
                const bool height_matches{
                    have_index &&
                    index->nHeight == refutation.statement.block_height};
                known_profile1 =
                    node::matmul_trusted::MmAttestRefuteKnownProfile1Block(
                        have_index, failed, profile1, height_matches);
            }
            if (!known_profile1) {
                throw JSONRPCError(
                    RPC_INVALID_ADDRESS_OR_KEY,
                    "Unknown, failed, non-Profile-1, or height-mismatched block");
            }
            const int32_t height{refutation.statement.block_height};
            const auto add_result{
                node::matmul_trusted::AddRefutation(refutation, hash, height)};
            UniValue result{UniValue::VOBJ};
            result.pushKV(
                "result", matmul::trusted::AddResultName(add_result));
            result.pushKV(
                "quorum", node::matmul_trusted::HasQuorum(hash, height));
            return result;
        }};
}

RPCHelpMan getfinalityinfo()
{
    return RPCHelpMan{
        "getfinalityinfo",
        "Read-only view of the active branch, uniquely attested Authority tip, "
        "parked higher-work candidates, and authenticated reorg-recovery state. "
        "Does not change chain selection. Use this instead of height agreement "
        "across local nodes (issue #108).\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "matmul_validation_mode", "consensus, trusted, relay, economic, or spv"},
                {RPCResult::Type::BOOL, "discovery_relay", "True when this node only introduces peers"},
                {RPCResult::Type::BOOL, "chain_oracle", "False on a discovery relay; this host's tip is not MatMul authority"},
                {RPCResult::Type::BOOL, "trusted_mirror", ""},
                {RPCResult::Type::ARR, "trusted_signer_pubkeys", "Configured compressed secp256k1 pubkeys this node currently trusts",
                    {{RPCResult::Type::STR_HEX, "", "Compressed pubkey hex"}}},
                {RPCResult::Type::NUM, "threshold", "Configured pin M. 0 when unconfigured."},
                {RPCResult::Type::NUM, "unblocked_pin_members", ""},
                {RPCResult::Type::BOOL, "pin_quorum_reachable", ""},
                {RPCResult::Type::BOOL, "open_attestors", ""},
                {RPCResult::Type::BOOL, "single_key_pin", ""},
                {RPCResult::Type::BOOL, "single_key_trusted_authority", ""},
                {RPCResult::Type::BOOL, "collocated_signer_pin", ""},
                {RPCResult::Type::ARR, "warnings", "Operator-visible split/island/hijack tells",
                    {{RPCResult::Type::STR, "", "Warning code"}}},
                {RPCResult::Type::OBJ, "active_tip", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", ""},
                        {RPCResult::Type::NUM, "height", ""},
                        {RPCResult::Type::STR_HEX, "chainwork", ""},
                        {RPCResult::Type::STR_HEX, "authenticated_chainwork", ""},
                        {RPCResult::Type::BOOL, "has_quorum", ""},
                    }},
                {RPCResult::Type::OBJ, "best_header", /*optional=*/true, "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", ""},
                        {RPCResult::Type::NUM, "height", ""},
                        {RPCResult::Type::STR_HEX, "chainwork", ""},
                        {RPCResult::Type::BOOL, "extends_active_tip", ""},
                    }},
                {RPCResult::Type::OBJ, "attested_tip", /*optional=*/true,
                 "Highest-work HAVE_DATA block with current quorum, or omitted",
                    {
                        {RPCResult::Type::STR_HEX, "hash", ""},
                        {RPCResult::Type::NUM, "height", ""},
                        {RPCResult::Type::BOOL, "on_active_chain", ""},
                        {RPCResult::Type::BOOL, "active_descends_from_attested", ""},
                    }},
                {RPCResult::Type::OBJ, "signed_frontier", /*optional=*/true, "",
                    {
                        {RPCResult::Type::NUM, "height", ""},
                        {RPCResult::Type::STR_HEX, "hash", /*optional=*/true, ""},
                        {RPCResult::Type::BOOL, "on_active_chain", ""},
                        {RPCResult::Type::NUM, "blocks_behind", ""},
                    }},
                {RPCResult::Type::ARR, "parked_branches", "",
                    {{RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "root", ""},
                            {RPCResult::Type::STR_HEX, "tip", /*optional=*/true, ""},
                            {RPCResult::Type::NUM, "tip_height", /*optional=*/true, ""},
                            {RPCResult::Type::STR_HEX, "fork", /*optional=*/true, ""},
                            {RPCResult::Type::NUM, "depth", /*optional=*/true, ""},
                            {RPCResult::Type::STR, "reason", "parked_unattested_rewrite"},
                        }}}},
                {RPCResult::Type::OBJ, "recovery", "",
                    {
                        {RPCResult::Type::STR, "state", "none or armed"},
                        {RPCResult::Type::STR, "mode", /*optional=*/true, "CONSENSUS_AUTHENTICATED or TRUSTED_AUTHORITY"},
                        {RPCResult::Type::STR_HEX, "fork_hash", /*optional=*/true, ""},
                        {RPCResult::Type::STR_HEX, "losing_tip_hash", /*optional=*/true, ""},
                        {RPCResult::Type::STR_HEX, "recovery_root_hash", /*optional=*/true, ""},
                        {RPCResult::Type::STR_HEX, "authenticated_tip_hash", /*optional=*/true, ""},
                        {RPCResult::Type::NUM, "initial_reorg_depth", /*optional=*/true, ""},
                    }},
                {RPCResult::Type::STR, "finality", "Always \"none\". ExactReplay is authority; signatures are a sidecar."},
                {RPCResult::Type::OBJ, "finality_profile", "Fork-choice park/warn profile; not signature-granted finality.",
                    {
                        {RPCResult::Type::STR, "profile", ""},
                        {RPCResult::Type::STR, "action", "park or warn"},
                        {RPCResult::Type::BOOL, "parking_enabled", "False when -parkdeepreorg=0 or a non-emergency profile is selected"},
                        {RPCResult::Type::BOOL, "follows_most_work", "True when deep rewrites are not parked"},
                        {RPCResult::Type::NUM, "warn_depth", ""},
                        {RPCResult::Type::NUM, "park_depth", "0 when parking is disabled"},
                    }},
            }},
        RPCExamples{HelpExampleCli("getfinalityinfo", "")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) {
            ChainstateManager& chainman{EnsureAnyChainman(request.context)};
            LOCK(cs_main);
            const CBlockIndex* const tip{chainman.ActiveChain().Tip()};
            const CBlockIndex* const best_header{chainman.m_best_header};
            UniValue result{UniValue::VOBJ};
            const auto mode{chainman.GetMatMulValidationMode()};
            result.pushKV("matmul_validation_mode",
                          kernel::MatMulValidationModeName(mode));
            result.pushKV("discovery_relay",
                          kernel::MatMulModeIsDiscoveryRelay(mode));
            result.pushKV("chain_oracle",
                          kernel::MatMulModeIsChainAuthority(mode));
            result.pushKV("trusted_mirror", node::matmul_trusted::IsTrustedMirror());
            result.pushKV("trusted_signer_pubkeys", TrustedSignerPubKeysJSON());
            {
                const size_t n_signers{node::matmul_trusted::TrustedSigners().size()};
                const size_t threshold{node::matmul_trusted::Threshold()};
                const bool trusted_mirror{node::matmul_trusted::IsTrustedMirror()};
                const bool configured{node::matmul_trusted::IsConfigured()};
                bool signer_in_pin{false};
                if (const auto local{node::matmul_trusted::LocalSigner()}) {
                    signer_in_pin = node::matmul_trusted::IsAuthoritySigner(*local);
                }
                result.pushKV("threshold", static_cast<uint64_t>(threshold));
                result.pushKV(
                    "unblocked_pin_members",
                    static_cast<uint64_t>(
                        node::matmul_trusted::UnblockedPinMembers()));
                result.pushKV(
                    "pin_quorum_reachable",
                    node::matmul_trusted::PinQuorumReachable());
                result.pushKV(
                    "open_attestors",
                    node::matmul_trusted::OpenAttestorsEnabled());
                result.pushKV(
                    "single_key_pin",
                    configured && (n_signers < 2 || threshold < 2));
                result.pushKV(
                    "single_key_trusted_authority",
                    node::matmul_trusted::TrustedMirrorIsSingleKeyAuthority(
                        trusted_mirror, n_signers, threshold));
                result.pushKV(
                    "collocated_signer_pin",
                    node::matmul_trusted::CollocatedSignerPinIsHijackAmplifier(
                        trusted_mirror,
                        node::matmul_trusted::HasLocalSigner(),
                        signer_in_pin,
                        n_signers,
                        threshold));
            }
            if (tip != nullptr) {
                UniValue active{UniValue::VOBJ};
                active.pushKV("hash", tip->GetBlockHash().GetHex());
                active.pushKV("height", tip->nHeight);
                active.pushKV("chainwork", tip->nChainWork.GetHex());
                active.pushKV("authenticated_chainwork",
                              tip->nAuthenticatedChainWork.GetHex());
                active.pushKV(
                    "has_quorum",
                    node::matmul_trusted::IsConfigured() &&
                        node::matmul_trusted::HasQuorum(
                            tip->GetBlockHash(), tip->nHeight));
                result.pushKV("active_tip", std::move(active));
            }
            if (best_header != nullptr) {
                UniValue header{UniValue::VOBJ};
                header.pushKV("hash", best_header->GetBlockHash().GetHex());
                header.pushKV("height", best_header->nHeight);
                header.pushKV("chainwork", best_header->nChainWork.GetHex());
                header.pushKV(
                    "extends_active_tip",
                    tip != nullptr &&
                        best_header->GetAncestor(tip->nHeight) == tip);
                result.pushKV("best_header", std::move(header));
            }
            if (node::matmul_trusted::IsConfigured()) {
                if (const CBlockIndex* attested{
                        chainman.FindBestKnownAttestedIndex()}) {
                    UniValue attested_tip{UniValue::VOBJ};
                    attested_tip.pushKV("hash", attested->GetBlockHash().GetHex());
                    attested_tip.pushKV("height", attested->nHeight);
                    const bool on_chain{
                        tip != nullptr &&
                        tip->GetAncestor(attested->nHeight) == attested};
                    attested_tip.pushKV("on_active_chain", on_chain);
                    attested_tip.pushKV(
                        "active_descends_from_attested", on_chain);
                    result.pushKV("attested_tip", std::move(attested_tip));
                }
                if (const auto frontier{chainman.GetSignedFrontierStatus()};
                    frontier.available) {
                    UniValue signed_frontier{UniValue::VOBJ};
                    signed_frontier.pushKV("height", frontier.height);
                    if (frontier.hash_known) {
                        signed_frontier.pushKV("hash", frontier.hash.GetHex());
                    }
                    signed_frontier.pushKV(
                        "on_active_chain", frontier.on_active_chain);
                    signed_frontier.pushKV("blocks_behind", frontier.blocks_behind);
                    result.pushKV("signed_frontier", std::move(signed_frontier));
                }
            }
            UniValue parked{UniValue::VARR};
            const CBlockIndex* parked_best{nullptr};
            for (const auto& [_, idx] : chainman.BlockIndex()) {
                if (!chainman.IsOnParkedReorgBranch(&idx)) continue;
                if (parked_best == nullptr ||
                    idx.nChainWork > parked_best->nChainWork) {
                    parked_best = &idx;
                }
            }
            for (const uint256& root_hash : chainman.GetParkedReorgBranchRoots()) {
                UniValue branch{UniValue::VOBJ};
                branch.pushKV("root", root_hash.GetHex());
                const CBlockIndex* const root{
                    chainman.m_blockman.LookupBlockIndex(root_hash)};
                if (root != nullptr && tip != nullptr) {
                    const CBlockIndex* const fork{
                        chainman.ActiveChain().FindFork(root)};
                    if (parked_best != nullptr &&
                        parked_best->GetAncestor(root->nHeight) == root) {
                        branch.pushKV("tip", parked_best->GetBlockHash().GetHex());
                        branch.pushKV("tip_height", parked_best->nHeight);
                    }
                    if (fork != nullptr) {
                        branch.pushKV("fork", fork->GetBlockHash().GetHex());
                        branch.pushKV(
                            "depth",
                            tip->nHeight - fork->nHeight);
                    }
                }
                branch.pushKV("reason", "parked_unattested_rewrite");
                parked.push_back(std::move(branch));
            }
            result.pushKV("parked_branches", std::move(parked));
            UniValue recovery{UniValue::VOBJ};
            if (const auto record{chainman.GetReorgRecoveryRecord()}) {
                recovery.pushKV("state", "armed");
                recovery.pushKV(
                    "mode",
                    record->mode == static_cast<uint8_t>(
                        node::ReorgRecoveryRecord::Mode::TRUSTED_AUTHORITY)
                        ? "TRUSTED_AUTHORITY"
                        : "CONSENSUS_AUTHENTICATED");
                recovery.pushKV("fork_hash", record->fork_hash.GetHex());
                recovery.pushKV("losing_tip_hash", record->losing_tip_hash.GetHex());
                recovery.pushKV(
                    "recovery_root_hash", record->recovery_root_hash.GetHex());
                recovery.pushKV(
                    "authenticated_tip_hash",
                    record->authenticated_tip_hash.GetHex());
                recovery.pushKV(
                    "initial_reorg_depth",
                    static_cast<uint64_t>(record->initial_reorg_depth));
            } else {
                recovery.pushKV("state", "none");
            }
            result.pushKV("recovery", std::move(recovery));
            const auto& cm_opts{chainman.m_options};
            const auto profile_settings{
                kernel::GetReorgProtectionProfileSettings(
                    cm_opts.reorg_protection_profile)};
            result.pushKV("finality", "none");
            UniValue profile{UniValue::VOBJ};
            profile.pushKV(
                "profile",
                kernel::ReorgProtectionProfileName(
                    cm_opts.reorg_protection_profile));
            const uint32_t park_depth{
                cm_opts.max_reorg_depth_park.value_or(
                    profile_settings.park_depth)};
            const bool park{
                cm_opts.deep_reorg_action == kernel::DeepReorgAction::PARK};
            const bool parking_enabled{
                park && park_depth != kernel::REORG_PROTECTION_DEPTH_DISABLED};
            profile.pushKV("action", park ? "park" : "warn");
            profile.pushKV("parking_enabled", parking_enabled);
            profile.pushKV("follows_most_work", !parking_enabled);
            profile.pushKV(
                "warn_depth",
                static_cast<int64_t>(
                    cm_opts.max_reorg_depth_warn.value_or(
                        profile_settings.warn_depth)));
            profile.pushKV(
                "park_depth",
                parking_enabled ? static_cast<int64_t>(park_depth) : 0);
            result.pushKV("finality_profile", std::move(profile));
            UniValue warnings{UniValue::VARR};
            if (kernel::MatMulModeIsDiscoveryRelay(mode)) {
                warnings.push_back("not_a_chain_oracle");
            }
            if (best_header != nullptr && tip != nullptr &&
                best_header->GetAncestor(tip->nHeight) != tip) {
                warnings.push_back("best_header_diverged_from_active_tip");
            }
            if (node::matmul_trusted::IsConfigured()) {
                if (const auto frontier{chainman.GetSignedFrontierStatus()};
                    frontier.available && !frontier.on_active_chain &&
                    frontier.blocks_behind > 0) {
                    warnings.push_back("signed_frontier_off_active_chain");
                }
            }
            if (node::matmul_trusted::TrustedMirrorIsSingleKeyAuthority(
                    node::matmul_trusted::IsTrustedMirror(),
                    node::matmul_trusted::TrustedSigners().size(),
                    node::matmul_trusted::Threshold())) {
                warnings.push_back("single_key_trusted_authority");
            }
            {
                bool signer_in_pin{false};
                if (const auto local{node::matmul_trusted::LocalSigner()}) {
                    signer_in_pin = node::matmul_trusted::IsAuthoritySigner(*local);
                }
                if (node::matmul_trusted::CollocatedSignerPinIsHijackAmplifier(
                        node::matmul_trusted::IsTrustedMirror(),
                        node::matmul_trusted::HasLocalSigner(),
                        signer_in_pin,
                        node::matmul_trusted::TrustedSigners().size(),
                        node::matmul_trusted::Threshold())) {
                    warnings.push_back("collocated_signer_pin");
                }
            }
            if (!parking_enabled) {
                warnings.push_back("deep_reorg_parking_disabled");
            }
            if (node::matmul_trusted::OpenAttestorsEnabled()) {
                warnings.push_back("open_attestors_enabled");
            }
            if (node::matmul_trusted::IsConfigured() &&
                node::matmul_trusted::UnblockedPinMembers() <=
                    node::matmul_trusted::Threshold()) {
                warnings.push_back("no_spare_pin_member");
            }
            result.pushKV("warnings", std::move(warnings));
            return result;
        }};
}

RPCHelpMan addmatmulattestationblocklist()
{
    return RPCHelpMan{
        "addmatmulattestationblocklist",
        "Manually block an attestation public key. The key becomes inert for "
        "pin votes, open admission, refutations, and IsAuthoritySigner even if "
        "it remains in -matmultrustedpubkey. Refused without applying when the "
        "add would leave fewer than M unblocked pin members, or when the key is "
        "this node's local signer. Never auto-populated from peer or attestor "
        "counts.\n",
        {
            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Compressed secp256k1 public key hex"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "added", "Whether the key was newly blocked"},
                {RPCResult::Type::STR, "result", "blocked|duplicate|would-disable-pin-quorum|local-signer|invalid|capacity"},
                {RPCResult::Type::ARR, "blocked_pubkeys", "",
                    {{RPCResult::Type::STR_HEX, "", "Compressed pubkey hex"}}},
                {RPCResult::Type::NUM, "unblocked_pin_members", ""},
                {RPCResult::Type::NUM, "threshold", ""},
                {RPCResult::Type::BOOL, "pin_quorum_reachable", ""},
                {RPCResult::Type::BOOL, "fail_closed", ""},
                {RPCResult::Type::STR, "persist_error", /*optional=*/true, ""},
            }},
        RPCExamples{HelpExampleCli("addmatmulattestationblocklist", "\"02..\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest&) {
            if (!node::matmul_trusted::IsConfigured()) {
                throw JSONRPCError(
                    RPC_MISC_ERROR,
                    "MatMul attestation store is not configured");
            }
            const CPubKey pubkey{
                ParseCompressedPubKeyHex(self.Arg<std::string>("pubkey"))};
            std::string persist_error;
            const auto result{
                node::matmul_trusted::AddBlocklistedSigner(
                    pubkey, persist_error)};
            if (result == matmul::trusted::BlocklistResult::WouldDisablePinQuorum ||
                result == matmul::trusted::BlocklistResult::LocalSigner ||
                result == matmul::trusted::BlocklistResult::Capacity ||
                result == matmul::trusted::BlocklistResult::Invalid) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    std::string{matmul::trusted::BlocklistResultName(result)});
            }
            UniValue out{BlocklistStatusJSON()};
            out.pushKV(
                "added",
                result == matmul::trusted::BlocklistResult::Blocked);
            out.pushKV(
                "result",
                matmul::trusted::BlocklistResultName(result));
            if (!persist_error.empty()) {
                out.pushKV("persist_error", persist_error);
            }
            return out;
        }};
}

RPCHelpMan listmatmulattestationblocklist()
{
    return RPCHelpMan{
        "listmatmulattestationblocklist",
        "List the operator attestation key blocklist and whether the remaining "
        "unblocked pin still meets M.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ARR, "blocked_pubkeys", "",
                    {{RPCResult::Type::STR_HEX, "", "Compressed pubkey hex"}}},
                {RPCResult::Type::NUM, "unblocked_pin_members", ""},
                {RPCResult::Type::NUM, "threshold", ""},
                {RPCResult::Type::BOOL, "pin_quorum_reachable", ""},
                {RPCResult::Type::BOOL, "fail_closed", "Always true: the node refuses a block that would drop unblocked pin members below M"},
                {RPCResult::Type::BOOL, "persisted", "Whether the durable attestation database is open"},
            }},
        RPCExamples{HelpExampleCli("listmatmulattestationblocklist", "")},
        [](const RPCHelpMan&, const JSONRPCRequest&) {
            if (!node::matmul_trusted::IsConfigured()) {
                throw JSONRPCError(
                    RPC_MISC_ERROR,
                    "MatMul attestation store is not configured");
            }
            return BlocklistStatusJSON();
        }};
}

} // namespace

void RegisterMatMulTrustedRPCCommands(CRPCTable& table)
{
    static const CRPCCommand commands[]{
        {"mining", &getmatmultrustedstatus},
        {"mining", &getmatmulattestedtip},
        {"mining", &getmatmulattestors},
        {"mining", &addmatmulattestationblocklist},
        {"mining", &listmatmulattestationblocklist},
        {"blockchain", &getfinalityinfo},
        {"mining", &getmatmulattestations},
        {"hidden", &clearlocalmatmulattestation},
        {"mining", &submitmatmulattestations},
        {"mining", &submitmatmulrefutation},
    };
    for (const auto& command : commands) {
        table.appendCommand(command.name, &command);
    }
    table.appendCommand(
        "exportmatmulattestations", &commands[4]);
    table.appendCommand(
        "importmatmulattestations", &commands[5]);
}
