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

#include <string>
#include <vector>

namespace {

UniValue TrustedSignerPubKeysJSON()
{
    UniValue keys{UniValue::VARR};
    for (const auto& pubkey : node::matmul_trusted::TrustedSigners()) {
        keys.push_back(HexStr(pubkey));
    }
    return keys;
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
                {RPCResult::Type::BOOL, "trusted_mirror", ""},
                {RPCResult::Type::BOOL, "serves_attestations", ""},
                {RPCResult::Type::BOOL, "local_signer", ""},
                {RPCResult::Type::NUM, "attestation_version", ""},
                {RPCResult::Type::STR_HEX, "replay_authority_context", /*optional=*/true, "Versioned ExactReplay authority context for this configuration"},
                {RPCResult::Type::NUM, "threshold", ""},
                {RPCResult::Type::NUM, "trusted_signers", ""},
                {RPCResult::Type::ARR, "trusted_signer_pubkeys", "Configured compressed secp256k1 pubkeys this node currently trusts",
                    {{RPCResult::Type::STR_HEX, "", "Compressed pubkey hex"}}},
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
            result.pushKV(
                "serves_attestations",
                node::matmul_trusted::ServesAttestations());
            result.pushKV(
                "local_signer",
                node::matmul_trusted::HasLocalSigner());
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
                node::matmul_trusted::IsTrustedMirror()
                    ? "Operator-trusted mirror: signed M-of-N attestations replace local ExactReplay; this is not independent full validation."
                    : "");
            return result;
        }};
}

RPCHelpMan getmatmulattestedtip()
{
    return RPCHelpMan{
        "getmatmulattestedtip",
        "Return the highest-work block this node currently has a configured "
        "attestation quorum for. Intended for pool/tooling authors: mine on "
        "this hash (or its descendant) and abandon a heavier unattested fork. "
        "Requires -matmultrustedpubkey (and typically -matmultrustedthreshold). "
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
                {RPCResult::Type::STR, "matmul_validation_mode", "consensus, trusted, or none"},
                {RPCResult::Type::BOOL, "trusted_mirror", ""},
                {RPCResult::Type::ARR, "trusted_signer_pubkeys", "Configured compressed secp256k1 pubkeys this node currently trusts",
                    {{RPCResult::Type::STR_HEX, "", "Compressed pubkey hex"}}},
                {RPCResult::Type::ARR, "warnings", "Operator-visible split/island tells",
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
                {RPCResult::Type::OBJ, "finality_profile", "",
                    {
                        {RPCResult::Type::STR, "profile", ""},
                        {RPCResult::Type::NUM, "warn_depth", ""},
                        {RPCResult::Type::NUM, "park_depth", ""},
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
            switch (mode) {
            case kernel::MatMulValidationMode::CONSENSUS:
                result.pushKV("matmul_validation_mode", "consensus");
                break;
            case kernel::MatMulValidationMode::TRUSTED:
                result.pushKV("matmul_validation_mode", "trusted");
                break;
            case kernel::MatMulValidationMode::ECONOMIC:
                result.pushKV("matmul_validation_mode", "economic");
                break;
            case kernel::MatMulValidationMode::SPV:
                result.pushKV("matmul_validation_mode", "spv");
                break;
            }
            result.pushKV("trusted_mirror", node::matmul_trusted::IsTrustedMirror());
            result.pushKV("trusted_signer_pubkeys", TrustedSignerPubKeysJSON());
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
            UniValue profile{UniValue::VOBJ};
            profile.pushKV(
                "profile",
                kernel::ReorgProtectionProfileName(
                    cm_opts.reorg_protection_profile));
            profile.pushKV(
                "warn_depth",
                static_cast<int64_t>(
                    cm_opts.max_reorg_depth_warn.value_or(
                        profile_settings.warn_depth)));
            profile.pushKV(
                "park_depth",
                static_cast<int64_t>(
                    cm_opts.max_reorg_depth_park.value_or(
                        profile_settings.park_depth)));
            result.pushKV("finality_profile", std::move(profile));
            UniValue warnings{UniValue::VARR};
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
            result.pushKV("warnings", std::move(warnings));
            return result;
        }};
}

} // namespace

void RegisterMatMulTrustedRPCCommands(CRPCTable& table)
{
    static const CRPCCommand commands[]{
        {"mining", &getmatmultrustedstatus},
        {"mining", &getmatmulattestedtip},
        {"blockchain", &getfinalityinfo},
        {"mining", &getmatmulattestations},
        {"mining", &submitmatmulattestations},
    };
    for (const auto& command : commands) {
        table.appendCommand(command.name, &command);
    }
    table.appendCommand(
        "exportmatmulattestations", &commands[3]);
    table.appendCommand(
        "importmatmulattestations", &commands[4]);
}
