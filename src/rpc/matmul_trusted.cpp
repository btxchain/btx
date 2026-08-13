// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rpc/register.h>

#include <chain.h>
#include <node/context.h>
#include <node/matmul_trusted_attestations.h>
#include <protocol.h>
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
         BLOCK_EXACT_REPLAY_VERIFIED) != 0};
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

} // namespace

void RegisterMatMulTrustedRPCCommands(CRPCTable& table)
{
    static const CRPCCommand commands[]{
        {"mining", &getmatmultrustedstatus},
        {"mining", &getmatmulattestedtip},
        {"mining", &getmatmulattestations},
        {"mining", &submitmatmulattestations},
    };
    for (const auto& command : commands) {
        table.appendCommand(command.name, &command);
    }
    table.appendCommand(
        "exportmatmulattestations", &commands[2]);
    table.appendCommand(
        "importmatmulattestations", &commands[3]);
}
