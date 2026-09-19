// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_BCP1_PACKAGE_H
#define BITCOIN_WALLET_BCP1_PACKAGE_H

#include <consensus/amount.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <script/pqm.h>
#include <script/script.h>
#include <span.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class UniValue;
struct PartiallySignedTransaction;

namespace wallet {
namespace bcp1 {

/** Public profile id. Independent of HCP / Model Network. */
inline constexpr const char* PROFILE_ID = "BTX_EXCHANGE_PROFILE_V1";
/** JSON container name. Not a consensus type. */
inline constexpr const char* FORMAT_ID = "BTXPSBT";
inline constexpr uint32_t PACKAGE_VERSION = 1;
inline constexpr const char* CHAIN_ID = "BTX";

/**
 * Canonical BCP/1 PQ derivation (seed-hardened, not BIP32 public children):
 *   m / 87h / coin_typeh / accounth / branch / index
 * branch 0 = deposit, 1 = change.
 *
 * ML-DSA-44 and SLH-DSA-128s cannot do Bitcoin-style non-hardened public-child
 * derivation. Watch-only deposit addresses come from signer-exported pubkeys
 * (`getp2mrpubkeys`) or a pre-generated pool (`importdepositpool`), never from
 * a fake BIP32 xpub.
 */
inline constexpr uint32_t PURPOSE = 87;
inline constexpr uint32_t BRANCH_DEPOSIT = 0;
inline constexpr uint32_t BRANCH_CHANGE = 1;
inline constexpr uint32_t HARDENED = 0x80000000u;

inline constexpr const char* ERR_MISSING_PREVOUT = "MISSING_PREVOUT";
inline constexpr const char* ERR_MISSING_AMOUNT = "MISSING_AMOUNT";
inline constexpr const char* ERR_AUTOMATIC_SPEND_FORBIDDEN = "AUTOMATIC_SPEND_FORBIDDEN";
inline constexpr const char* ERR_INVALID_STRUCTURE = "INVALID_STRUCTURE";
inline constexpr const char* ERR_WRONG_DIGEST = "WRONG_DIGEST";
inline constexpr const char* ERR_CORRUPT_SIGNATURE = "CORRUPT_SIGNATURE";
inline constexpr const char* ERR_NOT_READY = "NOT_READY";
inline constexpr const char* ERR_DUPLICATE_INPUT = "DUPLICATE_INPUT";
inline constexpr const char* ERR_NONCANONICAL = "NONCANONICAL";
inline constexpr const char* ERR_INVALID_P2MR = "INVALID_P2MR";
inline constexpr const char* ERR_WRONG_CHANGE = "WRONG_CHANGE";

struct P2MRSpend {
    std::vector<unsigned char> leaf_script;
    std::vector<unsigned char> control_block;
    uint8_t leaf_version{P2MR_LEAF_VERSION};
};

struct Input {
    Txid txid;
    uint32_t vout{0};
    //! Atomic units (satoshis). Negative means missing — ValidateStructure fails closed.
    CAmount amount{-1};
    CScript script_pub_key;
    std::optional<P2MRSpend> p2mr;
    //! `m/87h/...` when known. Absent on watch-only pool addresses.
    std::optional<std::string> derivation_path;
    std::optional<std::string> master_fingerprint;
    std::vector<unsigned char> pubkey;
    std::optional<PQAlgorithm> algo;
    //! Canonical P2MR sighash (32 bytes), hex in JSON.
    std::optional<uint256> digest;
    std::vector<unsigned char> signature;
};

struct ChangeOutput {
    uint32_t vout{0};
    CAmount amount{0};
    CScript script_pub_key;
    std::optional<std::string> derivation_path;
};

/** In-memory BTXPSBT-like unsigned/signed package. JSON via Encode/Decode. */
struct Package {
    uint32_t version{PACKAGE_VERSION};
    std::string profile{PROFILE_ID};
    std::string format{FORMAT_ID};
    std::string chain{CHAIN_ID};
    //! ChainTypeToString: "main", "test", "testnet4", "signet", "regtest", "shieldedv2dev".
    std::string network;
    //! SIGHASH_DEFAULT (0). Custody packages reject ANYONECANPAY.
    uint8_t sighash{0};
    CMutableTransaction unsigned_tx;
    std::vector<Input> inputs;
    std::vector<ChangeOutput> change;
};

/**
 * RPC calling sequence (wallet/rpc/bcp1.cpp):
 *
 *   prepareexternalsign
 *     createpsbt / fundrawtransaction (watch-only, no private keys)
 *     FromPSBT(psbt, Params().GetChainTypeString(), pkg, err)
 *       or FromUnsignedTx(mtx, prevouts, network, pkg, err) then fill p2mr/pubkey/path
 *     FillCanonicalDigests(pkg, err)
 *     ValidateStructure(pkg, err)
 *     return Encode(pkg)          // do not broadcast; never emits automatic_spend_atoms
 *
 *   getsigningdigests
 *     Decode(request, pkg, err) → FillCanonicalDigests → Encode (top-level "digests")
 *
 *   finalizeexternalsign
 *     Decode(package, pkg, err)
 *     InsertSignature(pkg, i, pubkey, sig, err)   // or SignBcp1Package(signer, pkg, err)
 *     PackageReadyToBroadcast(pkg, err)
 *     ApplyToPSBT / TryExtractSignedTx
 *     return hex; caller uses testmempoolaccept + sendrawtransaction
 *
 *   deriveexchangeaddress / getexchangereadiness
 *     MakeCommandSigner(-signer, chain, fingerprint)
 *     Health() → p2mr + pq_algorithms
 *     GetPublicKey(path, algo) for signer-exported keys
 *     DerivePublicKey(...) → PUBLIC_CHILD_UNSUPPORTED (use importdepositpool)
 */
bool ParseAlgo(const std::string& name, PQAlgorithm& algo);
std::string FormatAlgo(PQAlgorithm algo);

/** Witness-v2 P2MR address. Empty `slh_dsa` → single ML-DSA leaf; both set →
 *  default wallet tree `mr(ML-DSA, pk_slh(SLH-DSA))`. */
std::string EncodeP2MRFromPubkeys(Span<const unsigned char> ml_dsa,
                                  Span<const unsigned char> slh_dsa = {});

/** Accepts `m/87h/...` and `m/87'/...`. */
bool ParseDerivationPath(const std::string& path, std::vector<uint32_t>& out);

/**
 * Encode an in-memory package to a JSON object.
 * Never emits `automatic_spend_atoms` (that field is a modelnet gate, not a
 * wallet spend). Secrets/seeds are never serialized.
 */
UniValue Encode(const Package& pkg);

/** Decode JSON into a package. Fails closed if `automatic_spend_atoms` appears. */
bool Decode(const UniValue& in, Package& pkg, std::string& error);

/**
 * Structural checks for an unsigned or signed package:
 * required prevout (txid/vout/scriptPubKey) and amount on every input,
 * unsigned_tx present and consistent, unique prevouts, sighash DEFAULT,
 * P2MR leaf+control committed to the witness-v2 program, change scripts
 * matching unsigned_tx vout when present. Does not require signatures or
 * digests. `automatic_spend_atoms` is rejected at Decode.
 */
bool ValidateStructure(const Package& pkg, std::string& error);

/**
 * Compute canonical P2MR sighashes (same construction as ComputeP2MRSighash
 * in src/test/pq_consensus_tests.cpp: SignatureHashSchnorr, SigVersion::P2MR,
 * epoch 2, DEFAULT ≡ ALL). Fails closed on missing prevout/amount/leaf.
 */
bool FillCanonicalDigests(Package& pkg, std::string& error);

/**
 * Insert a signature for `input_index`. Requires pubkey, algo, and digest on
 * that input; verifies the PQ signature against the digest (fail closed on a
 * corrupt ML-DSA/SLH-DSA sig).
 */
bool InsertSignature(Package& pkg, size_t input_index, Span<const unsigned char> signature, std::string& error);
bool InsertSignature(Package& pkg, size_t input_index,
                     Span<const unsigned char> pubkey,
                     Span<const unsigned char> signature,
                     std::string& error);

/**
 * True when every input has a verifying signature over the *recomputed*
 * canonical digest (wrong prevout/amount cannot pass). Does not broadcast.
 */
bool PackageReadyToBroadcast(const Package& pkg, std::string& error);

/** RPC: build a package from a PSBT that already has witness UTXOs + P2MR metadata. */
bool FromPSBT(const PartiallySignedTransaction& psbt, const std::string& network,
              Package& pkg, std::string& error);

/** RPC: build a package from an unsigned tx + prevouts (amount+script required). */
bool FromUnsignedTx(const CMutableTransaction& tx, const std::vector<CTxOut>& prevouts,
                    const std::string& network, Package& pkg, std::string& error);

/** Copy signatures / P2MR spend data onto a PSBT with the same unsigned tx. */
bool ApplyToPSBT(const Package& pkg, PartiallySignedTransaction& psbt, std::string& error);

/**
 * Assemble a signed CMutableTransaction with P2MR witness
 * `[signature, leaf_script, control_block]` per input. Requires
 * PackageReadyToBroadcast.
 */
bool TryExtractSignedTx(const Package& pkg, CMutableTransaction& tx, std::string& error);

} // namespace bcp1
} // namespace wallet

#endif // BITCOIN_WALLET_BCP1_PACKAGE_H
