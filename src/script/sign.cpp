// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/sign.h>

#include <consensus/amount.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/keyorigin.h>
#include <script/miniscript.h>
#include <script/pqm.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <uint256.h>
#include <util/translation.h>
#include <util/vector.h>

#include <array>
#include <optional>
#include <set>

typedef std::vector<unsigned char> valtype;

MutableTransactionSignatureCreator::MutableTransactionSignatureCreator(const CMutableTransaction& tx, unsigned int input_idx, const CAmount& amount, int hash_type)
    : m_txto{tx}, nIn{input_idx}, nHashType{hash_type}, amount{amount}, checker{&m_txto, nIn, amount, MissingDataBehavior::FAIL},
      m_txdata(nullptr)
{
}

MutableTransactionSignatureCreator::MutableTransactionSignatureCreator(const CMutableTransaction& tx, unsigned int input_idx, const CAmount& amount, const PrecomputedTransactionData* txdata, int hash_type)
    : m_txto{tx}, nIn{input_idx}, nHashType{hash_type}, amount{amount},
      checker{txdata ? MutableTransactionSignatureChecker{&m_txto, nIn, amount, *txdata, MissingDataBehavior::FAIL} :
                       MutableTransactionSignatureChecker{&m_txto, nIn, amount, MissingDataBehavior::FAIL}},
      m_txdata(txdata)
{
}

bool MutableTransactionSignatureCreator::CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& address, const CScript& scriptCode, SigVersion sigversion) const
{
    assert(sigversion == SigVersion::BASE || sigversion == SigVersion::WITNESS_V0);

    CKey key;
    if (!provider.GetKey(address, key))
        return false;

    // Signing with uncompressed keys is disabled in witness scripts
    if (sigversion == SigVersion::WITNESS_V0 && !key.IsCompressed())
        return false;

    // Signing without known amount does not work in witness scripts.
    if (sigversion == SigVersion::WITNESS_V0 && !MoneyRange(amount)) return false;

    // BASE/WITNESS_V0 signatures don't support explicit SIGHASH_DEFAULT, use SIGHASH_ALL instead.
    const int hashtype = nHashType == SIGHASH_DEFAULT ? SIGHASH_ALL : nHashType;

    uint256 hash = SignatureHash(scriptCode, m_txto, nIn, hashtype, amount, sigversion, m_txdata);
    if (!key.Sign(hash, vchSig))
        return false;
    vchSig.push_back((unsigned char)hashtype);
    return true;
}

bool MutableTransactionSignatureCreator::CreateSchnorrSig(const SigningProvider& provider, std::vector<unsigned char>& sig, const XOnlyPubKey& pubkey, const uint256* leaf_hash, const uint256* merkle_root, SigVersion sigversion) const
{
    assert(sigversion == SigVersion::TAPROOT || sigversion == SigVersion::TAPSCRIPT);

    CKey key;
    if (!provider.GetKeyByXOnly(pubkey, key)) return false;

    // BIP341/BIP342 signing needs lots of precomputed transaction data. While some
    // (non-SIGHASH_DEFAULT) sighash modes exist that can work with just some subset
    // of data present, for now, only support signing when everything is provided.
    if (!m_txdata || !m_txdata->m_bip341_taproot_ready || !m_txdata->m_spent_outputs_ready) return false;

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false; // Only support annex-less signing for now.
    if (sigversion == SigVersion::TAPSCRIPT) {
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF; // Only support non-OP_CODESEPARATOR BIP342 signing for now.
        if (!leaf_hash) return false; // BIP342 signing needs leaf hash.
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = *leaf_hash;
    }
    uint256 hash;
    if (!SignatureHashSchnorr(hash, execdata, m_txto, nIn, nHashType, sigversion, *m_txdata, MissingDataBehavior::FAIL)) return false;
    sig.resize(64);
    // Use uint256{} as aux_rnd for now.
    if (!key.SignSchnorr(hash, sig, merkle_root, {})) return false;
    if (nHashType) sig.push_back(nHashType);
    return true;
}

bool MutableTransactionSignatureCreator::CreatePQSig(const SigningProvider& provider, std::vector<unsigned char>& sig, Span<const unsigned char> pubkey, PQAlgorithm algo, const uint256& leaf_hash, SigVersion sigversion) const
{
    assert(sigversion == SigVersion::P2MR);

    const CPQKey* key = provider.GetPQKey(pubkey);
    if (!key || !key->IsValid() || key->GetAlgorithm() != algo) return false;

    // P2MR signing needs BIP341-style precomputed transaction data.
    if (!m_txdata || !m_txdata->m_bip341_taproot_ready || !m_txdata->m_spent_outputs_ready) return false;

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_codeseparator_pos_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFF;
    execdata.m_tapleaf_hash_init = true;
    execdata.m_tapleaf_hash = leaf_hash;

    uint256 sighash;
    if (!SignatureHashSchnorr(sighash, execdata, m_txto, nIn, nHashType, sigversion, *m_txdata, MissingDataBehavior::FAIL)) return false;
    if (!key->Sign(sighash, sig)) return false;
    if (nHashType != SIGHASH_DEFAULT) sig.push_back(static_cast<unsigned char>(nHashType));
    return true;
}

static bool GetCScript(const SigningProvider& provider, const SignatureData& sigdata, const CScriptID& scriptid, CScript& script)
{
    if (provider.GetCScript(scriptid, script)) {
        return true;
    }
    // Look for scripts in SignatureData
    if (CScriptID(sigdata.redeem_script) == scriptid) {
        script = sigdata.redeem_script;
        return true;
    } else if (CScriptID(sigdata.witness_script) == scriptid) {
        script = sigdata.witness_script;
        return true;
    }
    return false;
}

static bool GetPubKey(const SigningProvider& provider, const SignatureData& sigdata, const CKeyID& address, CPubKey& pubkey)
{
    // Look for pubkey in all partial sigs
    const auto it = sigdata.signatures.find(address);
    if (it != sigdata.signatures.end()) {
        pubkey = it->second.first;
        return true;
    }
    // Look for pubkey in pubkey lists
    const auto& pk_it = sigdata.misc_pubkeys.find(address);
    if (pk_it != sigdata.misc_pubkeys.end()) {
        pubkey = pk_it->second.first;
        return true;
    }
    const auto& tap_pk_it = sigdata.tap_pubkeys.find(address);
    if (tap_pk_it != sigdata.tap_pubkeys.end()) {
        pubkey = tap_pk_it->second.GetEvenCorrespondingCPubKey();
        return true;
    }
    // Query the underlying provider
    return provider.GetPubKey(address, pubkey);
}

static bool CreateSig(const BaseSignatureCreator& creator, SignatureData& sigdata, const SigningProvider& provider, std::vector<unsigned char>& sig_out, const CPubKey& pubkey, const CScript& scriptcode, SigVersion sigversion)
{
    CKeyID keyid = pubkey.GetID();
    const auto it = sigdata.signatures.find(keyid);
    if (it != sigdata.signatures.end()) {
        sig_out = it->second.second;
        return true;
    }
    KeyOriginInfo info;
    if (provider.GetKeyOrigin(keyid, info)) {
        sigdata.misc_pubkeys.emplace(keyid, std::make_pair(pubkey, std::move(info)));
    }
    if (creator.CreateSig(provider, sig_out, keyid, scriptcode, sigversion)) {
        auto i = sigdata.signatures.emplace(keyid, SigPair(pubkey, sig_out));
        assert(i.second);
        return true;
    }
    // Could not make signature or signature not found, add keyid to missing
    sigdata.missing_sigs.push_back(keyid);
    return false;
}

static bool CreateTaprootScriptSig(const BaseSignatureCreator& creator, SignatureData& sigdata, const SigningProvider& provider, std::vector<unsigned char>& sig_out, const XOnlyPubKey& pubkey, const uint256& leaf_hash, SigVersion sigversion)
{
    KeyOriginInfo info;
    if (provider.GetKeyOriginByXOnly(pubkey, info)) {
        auto it = sigdata.taproot_misc_pubkeys.find(pubkey);
        if (it == sigdata.taproot_misc_pubkeys.end()) {
            sigdata.taproot_misc_pubkeys.emplace(pubkey, std::make_pair(std::set<uint256>({leaf_hash}), info));
        } else {
            it->second.first.insert(leaf_hash);
        }
    }

    auto lookup_key = std::make_pair(pubkey, leaf_hash);
    auto it = sigdata.taproot_script_sigs.find(lookup_key);
    if (it != sigdata.taproot_script_sigs.end()) {
        sig_out = it->second;
        return true;
    }
    if (creator.CreateSchnorrSig(provider, sig_out, pubkey, &leaf_hash, nullptr, sigversion)) {
        sigdata.taproot_script_sigs[lookup_key] = sig_out;
        return true;
    }
    return false;
}

static bool IsDefinedP2MRSighashType(uint8_t hash_type)
{
    const uint8_t base_type = hash_type & ~SIGHASH_ANYONECANPAY;
    return base_type == SIGHASH_ALL || base_type == SIGHASH_NONE || base_type == SIGHASH_SINGLE;
}

static bool CreateP2MRScriptSig(const BaseSignatureCreator& creator,
                                SignatureData& sigdata,
                                const SigningProvider& provider,
                                std::vector<unsigned char>& sig_out,
                                Span<const unsigned char> pubkey,
                                PQAlgorithm algo,
                                const uint256& leaf_hash,
                                SigVersion sigversion)
{
    const size_t expected_sig_size = GetPQSignatureSize(algo);
    auto lookup_key = std::make_pair(leaf_hash, std::vector<unsigned char>(pubkey.begin(), pubkey.end()));
    auto it = sigdata.p2mr_script_sigs.find(lookup_key);
    if (it != sigdata.p2mr_script_sigs.end()) {
        uint8_t hash_type = SIGHASH_DEFAULT;
        Span<const unsigned char> sig_to_check = it->second;
        bool cached_sig_well_formed = true;
        if (sig_to_check.size() == expected_sig_size + 1) {
            hash_type = sig_to_check.back();
            sig_to_check = sig_to_check.first(expected_sig_size);
            cached_sig_well_formed = IsDefinedP2MRSighashType(hash_type);
        } else if (sig_to_check.size() != expected_sig_size) {
            cached_sig_well_formed = false;
        }

        if (cached_sig_well_formed) {
            ScriptExecutionData execdata;
            execdata.m_annex_init = true;
            execdata.m_annex_present = false;
            execdata.m_codeseparator_pos_init = true;
            execdata.m_codeseparator_pos = 0xFFFFFFFF;
            execdata.m_tapleaf_hash_init = true;
            execdata.m_tapleaf_hash = leaf_hash;
            if (creator.Checker().CheckPQSignature(sig_to_check, pubkey, algo, hash_type, sigversion, execdata)) {
                sig_out = it->second;
                return true;
            }
        }

        // Stale or malformed cached signatures must not block this signer from replacing them.
        sigdata.p2mr_script_sigs.erase(it);
    }
    if (creator.CreatePQSig(provider, sig_out, pubkey, algo, leaf_hash, sigversion)) {
        sigdata.p2mr_script_sigs[std::move(lookup_key)] = sig_out;
        return true;
    }
    return false;
}

static bool CreateP2MRCSFSSig(SignatureData& sigdata,
                              const SigningProvider& provider,
                              std::vector<unsigned char>& sig_out,
                              Span<const unsigned char> pubkey,
                              PQAlgorithm algo,
                              const uint256& leaf_hash,
                              Span<const unsigned char> msg)
{
    const size_t expected_sig_size = GetPQSignatureSize(algo);
    const auto lookup_key = std::make_pair(leaf_hash, std::vector<unsigned char>(pubkey.begin(), pubkey.end()));
    auto it = sigdata.p2mr_csfs_sigs.find(lookup_key);
    if (it != sigdata.p2mr_csfs_sigs.end()) {
        if (it->second.size() == expected_sig_size) {
            const CPQPubKey verifier(algo, pubkey);
            HashWriter hasher = HASHER_CSFS;
            hasher.write(AsBytes(msg));
            if (verifier.Verify(hasher.GetSHA256(), it->second)) {
                sig_out = it->second;
                return true;
            }
        }
        sigdata.p2mr_csfs_sigs.erase(it);
    }

    const CPQKey* key = provider.GetPQKey(pubkey);
    if (key == nullptr || !key->IsValid() || key->GetAlgorithm() != algo) return false;
    HashWriter hasher = HASHER_CSFS;
    hasher.write(AsBytes(msg));
    if (!key->Sign(hasher.GetSHA256(), sig_out)) return false;
    sigdata.p2mr_csfs_sigs.emplace(lookup_key, sig_out);
    return true;
}

template<typename M, typename K, typename V>
miniscript::Availability MsLookupHelper(const M& map, const K& key, V& value)
{
    auto it = map.find(key);
    if (it != map.end()) {
        value = it->second;
        return miniscript::Availability::YES;
    }
    return miniscript::Availability::NO;
}

/**
 * Context for solving a Miniscript.
 * If enough material (access to keys, hash preimages, ..) is given, produces a valid satisfaction.
 */
template<typename Pk>
struct Satisfier {
    using Key = Pk;

    const SigningProvider& m_provider;
    SignatureData& m_sig_data;
    const BaseSignatureCreator& m_creator;
    const CScript& m_witness_script;
    //! The context of the script we are satisfying (either P2WSH or Tapscript).
    const miniscript::MiniscriptContext m_script_ctx;

    explicit Satisfier(const SigningProvider& provider LIFETIMEBOUND, SignatureData& sig_data LIFETIMEBOUND,
                       const BaseSignatureCreator& creator LIFETIMEBOUND,
                       const CScript& witscript LIFETIMEBOUND,
                       miniscript::MiniscriptContext script_ctx) : m_provider(provider),
                                                                   m_sig_data(sig_data),
                                                                   m_creator(creator),
                                                                   m_witness_script(witscript),
                                                                   m_script_ctx(script_ctx) {}

    static bool KeyCompare(const Key& a, const Key& b) {
        return a < b;
    }

    //! Get a CPubKey from a key hash. Note the key hash may be of an xonly pubkey.
    template<typename I>
    std::optional<CPubKey> CPubFromPKHBytes(I first, I last) const {
        assert(last - first == 20);
        CPubKey pubkey;
        CKeyID key_id;
        std::copy(first, last, key_id.begin());
        if (GetPubKey(m_provider, m_sig_data, key_id, pubkey)) return pubkey;
        m_sig_data.missing_pubkeys.push_back(key_id);
        return {};
    }

    //! Conversion to raw public key.
    std::vector<unsigned char> ToPKBytes(const Key& key) const { return {key.begin(), key.end()}; }

    //! Time lock satisfactions.
    bool CheckAfter(uint32_t value) const { return m_creator.Checker().CheckLockTime(CScriptNum(value)); }
    bool CheckOlder(uint32_t value) const { return m_creator.Checker().CheckSequence(CScriptNum(value)); }

    //! Hash preimage satisfactions.
    miniscript::Availability SatSHA256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.sha256_preimages, hash, preimage);
    }
    miniscript::Availability SatRIPEMD160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.ripemd160_preimages, hash, preimage);
    }
    miniscript::Availability SatHASH256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.hash256_preimages, hash, preimage);
    }
    miniscript::Availability SatHASH160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.hash160_preimages, hash, preimage);
    }

    miniscript::MiniscriptContext MsContext() const {
        return m_script_ctx;
    }
};

/** Miniscript satisfier specific to P2WSH context. */
struct WshSatisfier: Satisfier<CPubKey> {
    explicit WshSatisfier(const SigningProvider& provider LIFETIMEBOUND, SignatureData& sig_data LIFETIMEBOUND,
                          const BaseSignatureCreator& creator LIFETIMEBOUND, const CScript& witscript LIFETIMEBOUND)
                          : Satisfier(provider, sig_data, creator, witscript, miniscript::MiniscriptContext::P2WSH) {}

    //! Conversion from a raw compressed public key.
    template <typename I>
    std::optional<CPubKey> FromPKBytes(I first, I last) const {
        CPubKey pubkey{first, last};
        if (pubkey.IsValid()) return pubkey;
        return {};
    }

    //! Conversion from a raw compressed public key hash.
    template<typename I>
    std::optional<CPubKey> FromPKHBytes(I first, I last) const {
        return Satisfier::CPubFromPKHBytes(first, last);
    }

    //! Satisfy an ECDSA signature check.
    miniscript::Availability Sign(const CPubKey& key, std::vector<unsigned char>& sig) const {
        if (CreateSig(m_creator, m_sig_data, m_provider, sig, key, m_witness_script, SigVersion::WITNESS_V0)) {
            return miniscript::Availability::YES;
        }
        return miniscript::Availability::NO;
    }
};

/** Miniscript satisfier specific to Tapscript context. */
struct TapSatisfier: Satisfier<XOnlyPubKey> {
    const uint256& m_leaf_hash;

    explicit TapSatisfier(const SigningProvider& provider LIFETIMEBOUND, SignatureData& sig_data LIFETIMEBOUND,
                          const BaseSignatureCreator& creator LIFETIMEBOUND, const CScript& script LIFETIMEBOUND,
                          const uint256& leaf_hash LIFETIMEBOUND)
                          : Satisfier(provider, sig_data, creator, script, miniscript::MiniscriptContext::TAPSCRIPT),
                            m_leaf_hash(leaf_hash) {}

    //! Conversion from a raw xonly public key.
    template <typename I>
    std::optional<XOnlyPubKey> FromPKBytes(I first, I last) const {
        if (last - first != 32) return {};
        XOnlyPubKey pubkey;
        std::copy(first, last, pubkey.begin());
        return pubkey;
    }

    //! Conversion from a raw xonly public key hash.
    template<typename I>
    std::optional<XOnlyPubKey> FromPKHBytes(I first, I last) const {
        if (auto pubkey = Satisfier::CPubFromPKHBytes(first, last)) return XOnlyPubKey{*pubkey};
        return {};
    }

    //! Satisfy a BIP340 signature check.
    miniscript::Availability Sign(const XOnlyPubKey& key, std::vector<unsigned char>& sig) const {
        if (CreateTaprootScriptSig(m_creator, m_sig_data, m_provider, sig, key, m_leaf_hash, SigVersion::TAPSCRIPT)) {
            return miniscript::Availability::YES;
        }
        return miniscript::Availability::NO;
    }
};

static bool SignTaprootScript(const SigningProvider& provider, const BaseSignatureCreator& creator, SignatureData& sigdata, int leaf_version, Span<const unsigned char> script_bytes, std::vector<valtype>& result)
{
    // Only BIP342 tapscript signing is supported for now.
    if (leaf_version != TAPROOT_LEAF_TAPSCRIPT) return false;

    uint256 leaf_hash = ComputeTapleafHash(leaf_version, script_bytes);
    CScript script = CScript(script_bytes.begin(), script_bytes.end());

    TapSatisfier ms_satisfier{provider, sigdata, creator, script, leaf_hash};
    const auto ms = miniscript::FromScript(script, ms_satisfier);
    return ms && ms->Satisfy(ms_satisfier, result) == miniscript::Availability::YES;
}

static bool SignTaproot(const SigningProvider& provider, const BaseSignatureCreator& creator, const WitnessV1Taproot& output, SignatureData& sigdata, std::vector<valtype>& result)
{
    TaprootSpendData spenddata;
    TaprootBuilder builder;

    // Gather information about this output.
    if (provider.GetTaprootSpendData(output, spenddata)) {
        sigdata.tr_spenddata.Merge(spenddata);
    }
    if (provider.GetTaprootBuilder(output, builder)) {
        sigdata.tr_builder = builder;
    }

    // Try key path spending.
    {
        KeyOriginInfo info;
        if (provider.GetKeyOriginByXOnly(sigdata.tr_spenddata.internal_key, info)) {
            auto it = sigdata.taproot_misc_pubkeys.find(sigdata.tr_spenddata.internal_key);
            if (it == sigdata.taproot_misc_pubkeys.end()) {
                sigdata.taproot_misc_pubkeys.emplace(sigdata.tr_spenddata.internal_key, std::make_pair(std::set<uint256>(), info));
            }
        }

        std::vector<unsigned char> sig;
        if (sigdata.taproot_key_path_sig.size() == 0) {
            if (creator.CreateSchnorrSig(provider, sig, sigdata.tr_spenddata.internal_key, nullptr, &sigdata.tr_spenddata.merkle_root, SigVersion::TAPROOT)) {
                sigdata.taproot_key_path_sig = sig;
            }
        }
        if (sigdata.taproot_key_path_sig.size() == 0) {
            if (creator.CreateSchnorrSig(provider, sig, output, nullptr, nullptr, SigVersion::TAPROOT)) {
                sigdata.taproot_key_path_sig = sig;
            }
        }
        if (sigdata.taproot_key_path_sig.size()) {
            result = Vector(sigdata.taproot_key_path_sig);
            return true;
        }
    }

    // Try script path spending.
    std::vector<std::vector<unsigned char>> smallest_result_stack;
    for (const auto& [key, control_blocks] : sigdata.tr_spenddata.scripts) {
        const auto& [script, leaf_ver] = key;
        std::vector<std::vector<unsigned char>> result_stack;
        if (SignTaprootScript(provider, creator, sigdata, leaf_ver, script, result_stack)) {
            result_stack.emplace_back(std::begin(script), std::end(script)); // Push the script
            result_stack.push_back(*control_blocks.begin()); // Push the smallest control block
            if (smallest_result_stack.size() == 0 ||
                GetSerializeSize(result_stack) < GetSerializeSize(smallest_result_stack)) {
                smallest_result_stack = std::move(result_stack);
            }
        }
    }
    if (smallest_result_stack.size() != 0) {
        result = std::move(smallest_result_stack);
        return true;
    }

    return false;
}

enum class P2MRLeafType {
    CHECKSIG,
    MULTISIG,
    CLTV_CHECKSIG,
    CLTV_MULTISIG,
    CSV_MULTISIG,
    CTV_ONLY,
    CTV_CSFS_ONLY,
    CTV_CHECKSIG,
    CTV_MULTISIG,
    CSFS_ONLY,
    CSFS_VERIFY_CHECKSIG,
};

struct P2MRLeafInfo {
    P2MRLeafType type;
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    Span<const unsigned char> pubkey{};
    uint8_t multisig_threshold{0};
    std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> multisig_pubkeys;
    PQAlgorithm csfs_algo{PQAlgorithm::ML_DSA_44};
    Span<const unsigned char> csfs_pubkey{};
    uint256 ctv_hash{};
};

static bool ParseP2MRChecksigLeaf(Span<const unsigned char> script, size_t offset, P2MRLeafInfo& info, size_t& consumed)
{
    Span<const unsigned char> pubkey;
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    size_t push_consumed{0};
    if (!ParseP2MRAnyPubkeyPush(script, offset, algo, pubkey, push_consumed)) return false;
    if (script.size() != offset + push_consumed + 1 || script[offset + push_consumed] != GetP2MRChecksigOpcode(algo)) return false;
    info.type = P2MRLeafType::CHECKSIG;
    info.algo = algo;
    info.pubkey = pubkey;
    consumed = push_consumed + 1;
    return true;
}

static bool ParseP2MRCSFSLeaf(Span<const unsigned char> script, size_t offset, P2MRLeafInfo& info, size_t& consumed)
{
    Span<const unsigned char> pubkey;
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    size_t push_consumed{0};
    if (!ParseP2MRAnyPubkeyPush(script, offset, algo, pubkey, push_consumed)) return false;
    if (script.size() != offset + push_consumed + 1 || script[offset + push_consumed] != OP_CHECKSIGFROMSTACK) return false;
    info.type = P2MRLeafType::CSFS_ONLY;
    info.csfs_algo = algo;
    info.csfs_pubkey = pubkey;
    consumed = push_consumed + 1;
    return true;
}

static bool ParseP2MRTimelockPrefix(Span<const unsigned char> script, opcodetype timelock_opcode, int64_t& value, size_t& consumed)
{
    const CScript script_obj(script.begin(), script.end());
    CScript::const_iterator pc = script_obj.begin();
    opcodetype opcode{OP_INVALIDOPCODE};
    std::vector<unsigned char> push_data;
    if (!script_obj.GetOp(pc, opcode, push_data)) return false;

    try {
        switch (opcode) {
        case OP_0:
            value = 0;
            break;
        case OP_1NEGATE:
            value = -1;
            break;
        default:
            if (opcode >= OP_1 && opcode <= OP_16) {
                value = CScript::DecodeOP_N(opcode);
            } else if (!push_data.empty()) {
                value = CScriptNum(push_data, /*fRequireMinimal=*/false, /*nMaxNumSize=*/5).GetInt64();
            } else {
                return false;
            }
            break;
        }
    } catch (const scriptnum_error&) {
        return false;
    }

    switch (opcode) {
    case OP_0:
        break;
    case OP_1NEGATE:
        break;
    default:
        if (((opcode < OP_1) || (opcode > OP_16)) && push_data.empty()) return false;
        break;
    }

    if (!script_obj.GetOp(pc, opcode, push_data) || opcode != timelock_opcode) return false;
    if (!script_obj.GetOp(pc, opcode, push_data) || opcode != OP_DROP) return false;
    consumed = std::distance(script_obj.begin(), pc);
    return true;
}

static bool ParseP2MRCLTVPrefix(Span<const unsigned char> script, size_t& consumed)
{
    int64_t ignored_value{0};
    return ParseP2MRTimelockPrefix(script, OP_CHECKLOCKTIMEVERIFY, ignored_value, consumed);
}

static bool ParseP2MRCSVPrefix(Span<const unsigned char> script, size_t& consumed)
{
    int64_t ignored_value{0};
    return ParseP2MRTimelockPrefix(script, OP_CHECKSEQUENCEVERIFY, ignored_value, consumed);
}

static bool ParseP2MRCLTVChecksigLeaf(Span<const unsigned char> script, P2MRLeafInfo& info)
{
    size_t prefix_consumed{0};
    if (!ParseP2MRCLTVPrefix(script, prefix_consumed) || prefix_consumed >= script.size()) return false;

    const Span<const unsigned char> checksig_tail = script.subspan(prefix_consumed);
    P2MRLeafInfo checksig_info;
    size_t consumed{0};
    if (!ParseP2MRChecksigLeaf(checksig_tail, /*offset=*/0, checksig_info, consumed)) return false;
    if (consumed != checksig_tail.size()) return false;

    info.type = P2MRLeafType::CLTV_CHECKSIG;
    info.algo = checksig_info.algo;
    info.pubkey = checksig_info.pubkey;
    return true;
}

static bool ParseP2MRMultisigLeaf(Span<const unsigned char> script, P2MRLeafInfo& info)
{
    size_t offset{0};
    std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> keys;
    std::set<std::pair<PQAlgorithm, std::vector<unsigned char>>> unique_keys;
    while (offset < script.size()) {
        Span<const unsigned char> pubkey;
        PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
        size_t push_consumed{0};
        if (!ParseP2MRAnyPubkeyPush(script, offset, algo, pubkey, push_consumed)) break;

        offset += push_consumed;
        if (offset >= script.size()) return false;
        const opcodetype observed = static_cast<opcodetype>(script[offset]);
        const opcodetype expected = keys.empty() ? GetP2MRChecksigOpcode(algo) : GetP2MRChecksigAddOpcode(algo);
        if (observed != expected) return false;
        ++offset;

        std::vector<unsigned char> key_bytes(pubkey.begin(), pubkey.end());
        if (!unique_keys.emplace(algo, key_bytes).second) return false;
        keys.emplace_back(algo, std::move(key_bytes));
    }

    if (keys.size() < 2) return false;
    if (offset + 2 != script.size()) return false;

    const opcodetype threshold_opcode = static_cast<opcodetype>(script[offset]);
    if (threshold_opcode < OP_1 || threshold_opcode > OP_16) return false;
    const uint8_t threshold = static_cast<uint8_t>(CScript::DecodeOP_N(threshold_opcode));
    if (threshold == 0 || threshold > keys.size()) return false;
    if (static_cast<opcodetype>(script[offset + 1]) != OP_NUMEQUAL) return false;

    info.type = P2MRLeafType::MULTISIG;
    info.multisig_threshold = threshold;
    info.multisig_pubkeys = std::move(keys);
    return true;
}

static bool ExtractP2MRLeafInfo(Span<const unsigned char> script, P2MRLeafInfo& info)
{
    if (script.size() == 34 && script[0] == 32 && script[33] == OP_CHECKTEMPLATEVERIFY) {
        info.type = P2MRLeafType::CTV_ONLY;
        info.ctv_hash = uint256{script.subspan(1, uint256::size())};
        return true;
    }

    if (script.size() > 35 && script[0] == 32 && script[33] == OP_CHECKTEMPLATEVERIFY && script[34] == OP_DROP) {
        P2MRLeafInfo csfs_info;
        size_t consumed{0};
        if (ParseP2MRCSFSLeaf(script, /*offset=*/35, csfs_info, consumed)) {
            if (35 + consumed != script.size()) return false;
            info.type = P2MRLeafType::CTV_CSFS_ONLY;
            info.ctv_hash = uint256{script.subspan(1, uint256::size())};
            info.csfs_algo = csfs_info.csfs_algo;
            info.csfs_pubkey = csfs_info.csfs_pubkey;
            return true;
        }

        P2MRLeafInfo checksig_info;
        consumed = 0;
        if (ParseP2MRChecksigLeaf(script, /*offset=*/35, checksig_info, consumed)) {
            if (35 + consumed != script.size()) return false;
            info.type = P2MRLeafType::CTV_CHECKSIG;
            info.ctv_hash = uint256{script.subspan(1, uint256::size())};
            info.algo = checksig_info.algo;
            info.pubkey = checksig_info.pubkey;
            return true;
        }

        P2MRLeafInfo multisig_info;
        if (ParseP2MRMultisigLeaf(script.subspan(35), multisig_info)) {
            info.type = P2MRLeafType::CTV_MULTISIG;
            info.ctv_hash = uint256{script.subspan(1, uint256::size())};
            info.multisig_threshold = multisig_info.multisig_threshold;
            info.multisig_pubkeys = std::move(multisig_info.multisig_pubkeys);
            return true;
        }
        return false;
    }

    if (ParseP2MRCLTVChecksigLeaf(script, info)) {
        return true;
    }

    size_t cltv_prefix_consumed{0};
    if (ParseP2MRCLTVPrefix(script, cltv_prefix_consumed) && cltv_prefix_consumed < script.size()) {
        P2MRLeafInfo multisig_info;
        if (ParseP2MRMultisigLeaf(script.subspan(cltv_prefix_consumed), multisig_info)) {
            info.type = P2MRLeafType::CLTV_MULTISIG;
            info.multisig_threshold = multisig_info.multisig_threshold;
            info.multisig_pubkeys = std::move(multisig_info.multisig_pubkeys);
            return true;
        }
    }

    size_t csv_prefix_consumed{0};
    if (ParseP2MRCSVPrefix(script, csv_prefix_consumed) && csv_prefix_consumed < script.size()) {
        P2MRLeafInfo multisig_info;
        if (ParseP2MRMultisigLeaf(script.subspan(csv_prefix_consumed), multisig_info)) {
            info.type = P2MRLeafType::CSV_MULTISIG;
            info.multisig_threshold = multisig_info.multisig_threshold;
            info.multisig_pubkeys = std::move(multisig_info.multisig_pubkeys);
            return true;
        }
    }

    Span<const unsigned char> csfs_pubkey;
    PQAlgorithm csfs_algo{PQAlgorithm::ML_DSA_44};
    size_t csfs_push_consumed{0};
    if (ParseP2MRAnyPubkeyPush(script, 0, csfs_algo, csfs_pubkey, csfs_push_consumed)) {
        if (script.size() == csfs_push_consumed + 1 && script[csfs_push_consumed] == OP_CHECKSIGFROMSTACK) {
            info.type = P2MRLeafType::CSFS_ONLY;
            info.csfs_algo = csfs_algo;
            info.csfs_pubkey = csfs_pubkey;
            return true;
        }
        if (script.size() > csfs_push_consumed + 2 &&
            script[csfs_push_consumed] == OP_CHECKSIGFROMSTACK &&
            script[csfs_push_consumed + 1] == OP_VERIFY) {
            P2MRLeafInfo checksig_info;
            size_t consumed{0};
            if (!ParseP2MRChecksigLeaf(script, csfs_push_consumed + 2, checksig_info, consumed)) return false;
            if (csfs_push_consumed + 2 + consumed != script.size()) return false;
            info.type = P2MRLeafType::CSFS_VERIFY_CHECKSIG;
            info.csfs_algo = csfs_algo;
            info.csfs_pubkey = csfs_pubkey;
            info.algo = checksig_info.algo;
            info.pubkey = checksig_info.pubkey;
            return true;
        }
    }

    if (ParseP2MRMultisigLeaf(script, info)) return true;

    size_t consumed{0};
    return ParseP2MRChecksigLeaf(script, /*offset=*/0, info, consumed);
}

static PQAlgorithm GetPreferredP2MRAlgo(const SignatureData& sigdata)
{
    return sigdata.preferred_pq_signing_algo.value_or(PQAlgorithm::ML_DSA_44);
}

static std::array<PQAlgorithm, 2> GetP2MRAlgoPreferenceOrder(PQAlgorithm preferred_algo)
{
    return preferred_algo == PQAlgorithm::SLH_DSA_128S
        ? std::array<PQAlgorithm, 2>{PQAlgorithm::SLH_DSA_128S, PQAlgorithm::ML_DSA_44}
        : std::array<PQAlgorithm, 2>{PQAlgorithm::ML_DSA_44, PQAlgorithm::SLH_DSA_128S};
}

static int P2MRPriority(PQAlgorithm algo, PQAlgorithm preferred_algo, int preferred_priority, int non_preferred_priority)
{
    return algo == preferred_algo ? preferred_priority : non_preferred_priority;
}

static bool SignP2MR(const SigningProvider& provider,
                     const BaseSignatureCreator& creator,
                     const WitnessV2P2MR& output,
                     SignatureData& sigdata,
                     std::vector<valtype>& result)
{
    const PQAlgorithm preferred_algo = GetPreferredP2MRAlgo(sigdata);

    P2MRSpendData spenddata;
    if (provider.GetP2MRSpendData(output, spenddata)) {
        sigdata.p2mr_spenddata.Merge(spenddata);
    }
    if (!sigdata.p2mr_leaf_script.empty() && !sigdata.p2mr_control_block.empty()) {
        sigdata.p2mr_spenddata.scripts[sigdata.p2mr_leaf_script].insert(sigdata.p2mr_control_block);
    }
    if (sigdata.p2mr_spenddata.scripts.empty()) return false;

    bool have_best{false};
    int best_priority{0};
    std::vector<valtype> best_result;
    std::vector<unsigned char> best_script;
    std::vector<unsigned char> best_control;
    const auto commit_candidate = [&](int priority,
                                      std::vector<valtype>&& candidate_result,
                                      const std::vector<unsigned char>& candidate_script,
                                      const std::vector<unsigned char>& candidate_control) {
        if (!have_best || priority < best_priority) {
            have_best = true;
            best_priority = priority;
            best_result = std::move(candidate_result);
            best_script = candidate_script;
            best_control = candidate_control;
        }
    };

    for (const auto& [script, controls] : sigdata.p2mr_spenddata.scripts) {
        if (controls.empty()) continue;
        if (!sigdata.p2mr_leaf_script.empty() && script != sigdata.p2mr_leaf_script) continue;

        const std::vector<unsigned char>* control{nullptr};
        if (!sigdata.p2mr_control_block.empty()) {
            if (controls.count(sigdata.p2mr_control_block) == 0) continue;
            control = &sigdata.p2mr_control_block;
        } else {
            control = &*controls.begin();
        }

        P2MRLeafInfo leaf_info;
        if (!ExtractP2MRLeafInfo(script, leaf_info)) continue;

        const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, script);
        const std::vector<unsigned char> script_bytes(script.begin(), script.end());
        switch (leaf_info.type) {
        case P2MRLeafType::CHECKSIG:
        case P2MRLeafType::CLTV_CHECKSIG:
        case P2MRLeafType::CTV_CHECKSIG: {
            std::vector<unsigned char> sig;
            if (!CreateP2MRScriptSig(creator, sigdata, provider, sig, leaf_info.pubkey, leaf_info.algo, leaf_hash, SigVersion::P2MR)) {
                continue;
            }
            std::vector<valtype> candidate = Vector(sig, script_bytes, *control);
            const int priority = P2MRPriority(leaf_info.algo, preferred_algo, /*preferred_priority=*/0, /*non_preferred_priority=*/10);
            if (priority == 0) {
                sigdata.p2mr_leaf_script = script;
                sigdata.p2mr_control_block = *control;
                result = std::move(candidate);
                return true;
            }
            commit_candidate(priority, std::move(candidate), script_bytes, *control);
            continue;
        }
        case P2MRLeafType::MULTISIG:
        case P2MRLeafType::CLTV_MULTISIG:
        case P2MRLeafType::CSV_MULTISIG:
        case P2MRLeafType::CTV_MULTISIG: {
            std::vector<std::vector<unsigned char>> available_sigs;
            available_sigs.reserve(leaf_info.multisig_pubkeys.size());
            size_t available_count{0};
            for (const auto& [algo, pubkey] : leaf_info.multisig_pubkeys) {
                std::vector<unsigned char> sig;
                if (CreateP2MRScriptSig(creator, sigdata, provider, sig, pubkey, algo, leaf_hash, SigVersion::P2MR)) {
                    ++available_count;
                }
                available_sigs.push_back(std::move(sig));
            }

            if (available_count < leaf_info.multisig_threshold) continue;

            std::vector<std::vector<unsigned char>> selected_sigs(available_sigs.size());
            size_t selected_count{0};
            int non_preferred_selected{0};

            // Prefer signatures matching requested algorithm; only use fallback algo to meet threshold.
            for (PQAlgorithm algo_preference : GetP2MRAlgoPreferenceOrder(preferred_algo)) {
                for (size_t i = 0; i < available_sigs.size() && selected_count < leaf_info.multisig_threshold; ++i) {
                    if (available_sigs[i].empty()) continue;
                    const auto algo = leaf_info.multisig_pubkeys[i].first;
                    if (algo != algo_preference) continue;
                    selected_sigs[i] = std::move(available_sigs[i]);
                    ++selected_count;
                    if (algo != preferred_algo) ++non_preferred_selected;
                }
            }
            if (selected_count != leaf_info.multisig_threshold) continue;

            std::vector<valtype> candidate;
            candidate.reserve(selected_sigs.size() + 2);
            for (size_t i = selected_sigs.size(); i > 0; --i) {
                candidate.push_back(std::move(selected_sigs[i - 1]));
            }
            candidate.push_back(script_bytes);
            candidate.push_back(*control);

            if (non_preferred_selected == 0) {
                sigdata.p2mr_leaf_script = script;
                sigdata.p2mr_control_block = *control;
                result = std::move(candidate);
                return true;
            }
            // Lower priority is better; fewer fallback-algorithm signatures is preferred.
            commit_candidate(non_preferred_selected, std::move(candidate), script_bytes, *control);
            continue;
        }
        case P2MRLeafType::CTV_ONLY: {
            // CTV-only branch has no PQ signature algorithm choice; keep as low-priority fallback.
            std::vector<valtype> candidate = Vector(script_bytes, *control);
            commit_candidate(100, std::move(candidate), script_bytes, *control);
            continue;
        }
        case P2MRLeafType::CTV_CSFS_ONLY:
        case P2MRLeafType::CSFS_ONLY: {
            const auto key = std::make_pair(leaf_hash, std::vector<unsigned char>(leaf_info.csfs_pubkey.begin(), leaf_info.csfs_pubkey.end()));
            const auto it_msg = sigdata.p2mr_csfs_msgs.find(key);
            if (it_msg == sigdata.p2mr_csfs_msgs.end()) continue;
            std::vector<unsigned char> sig_csfs;
            if (!CreateP2MRCSFSSig(sigdata, provider, sig_csfs, leaf_info.csfs_pubkey, leaf_info.csfs_algo, leaf_hash, it_msg->second)) continue;
            std::vector<valtype> candidate = Vector(sig_csfs, it_msg->second, script_bytes, *control);
            const int priority = P2MRPriority(leaf_info.csfs_algo, preferred_algo, /*preferred_priority=*/20, /*non_preferred_priority=*/30);
            commit_candidate(priority, std::move(candidate), script_bytes, *control);
            continue;
        }
        case P2MRLeafType::CSFS_VERIFY_CHECKSIG: {
            const auto csfs_key = std::make_pair(leaf_hash, std::vector<unsigned char>(leaf_info.csfs_pubkey.begin(), leaf_info.csfs_pubkey.end()));
            const auto it_msg_csfs = sigdata.p2mr_csfs_msgs.find(csfs_key);
            if (it_msg_csfs == sigdata.p2mr_csfs_msgs.end()) continue;

            std::vector<unsigned char> sig_checksig;
            if (!CreateP2MRScriptSig(creator, sigdata, provider, sig_checksig, leaf_info.pubkey, leaf_info.algo, leaf_hash, SigVersion::P2MR)) {
                continue;
            }
            std::vector<unsigned char> sig_csfs;
            if (!CreateP2MRCSFSSig(sigdata, provider, sig_csfs, leaf_info.csfs_pubkey, leaf_info.csfs_algo, leaf_hash, it_msg_csfs->second)) {
                continue;
            }
            std::vector<valtype> candidate = Vector(sig_checksig, sig_csfs, it_msg_csfs->second, script_bytes, *control);
            const int priority = P2MRPriority(leaf_info.algo, preferred_algo, /*preferred_priority=*/0, /*non_preferred_priority=*/10);
            if (priority == 0) {
                sigdata.p2mr_leaf_script = script;
                sigdata.p2mr_control_block = *control;
                result = std::move(candidate);
                return true;
            }
            commit_candidate(priority, std::move(candidate), script_bytes, *control);
            continue;
        }
        }
    }

    if (!have_best) return false;

    sigdata.p2mr_leaf_script = best_script;
    sigdata.p2mr_control_block = best_control;
    result = std::move(best_result);
    return true;
}

/**
 * Sign scriptPubKey using signature made with creator.
 * Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
 * unless whichTypeRet is TxoutType::SCRIPTHASH, in which case scriptSigRet is the redemption script.
 * Returns false if scriptPubKey could not be completely satisfied.
 */
static bool SignStep(const SigningProvider& provider, const BaseSignatureCreator& creator, const CScript& scriptPubKey,
                     std::vector<valtype>& ret, TxoutType& whichTypeRet, SigVersion sigversion, SignatureData& sigdata)
{
    CScript scriptRet;
    ret.clear();
    std::vector<unsigned char> sig;

    std::vector<valtype> vSolutions;
    whichTypeRet = Solver(scriptPubKey, vSolutions);

    switch (whichTypeRet) {
    case TxoutType::NONSTANDARD:
    case TxoutType::NULL_DATA:
    case TxoutType::WITNESS_UNKNOWN:
        return false;
    case TxoutType::PUBKEY:
        if (!CreateSig(creator, sigdata, provider, sig, CPubKey(vSolutions[0]), scriptPubKey, sigversion)) return false;
        ret.push_back(std::move(sig));
        return true;
    case TxoutType::PUBKEYHASH: {
        CKeyID keyID = CKeyID(uint160(vSolutions[0]));
        CPubKey pubkey;
        if (!GetPubKey(provider, sigdata, keyID, pubkey)) {
            // Pubkey could not be found, add to missing
            sigdata.missing_pubkeys.push_back(keyID);
            return false;
        }
        if (!CreateSig(creator, sigdata, provider, sig, pubkey, scriptPubKey, sigversion)) return false;
        ret.push_back(std::move(sig));
        ret.push_back(ToByteVector(pubkey));
        return true;
    }
    case TxoutType::SCRIPTHASH: {
        uint160 h160{vSolutions[0]};
        if (GetCScript(provider, sigdata, CScriptID{h160}, scriptRet)) {
            ret.emplace_back(scriptRet.begin(), scriptRet.end());
            return true;
        }
        // Could not find redeemScript, add to missing
        sigdata.missing_redeem_script = h160;
        return false;
    }
    case TxoutType::MULTISIG: {
        size_t required = vSolutions.front()[0];
        ret.emplace_back(); // workaround CHECKMULTISIG bug
        for (size_t i = 1; i < vSolutions.size() - 1; ++i) {
            CPubKey pubkey = CPubKey(vSolutions[i]);
            // We need to always call CreateSig in order to fill sigdata with all
            // possible signatures that we can create. This will allow further PSBT
            // processing to work as it needs all possible signature and pubkey pairs
            if (CreateSig(creator, sigdata, provider, sig, pubkey, scriptPubKey, sigversion)) {
                if (ret.size() < required + 1) {
                    ret.push_back(std::move(sig));
                }
            }
        }
        bool ok = ret.size() == required + 1;
        for (size_t i = 0; i + ret.size() < required + 1; ++i) {
            ret.emplace_back();
        }
        return ok;
    }
    case TxoutType::WITNESS_V0_KEYHASH:
        ret.push_back(vSolutions[0]);
        return true;

    case TxoutType::WITNESS_V0_SCRIPTHASH:
        if (GetCScript(provider, sigdata, CScriptID{RIPEMD160(vSolutions[0])}, scriptRet)) {
            ret.emplace_back(scriptRet.begin(), scriptRet.end());
            return true;
        }
        // Could not find witnessScript, add to missing
        sigdata.missing_witness_script = uint256(vSolutions[0]);
        return false;

    case TxoutType::WITNESS_V1_TAPROOT:
        return SignTaproot(provider, creator, WitnessV1Taproot(XOnlyPubKey{vSolutions[0]}), sigdata, ret);

    case TxoutType::WITNESS_V2_P2MR:
        return SignP2MR(provider, creator, WitnessV2P2MR(uint256{vSolutions[0]}), sigdata, ret);

    case TxoutType::ANCHOR:
        return true;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
    return false;
}

static CScript PushAll(const std::vector<valtype>& values)
{
    CScript result;
    for (const valtype& v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else if (v.size() == 1 && v[0] == 0x81) {
            result << OP_1NEGATE;
        } else {
            result << v;
        }
    }
    return result;
}

bool ProduceSignature(const SigningProvider& provider, const BaseSignatureCreator& creator, const CScript& fromPubKey, SignatureData& sigdata)
{
    if (sigdata.complete) return true;

    std::vector<valtype> result;
    TxoutType whichType;
    bool solved = SignStep(provider, creator, fromPubKey, result, whichType, SigVersion::BASE, sigdata);
    bool P2SH = false;
    CScript subscript;

    if (solved && whichType == TxoutType::SCRIPTHASH)
    {
        // Solver returns the subscript that needs to be evaluated;
        // the final scriptSig is the signatures from that
        // and then the serialized subscript:
        subscript = CScript(result[0].begin(), result[0].end());
        sigdata.redeem_script = subscript;
        solved = solved && SignStep(provider, creator, subscript, result, whichType, SigVersion::BASE, sigdata) && whichType != TxoutType::SCRIPTHASH;
        P2SH = true;
    }

    if (solved && whichType == TxoutType::WITNESS_V0_KEYHASH)
    {
        CScript witnessscript;
        witnessscript << OP_DUP << OP_HASH160 << ToByteVector(result[0]) << OP_EQUALVERIFY << OP_CHECKSIG;
        TxoutType subType;
        solved = solved && SignStep(provider, creator, witnessscript, result, subType, SigVersion::WITNESS_V0, sigdata);
        sigdata.scriptWitness.stack = result;
        sigdata.witness = true;
        result.clear();
    }
    else if (solved && whichType == TxoutType::WITNESS_V0_SCRIPTHASH)
    {
        CScript witnessscript(result[0].begin(), result[0].end());
        sigdata.witness_script = witnessscript;

        TxoutType subType{TxoutType::NONSTANDARD};
        solved = solved && SignStep(provider, creator, witnessscript, result, subType, SigVersion::WITNESS_V0, sigdata) && subType != TxoutType::SCRIPTHASH && subType != TxoutType::WITNESS_V0_SCRIPTHASH && subType != TxoutType::WITNESS_V0_KEYHASH;

        // If we couldn't find a solution with the legacy satisfier, try satisfying the script using Miniscript.
        // Note we need to check if the result stack is empty before, because it might be used even if the Script
        // isn't fully solved. For instance the CHECKMULTISIG satisfaction in SignStep() pushes partial signatures
        // and the extractor relies on this behaviour to combine witnesses.
        if (!solved && result.empty()) {
            WshSatisfier ms_satisfier{provider, sigdata, creator, witnessscript};
            const auto ms = miniscript::FromScript(witnessscript, ms_satisfier);
            solved = ms && ms->Satisfy(ms_satisfier, result) == miniscript::Availability::YES;
        }
        result.emplace_back(witnessscript.begin(), witnessscript.end());

        sigdata.scriptWitness.stack = result;
        sigdata.witness = true;
        result.clear();
    } else if (whichType == TxoutType::WITNESS_V1_TAPROOT && !P2SH) {
        sigdata.witness = true;
        if (solved) {
            sigdata.scriptWitness.stack = std::move(result);
        }
        result.clear();
    } else if (whichType == TxoutType::WITNESS_V2_P2MR && !P2SH) {
        sigdata.witness = true;
        if (solved) {
            sigdata.scriptWitness.stack = std::move(result);
        }
        result.clear();
    } else if (solved && whichType == TxoutType::WITNESS_UNKNOWN) {
        sigdata.witness = true;
    }

    if (!sigdata.witness) sigdata.scriptWitness.stack.clear();
    if (P2SH) {
        result.emplace_back(subscript.begin(), subscript.end());
    }
    sigdata.scriptSig = PushAll(result);

    // Test solution
    sigdata.complete = solved && VerifyScript(sigdata.scriptSig, fromPubKey, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker());
    return sigdata.complete;
}

namespace {
class SignatureExtractorChecker final : public DeferringSignatureChecker
{
private:
    SignatureData& sigdata;

public:
    SignatureExtractorChecker(SignatureData& sigdata, BaseSignatureChecker& checker) : DeferringSignatureChecker(checker), sigdata(sigdata) {}

    bool CheckECDSASignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override
    {
        if (m_checker.CheckECDSASignature(scriptSig, vchPubKey, scriptCode, sigversion)) {
            CPubKey pubkey(vchPubKey);
            sigdata.signatures.emplace(pubkey.GetID(), SigPair(pubkey, scriptSig));
            return true;
        }
        return false;
    }
};

struct Stacks
{
    std::vector<valtype> script;
    std::vector<valtype> witness;

    Stacks() = delete;
    Stacks(const Stacks&) = delete;
    explicit Stacks(const SignatureData& data) : witness(data.scriptWitness.stack) {
        EvalScript(script, data.scriptSig, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker(), SigVersion::BASE);
    }
};
}

// Extracts signatures and scripts from incomplete scriptSigs. Please do not extend this, use PSBT instead
SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn, const CTxOut& txout)
{
    SignatureData data;
    assert(tx.vin.size() > nIn);
    data.scriptSig = tx.vin[nIn].scriptSig;
    data.scriptWitness = tx.vin[nIn].scriptWitness;
    Stacks stack(data);

    // Get signatures
    MutableTransactionSignatureChecker tx_checker(&tx, nIn, txout.nValue, MissingDataBehavior::FAIL);
    SignatureExtractorChecker extractor_checker(data, tx_checker);
    if (VerifyScript(data.scriptSig, txout.scriptPubKey, &data.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, extractor_checker)) {
        data.complete = true;
        return data;
    }

    // Get scripts
    std::vector<std::vector<unsigned char>> solutions;
    TxoutType script_type = Solver(txout.scriptPubKey, solutions);
    SigVersion sigversion = SigVersion::BASE;
    CScript next_script = txout.scriptPubKey;

    if (script_type == TxoutType::SCRIPTHASH && !stack.script.empty() && !stack.script.back().empty()) {
        // Get the redeemScript
        CScript redeem_script(stack.script.back().begin(), stack.script.back().end());
        data.redeem_script = redeem_script;
        next_script = std::move(redeem_script);

        // Get redeemScript type
        script_type = Solver(next_script, solutions);
        stack.script.pop_back();
    }
    if (script_type == TxoutType::WITNESS_V0_SCRIPTHASH && !stack.witness.empty() && !stack.witness.back().empty()) {
        // Get the witnessScript
        CScript witness_script(stack.witness.back().begin(), stack.witness.back().end());
        data.witness_script = witness_script;
        next_script = std::move(witness_script);

        // Get witnessScript type
        script_type = Solver(next_script, solutions);
        stack.witness.pop_back();
        stack.script = std::move(stack.witness);
        stack.witness.clear();
        sigversion = SigVersion::WITNESS_V0;
    }
    if (script_type == TxoutType::MULTISIG && !stack.script.empty()) {
        // Build a map of pubkey -> signature by matching sigs to pubkeys:
        assert(solutions.size() > 1);
        unsigned int num_pubkeys = solutions.size()-2;
        unsigned int last_success_key = 0;
        for (const valtype& sig : stack.script) {
            for (unsigned int i = last_success_key; i < num_pubkeys; ++i) {
                const valtype& pubkey = solutions[i+1];
                // We either have a signature for this pubkey, or we have found a signature and it is valid
                if (data.signatures.count(CPubKey(pubkey).GetID()) || extractor_checker.CheckECDSASignature(sig, pubkey, next_script, sigversion)) {
                    last_success_key = i + 1;
                    break;
                }
            }
        }
    }

    return data;
}

void UpdateInput(CTxIn& input, const SignatureData& data)
{
    input.scriptSig = data.scriptSig;
    input.scriptWitness = data.scriptWitness;
}

void SignatureData::MergeSignatureData(SignatureData sigdata)
{
    if (complete) return;
    if (sigdata.complete) {
        *this = std::move(sigdata);
        return;
    }
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    signatures.insert(std::make_move_iterator(sigdata.signatures.begin()), std::make_move_iterator(sigdata.signatures.end()));
    pq_keys.insert(std::make_move_iterator(sigdata.pq_keys.begin()), std::make_move_iterator(sigdata.pq_keys.end()));
    p2mr_spenddata.Merge(std::move(sigdata.p2mr_spenddata));
    p2mr_script_sigs.insert(std::make_move_iterator(sigdata.p2mr_script_sigs.begin()), std::make_move_iterator(sigdata.p2mr_script_sigs.end()));
    p2mr_csfs_sigs.insert(std::make_move_iterator(sigdata.p2mr_csfs_sigs.begin()), std::make_move_iterator(sigdata.p2mr_csfs_sigs.end()));
    p2mr_csfs_msgs.insert(std::make_move_iterator(sigdata.p2mr_csfs_msgs.begin()), std::make_move_iterator(sigdata.p2mr_csfs_msgs.end()));
    if (p2mr_leaf_script.empty() && !sigdata.p2mr_leaf_script.empty()) {
        p2mr_leaf_script = std::move(sigdata.p2mr_leaf_script);
    }
    if (p2mr_control_block.empty() && !sigdata.p2mr_control_block.empty()) {
        p2mr_control_block = std::move(sigdata.p2mr_control_block);
    }
    if (!preferred_pq_signing_algo.has_value() && sigdata.preferred_pq_signing_algo.has_value()) {
        preferred_pq_signing_algo = sigdata.preferred_pq_signing_algo;
    }
}

namespace {
/** Dummy signature checker which accepts all signatures. */
class DummySignatureChecker final : public BaseSignatureChecker
{
public:
    DummySignatureChecker() = default;
    bool CheckECDSASignature(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override { return sig.size() != 0; }
    bool CheckSchnorrSignature(Span<const unsigned char> sig, Span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror) const override { return sig.size() != 0; }
    bool CheckLockTime(const CScriptNum& nLockTime) const override { return true; }
    bool CheckSequence(const CScriptNum& nSequence) const override { return true; }
};
}

const BaseSignatureChecker& DUMMY_CHECKER = DummySignatureChecker();

namespace {
class DummySignatureCreator final : public BaseSignatureCreator {
private:
    char m_r_len = 32;
    char m_s_len = 32;
public:
    DummySignatureCreator(char r_len, char s_len) : m_r_len(r_len), m_s_len(s_len) {}
    const BaseSignatureChecker& Checker() const override { return DUMMY_CHECKER; }
    bool CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const override
    {
        // Create a dummy signature that is a valid DER-encoding
        vchSig.assign(m_r_len + m_s_len + 7, '\000');
        vchSig[0] = 0x30;
        vchSig[1] = m_r_len + m_s_len + 4;
        vchSig[2] = 0x02;
        vchSig[3] = m_r_len;
        vchSig[4] = 0x01;
        vchSig[4 + m_r_len] = 0x02;
        vchSig[5 + m_r_len] = m_s_len;
        vchSig[6 + m_r_len] = 0x01;
        vchSig[6 + m_r_len + m_s_len] = SIGHASH_ALL;
        return true;
    }
    bool CreateSchnorrSig(const SigningProvider& provider, std::vector<unsigned char>& sig, const XOnlyPubKey& pubkey, const uint256* leaf_hash, const uint256* tweak, SigVersion sigversion) const override
    {
        sig.assign(64, '\000');
        return true;
    }
    bool CreatePQSig(const SigningProvider&, std::vector<unsigned char>& sig, Span<const unsigned char>, PQAlgorithm algo, const uint256&, SigVersion) const override
    {
        const size_t sig_size = GetPQSignatureSize(algo);
        sig.assign(sig_size, '\000');
        return true;
    }
};

}

const BaseSignatureCreator& DUMMY_SIGNATURE_CREATOR = DummySignatureCreator(32, 32);
const BaseSignatureCreator& DUMMY_MAXIMUM_SIGNATURE_CREATOR = DummySignatureCreator(33, 32);

namespace {

enum class ParsedP2MRTimelockType {
    NONE,
    CLTV,
    CSV,
};

struct ParsedP2MRTimelockRequirement {
    ParsedP2MRTimelockType type{ParsedP2MRTimelockType::NONE};
    int64_t value{0};
};

bool GetP2MRTimelockRequirement(Span<const unsigned char> leaf_script, ParsedP2MRTimelockRequirement& requirement)
{
    size_t consumed{0};
    int64_t value{0};
    if (ParseP2MRTimelockPrefix(leaf_script, OP_CHECKLOCKTIMEVERIFY, value, consumed) && consumed < leaf_script.size()) {
        requirement.type = ParsedP2MRTimelockType::CLTV;
        requirement.value = value;
        return true;
    }

    consumed = 0;
    value = 0;
    if (ParseP2MRTimelockPrefix(leaf_script, OP_CHECKSEQUENCEVERIFY, value, consumed) && consumed < leaf_script.size()) {
        requirement.type = ParsedP2MRTimelockType::CSV;
        requirement.value = value;
        return true;
    }

    requirement = {};
    return true;
}

bool CheckP2MRCSVSequence(uint32_t tx_sequence, uint32_t required_sequence)
{
    if ((required_sequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) return false;
    if ((tx_sequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) return false;

    const uint32_t locktime_mask = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
    const uint32_t tx_masked = tx_sequence & locktime_mask;
    const uint32_t required_masked = required_sequence & locktime_mask;
    const bool same_domain =
        (tx_masked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && required_masked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
        (tx_masked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && required_masked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG);
    return same_domain && required_masked <= tx_masked;
}

bool HandleP2MRTimelockedTransaction(CMutableTransaction& tx,
                                     Span<const P2MRTimelockedInput> inputs,
                                     bool allow_mutation,
                                     bilingual_str& error)
{
    std::optional<uint32_t> required_cltv_locktime;
    std::optional<bool> required_cltv_time_based;
    std::set<unsigned int> cltv_inputs;
    std::vector<std::pair<unsigned int, uint32_t>> csv_inputs;

    for (const auto& input : inputs) {
        if (input.input_index >= tx.vin.size()) {
            error = Untranslated("Selected P2MR timelock input index is out of range");
            return false;
        }

        ParsedP2MRTimelockRequirement requirement;
        if (!GetP2MRTimelockRequirement(input.leaf_script, requirement)) {
            error = Untranslated("Unable to parse selected P2MR timelock leaf");
            return false;
        }

        switch (requirement.type) {
        case ParsedP2MRTimelockType::NONE:
            break;
        case ParsedP2MRTimelockType::CLTV: {
            if (requirement.value < 0 || requirement.value > LOCKTIME_MAX) {
                error = Untranslated("Selected P2MR CLTV leaf uses an invalid locktime");
                return false;
            }
            const auto locktime = static_cast<uint32_t>(requirement.value);
            const bool time_based = locktime >= LOCKTIME_THRESHOLD;
            if (required_cltv_time_based.has_value() && *required_cltv_time_based != time_based) {
                error = Untranslated("Selected P2MR CLTV leaves require conflicting locktime domains");
                return false;
            }
            required_cltv_time_based = time_based;
            if (!required_cltv_locktime.has_value() || locktime > *required_cltv_locktime) {
                required_cltv_locktime = locktime;
            }
            cltv_inputs.insert(input.input_index);
            break;
        }
        case ParsedP2MRTimelockType::CSV: {
            if (requirement.value < 1 || requirement.value >= CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
                error = Untranslated("Selected P2MR CSV leaf uses an invalid sequence");
                return false;
            }
            csv_inputs.emplace_back(input.input_index, static_cast<uint32_t>(requirement.value));
            break;
        }
        }
    }

    if (required_cltv_locktime.has_value()) {
        const bool tx_time_based = tx.nLockTime >= LOCKTIME_THRESHOLD;
        const bool locktime_satisfied = tx.nLockTime >= *required_cltv_locktime &&
                                        tx_time_based == *required_cltv_time_based;
        if (!locktime_satisfied) {
            if (!allow_mutation) {
                error = Untranslated("Selected P2MR CLTV leaf requires a different transaction locktime");
                return false;
            }
            tx.nLockTime = *required_cltv_locktime;
        }

        for (const unsigned int input_index : cltv_inputs) {
            if (tx.vin[input_index].nSequence == CTxIn::SEQUENCE_FINAL) {
                if (!allow_mutation) {
                    error = Untranslated("Selected P2MR CLTV leaf requires a non-final input sequence");
                    return false;
                }
                tx.vin[input_index].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;
            }
        }
    }

    if (!csv_inputs.empty() && tx.version < 2) {
        if (!allow_mutation) {
            error = Untranslated("Selected P2MR CSV leaf requires transaction version 2 or higher");
            return false;
        }
        tx.version = 2;
    }

    for (const auto& [input_index, required_sequence] : csv_inputs) {
        if (!CheckP2MRCSVSequence(tx.vin[input_index].nSequence, required_sequence)) {
            if (!allow_mutation) {
                error = Untranslated("Selected P2MR CSV leaf requires a different input sequence");
                return false;
            }
            tx.vin[input_index].nSequence = required_sequence;
        }
    }

    return true;
}

bool TransactionHasExistingSignatures(const CMutableTransaction& tx)
{
    return std::any_of(tx.vin.begin(), tx.vin.end(), [](const CTxIn& txin) {
        return !txin.scriptSig.empty() || !txin.scriptWitness.IsNull();
    });
}

void AssignP2MRTimelockError(const std::vector<P2MRTimelockedInput>& inputs,
                             const bilingual_str& error,
                             std::map<int, bilingual_str>& input_errors)
{
    for (const auto& input : inputs) {
        input_errors[input.input_index] = error;
    }
}

} // namespace

bool CheckP2MRTimelockedTransaction(const CTransaction& tx, Span<const P2MRTimelockedInput> inputs, bilingual_str& error)
{
    CMutableTransaction mutable_tx(tx);
    return HandleP2MRTimelockedTransaction(mutable_tx, inputs, /*allow_mutation=*/false, error);
}

bool PrepareP2MRTimelockedTransaction(CMutableTransaction& tx, Span<const P2MRTimelockedInput> inputs, bilingual_str& error)
{
    return HandleP2MRTimelockedTransaction(tx, inputs, /*allow_mutation=*/true, error);
}

bool IsSegWitOutput(const SigningProvider& provider, const CScript& script)
{
    int version;
    valtype program;
    if (script.IsWitnessProgram(version, program)) return true;
    if (script.IsPayToScriptHash()) {
        std::vector<valtype> solutions;
        auto whichtype = Solver(script, solutions);
        if (whichtype == TxoutType::SCRIPTHASH) {
            auto h160 = uint160(solutions[0]);
            CScript subscript;
            if (provider.GetCScript(CScriptID{h160}, subscript)) {
                if (subscript.IsWitnessProgram(version, program)) return true;
            }
        }
    }
    return false;
}

bool SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<COutPoint, Coin>& coins, int nHashType, std::map<int, bilingual_str>& input_errors, std::optional<CAmount>* inputs_amount_sum, std::optional<PQAlgorithm> preferred_pq_signing_algo)
{
    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    const auto build_txdata = [&](const CMutableTransaction& tx) {
        const CTransaction tx_const(tx);
        PrecomputedTransactionData out;
        std::vector<CTxOut> spent_outputs;
        for (const CTxIn& txin : tx.vin) {
            auto coin = coins.find(txin.prevout);
            if (coin == coins.end() || coin->second.IsSpent()) {
                out.Init(tx_const, /*spent_outputs=*/{}, /*force=*/true);
                return out;
            }
            spent_outputs.emplace_back(coin->second.out.nValue, coin->second.out.scriptPubKey);
        }
        out.Init(tx_const, std::move(spent_outputs), true);
        return out;
    };

    std::vector<P2MRTimelockedInput> p2mr_timelocked_inputs;
    {
        const PrecomputedTransactionData probe_txdata = build_txdata(mtx);
        for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
            if (fHashSingle && i >= mtx.vout.size()) continue;

            auto coin = coins.find(mtx.vin[i].prevout);
            if (coin == coins.end() || coin->second.IsSpent()) continue;

            SignatureData probe_sigdata = DataFromTransaction(mtx, i, coin->second.out);
            probe_sigdata.preferred_pq_signing_algo = preferred_pq_signing_algo;
            ProduceSignature(*keystore, MutableTransactionSignatureCreator(mtx, i, coin->second.out.nValue, &probe_txdata, nHashType), coin->second.out.scriptPubKey, probe_sigdata);
            if (!probe_sigdata.p2mr_leaf_script.empty()) {
                p2mr_timelocked_inputs.push_back({i, std::move(probe_sigdata.p2mr_leaf_script)});
            }
        }
    }

    bilingual_str timelock_error;
    if (!CheckP2MRTimelockedTransaction(CTransaction{mtx}, p2mr_timelocked_inputs, timelock_error)) {
        if (TransactionHasExistingSignatures(mtx) || !PrepareP2MRTimelockedTransaction(mtx, p2mr_timelocked_inputs, timelock_error)) {
            AssignP2MRTimelockError(p2mr_timelocked_inputs, timelock_error, input_errors);
            return false;
        }
    }

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mtx);
    PrecomputedTransactionData txdata = build_txdata(mtx);

    // Sign what we can:
    if (inputs_amount_sum) *inputs_amount_sum = 0;
    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        CTxIn& txin = mtx.vin[i];
        auto coin = coins.find(txin.prevout);
        if (coin == coins.end() || coin->second.IsSpent()) {
            if (inputs_amount_sum) {
                inputs_amount_sum->reset();
                inputs_amount_sum = nullptr;
            }
            input_errors[i] = _("Input not found or already spent");
            continue;
        }
        const CScript& prevPubKey = coin->second.out.scriptPubKey;
        const CAmount& amount = coin->second.out.nValue;
        if (inputs_amount_sum && *inputs_amount_sum) {
            if (amount > 0) {
                **inputs_amount_sum += amount;
            } else {
                inputs_amount_sum->reset();
                inputs_amount_sum = nullptr;
            }
        }

        SignatureData sigdata = DataFromTransaction(mtx, i, coin->second.out);
        sigdata.preferred_pq_signing_algo = preferred_pq_signing_algo;
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mtx.vout.size())) {
            ProduceSignature(*keystore, MutableTransactionSignatureCreator(mtx, i, amount, &txdata, nHashType), prevPubKey, sigdata);
            if ((!sigdata.witness) && inputs_amount_sum && *inputs_amount_sum) {
                inputs_amount_sum->reset();
                inputs_amount_sum = nullptr;
            }
        }

        UpdateInput(txin, sigdata);

        // amount must be specified for valid segwit signature
        if (amount == MAX_MONEY && !txin.scriptWitness.IsNull()) {
            input_errors[i] = _("Missing amount");
            continue;
        }

        ScriptError serror = SCRIPT_ERR_OK;
        if (!sigdata.complete && !VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, i, amount, txdata, MissingDataBehavior::FAIL), &serror)) {
            if (serror == SCRIPT_ERR_INVALID_STACK_OPERATION) {
                // Unable to sign input and verification failed (possible attempt to partially sign).
                input_errors[i] = Untranslated("Unable to sign input, invalid stack size (possibly missing key)");
            } else if (serror == SCRIPT_ERR_SIG_NULLFAIL) {
                // Verification failed (possibly due to insufficient signatures).
                input_errors[i] = Untranslated("CHECK(MULTI)SIG failing with non-zero signature (possibly need more signatures)");
            } else {
                input_errors[i] = Untranslated(ScriptErrorString(serror));
            }
        } else {
            // If this input succeeds, make sure there is no error set for it
            input_errors.erase(i);
        }
    }
    return input_errors.empty();
}
