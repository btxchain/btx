// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_TEST_SHIELDED_V2_ADVERSARIAL_PROOF_CORPUS_H
#define BTX_TEST_SHIELDED_V2_ADVERSARIAL_PROOF_CORPUS_H

#include <optional>
#include <string>
#include <vector>

namespace btx::test::shielded {

struct AdversarialProofVariant
{
    std::string id;
    std::string description;
    std::string expected_reject_reason;
    std::string expected_failure_stage;
    std::string tx_hex;
    std::string txid_hex;
    std::string wtxid_hex;
};

struct AdversarialProofCorpus
{
    std::string family_name;
    std::string base_tx_hex;
    std::string base_txid_hex;
    std::string base_wtxid_hex;
    std::vector<AdversarialProofVariant> variants;
};

[[nodiscard]] std::optional<AdversarialProofCorpus> BuildV2SendAdversarialProofCorpus(
    const std::string& base_tx_hex,
    std::string& reject_reason);

} // namespace btx::test::shielded

#endif // BTX_TEST_SHIELDED_V2_ADVERSARIAL_PROOF_CORPUS_H
