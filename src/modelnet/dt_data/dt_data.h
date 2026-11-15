// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_DATA_DT_DATA_H
#define BITCOIN_MODELNET_DT_DATA_DT_DATA_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** Empty dataset id. Nothing is stored. */
inline constexpr char kDtDataDataset[] = "DATASET";

/** Empty license. Nothing is stored. */
inline constexpr char kDtDataLicense[] = "LICENSE";

/** Evaluation data is not a training row. The training cursor stays. */
inline constexpr char kDtDataHoldout[] = "HOLDOUT";

/** Purpose is not training or evaluation. Nothing is stored. */
inline constexpr char kDtDataNotAuthorized[] = "NOT_AUTHORIZED";

/** Public trajectory kind that may be admitted. */
inline constexpr char kDtDataPublic[] = "public_trajectory";

/** Synthetic trajectory kind that may be admitted. */
inline constexpr char kDtDataSynthetic[] = "synthetic_trajectory";

/** Purpose that feeds the training cursor. */
inline constexpr char kDtDataTraining[] = "training";

/** Purpose that is held out of training. */
inline constexpr char kDtDataEvaluation[] = "evaluation";

/**
 * Admitted training rows.
 *
 * Admit stores one id. An empty id is DATASET. An empty license is LICENSE.
 * Kind must be public_trajectory or synthetic_trajectory. private, incident,
 * and every other kind are NIFDT_PRIVATE_DATA and store nothing. Purpose must
 * be training or evaluation. Purpose defensive is NOT_AUTHORIZED and stores
 * nothing. A second admit of the same id is NIFDT_REPLAY and keeps the first
 * license and purpose.
 *
 * Cursor returns the next training row index only for an admitted training
 * partition. An evaluation partition is HOLDOUT and does not advance the
 * training cursor. A private id that was refused has no cursor. Train refuses
 * an evaluation partition with HOLDOUT and a missing id with DATASET. A
 * successful Train advances that training cursor by 1.
 *
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is "0".
 * No socket is opened.
 */
class DtData {
public:
    bool Admit(const std::string& id,
               const std::string& license,
               const std::string& purpose,
               const std::string& kind,
               const std::string& partition,
               std::string& err);
    int64_t Cursor(const std::string& id, std::string& err) const;
    bool Train(const std::string& id, std::string& err);

    bool admitted(const std::string& id) const;
    std::string license(const std::string& id) const;
    std::string purpose(const std::string& id) const;
    std::string kind(const std::string& id) const;
    std::string partition(const std::string& id) const;

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        std::string license;
        std::string purpose;
        std::string kind;
        std::string partition;
        int64_t cursor{0};
    };

    const Row* Find(const std::string& id) const;

    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_DATA_DT_DATA_H
