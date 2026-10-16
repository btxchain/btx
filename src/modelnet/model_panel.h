// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_MODEL_PANEL_H
#define BITCOIN_MODELNET_MODEL_PANEL_H

#include <modelnet/action_authority.h>
#include <modelnet/model_admission.h>
#include <modelnet/realm_channel.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Read-only lab panel. No Qt. */
struct PanelSnapshot {
    std::string admission_code;
    bool serve_allowed{false};
    std::string realm;
    int64_t channel_sequence{-1};
    std::string logical_state;
    std::string physical_state;
};

PanelSnapshot CapturePanel(const AdmissionResult& admission,
                           const RealmRollout& rollout,
                           const std::string& realm,
                           const ActionGate& gate,
                           const std::string& operation);

} // namespace modelnet

#endif // BITCOIN_MODELNET_MODEL_PANEL_H
