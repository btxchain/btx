// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/model_panel.h>

namespace modelnet {

PanelSnapshot CapturePanel(const AdmissionResult& admission,
                           const RealmRollout& rollout,
                           const std::string& realm,
                           const ActionGate& gate,
                           const std::string& operation)
{
    const OperationDisposition disposition = gate.Disposition(operation);
    PanelSnapshot snap;
    snap.admission_code = admission.code;
    snap.serve_allowed = admission.ServeAllowed();
    snap.realm = realm;
    snap.channel_sequence = rollout.ChannelSequence(realm);
    snap.logical_state = disposition.logical_state;
    snap.physical_state = disposition.physical_state;
    return snap;
}

} // namespace modelnet
