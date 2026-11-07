// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVIDENCE_CODES_H
#define BITCOIN_MODELNET_SWARM_EVIDENCE_CODES_H

namespace modelnet {

/** An empty id or an empty byte vector. Nothing is stored. */
inline constexpr char kSwarmEvidenceEvidence[] = "EVIDENCE";

/**
 * The id was never stored, or the stored bytes are private.
 * Both answers use this code.
 */
inline constexpr char kSwarmEvidenceNotVisible[] = "NOT_VISIBLE";

/** An empty summary id, an empty summary, or an empty source id. Nothing is stored. */
inline constexpr char kSwarmEvidenceSummary[] = "SUMMARY";

/** The source id is not a stored evidence record. Nothing is stored. */
inline constexpr char kSwarmEvidenceSource[] = "SOURCE";

/** Model text is data. It is kept tainted and is not an instruction. */
inline constexpr char kSwarmEvidenceNotAuthority[] = "NOT_AUTHORITY";

/** A replica promise is not bytes. Retrieve does not hand bytes back. */
inline constexpr char kSwarmEvidenceNotRetrievable[] = "NOT_RETRIEVABLE";

/** This id already holds evidence or a summary. The first record stays. */
inline constexpr char kSwarmEvidenceReplay[] = "REPLAY";

/** An empty promise id. Nothing is recorded. */
inline constexpr char kSwarmEvidenceId[] = "ID";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVIDENCE_CODES_H
