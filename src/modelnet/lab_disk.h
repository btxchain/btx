// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LAB_DISK_H
#define BITCOIN_MODELNET_LAB_DISK_H

#include <modelnet/research_views.h>
#include <modelnet/training_integer.h>
#include <modelnet/training_launch.h>
#include <util/fs.h>

#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/** One stored exchange object. Identity secret keys are not part of this image. */
struct LabDiskObject {
    std::string kind;
    std::string digest;
    std::string content;
};

/**
 * Fields a second lab process needs. automatic_spend_atoms is always "0" on
 * disk. Secret identity keys are not represented and are never written.
 */
struct LabDiskImage {
    std::map<std::string, std::string> records;
    std::vector<ResearchObservation> observations;
    std::map<std::string, std::vector<LabDiskObject>> repo_objects;
    std::set<std::string> repos;
    std::map<std::string, std::string> repo_commit;
    std::map<std::string, std::string> repo_genesis;
    std::set<std::string> repo_ref_published;
    std::set<std::string> snapshots;
    std::map<std::string, std::string> realms;
    std::map<std::string, std::string> lineage;
    std::map<std::string, std::string> plans;
    std::map<std::string, std::string> admissions;
    /** Public identity keys, lowercase hex. Never a secret key. */
    std::map<std::string, std::string> identity_pk;
    /** INTEGER_LINEAR trainer state keyed by trajectory id. No secret keys. */
    std::map<std::string, IntegerState> trains;
    /** Trajectory id to the public identity that ran it. Absent for an older file. */
    std::map<std::string, std::string> train_authors;
    /**
     * Launch-decoder checkpoints. Absent on a file written before this field.
     * The integer `trains` map does not carry these rows.
     */
    std::map<std::string, LaunchCheckpoint> launch_trains;
    std::map<std::string, std::string> launch_authors;
    /** Channel and policy rows. Absent on a file written before this field. */
    struct RolloutRow {
        std::string key;
        bool policy{false};
        int threshold{0};
        std::vector<std::string> pins;
        std::vector<std::string> revoked;
        bool has_channel{false};
        int64_t sequence{-1};
        std::string body;
    };
    std::vector<RolloutRow> rollout;
    std::set<std::string> hosted;
    std::map<std::string, std::set<std::string>> verified_rings;
    std::map<std::string, std::string> fleet;
    std::map<std::string, std::string> endpoints;
    std::map<std::string, std::string> pause_epochs;
    std::map<std::string, std::string> checkpoints;
    std::set<std::string> migrations;
    std::set<std::string> migration_plans;
    struct OperationRow {
        std::string state;
        std::string physical;
        std::string generation;
    };
    std::map<std::string, OperationRow> operations;
    std::vector<std::string> generations;
    std::string active_generation;
    std::string previous_generation;
    std::map<std::string, std::string> grants;
    std::map<std::string, std::string> bindings;
    struct WorkspaceRow {
        std::string backend;
        std::string generation{"1"};
        std::map<std::string, std::string> live;
        std::map<std::string, std::map<std::string, std::string>> closed;
        std::vector<std::string> publications;
        std::string next_publication{"1"};
        std::set<std::string> cancelled;
        std::set<std::string> completed;
    };
    std::map<std::string, WorkspaceRow> workspaces;
    /** Public identity that was active when the image was saved. Never a secret key. */
    std::string active_root;
    /**
     * Caller-scoped idempotency rows. `digest` is the canonical request digest
     * and `result` is the response already returned for that caller and key.
     */
    struct IdempotencyRow {
        std::string caller;
        std::string key;
        std::string digest;
        std::string result;
        /** Result dropped after the live cap. A retry must not run as a new request. */
        bool retired{false};
    };
    std::vector<IdempotencyRow> idempotency;
    /** Admission id to model id, a newline, and the digest. Absent on an older file. */
    std::map<std::string, std::string> admission_subject;
};

/** BTX035_LAB_DIR, or empty when unset. No relative or home fallback. */
fs::path LabDiskDirectory();

/**
 * Load lab.json when the directory and file exist. A missing directory or file
 * leaves `image` unchanged and returns true. A corrupt, truncated, unsupported
 * version, or inconsistent piece image returns false with
 * BTX035_RECOVERY_REQUIRED and does not modify the file. Does not create the
 * directory.
 */
bool LoadLabDisk(LabDiskImage& image, std::string& err);

/**
 * Write lab.json by temp file then rename. A failed call leaves any previous
 * lab.json in place. Refuses to replace a file that does not decode. Does
 * nothing when BTX035_LAB_DIR is unset.
 */
bool SaveLabDisk(const LabDiskImage& image, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_LAB_DISK_H
