#!/usr/bin/env bash
# Reproduce the immutable commit-set inventories used by the BTX 0.33.2
# Core/Knots catch-up audit. If gh is authenticated, also snapshot current open
# pull-request metadata for comparison with the documented cutoff.

export LC_ALL=C
set -euo pipefail

if (( $# > 1 )); then
    echo "usage: $0 [output-directory]" >&2
    exit 1
fi

audit_repo=$(git rev-parse --show-toplevel)
audit_output=${1:-"$audit_repo/upstream-catchup-audit"}
audit_tmp=$(mktemp -d "${TMPDIR:-/tmp}/btx-upstream-audit.XXXXXX")
trap 'rm -rf "$audit_tmp"' EXIT

core_tip=70d9ec7f3d452789d04dce81dc02db0b3b778bb5
knots_tip=f41f01e1e6de7025d52a865bef97f2a67277f0f3
knots_source=7b009f5531b9641f3fe5456f668638c5ddd5929a

for audit_commit in "$core_tip" "$knots_tip" "$knots_source"; do
    git -C "$audit_repo" cat-file -e "$audit_commit^{commit}"
done

mkdir -p "$audit_output"
git -C "$audit_repo" rev-list "$core_tip" | sort > "$audit_tmp/core.ids"
git -C "$audit_repo" rev-list "$knots_tip" | sort > "$audit_tmp/knots.ids"
git -C "$audit_repo" rev-list "$knots_source" | sort > "$audit_tmp/source.ids"

comm -12 "$audit_tmp/core.ids" "$audit_tmp/source.ids" > "$audit_tmp/core-inherited.ids"
comm -13 "$audit_tmp/core.ids" "$audit_tmp/source.ids" > "$audit_tmp/knots-pre-source.ids"
comm -23 "$audit_tmp/core.ids" "$audit_tmp/source.ids" > "$audit_tmp/core-absent.ids"
comm -13 "$audit_tmp/source.ids" "$audit_tmp/knots.ids" > "$audit_tmp/knots-post-source.ids"

emit_inventory()
{
    local ids=$1
    local output=$2
    : > "$output"
    while IFS= read -r commit; do
        git -C "$audit_repo" show -s --format='%H%x09%P%x09%cI%x09%s' "$commit" >> "$output"
    done < "$ids"
}

emit_inventory "$audit_tmp/core-inherited.ids" "$audit_output/core-history-inherited-by-knots.tsv"
emit_inventory "$audit_tmp/knots-pre-source.ids" "$audit_output/knots-only-pre-btx-source.tsv"
emit_inventory "$audit_tmp/core-absent.ids" "$audit_output/core-not-in-btx-source-through-tip.tsv"
emit_inventory "$audit_tmp/knots-post-source.ids" "$audit_output/knots-post-btx-source-through-tip.tsv"

if command -v gh >/dev/null 2>&1; then
    gh api --paginate 'repos/bitcoin/bitcoin/pulls?state=open&per_page=100' \
        --jq '.[] | [.number, .updated_at, .draft, .title, .html_url] | @tsv' \
        > "$audit_output/core-open-prs.tsv"
    gh api --paginate 'repos/bitcoinknots/bitcoin/pulls?state=open&per_page=100' \
        --jq '.[] | [.number, .updated_at, .draft, .title, .html_url] | @tsv' \
        > "$audit_output/knots-open-prs.tsv"
fi

(
    cd "$audit_output"
    shasum -a 256 ./*.tsv > SHA256SUMS
)

echo "Wrote audit inventories to $audit_output"
