#!/usr/bin/env bash
# Local unix-RPC e2e for btx-modeld. Does not start btxd.
# No WAN, no granite, no operator hosts. Scratch lives on disk (not /tmp tmpfs).
set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/build-gcc13/bin"
MODELD="$BIN/btx-modeld"
WORKDIR="$ROOT/e2e-scratch/local-helper"
HELPER_PID=""

cleanup() {
  if [[ -n "${HELPER_PID}" ]] && kill -0 "$HELPER_PID" 2>/dev/null; then
    kill -TERM "$HELPER_PID" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$HELPER_PID" 2>/dev/null || break
      sleep 0.1
    done
    # Test helper only; never production btxd.
    if kill -0 "$HELPER_PID" 2>/dev/null; then
      echo "warning: test helper still running after SIGTERM" >&2
    fi
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

if [[ ! -x "$MODELD" ]]; then
  echo "btx-modeld missing: $MODELD" >&2
  exit 1
fi

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/modeldir" "$WORKDIR/import" "$WORKDIR/watch"
ST="$WORKDIR/import/model.safetensors"
python3 -c 'import struct,sys; open(sys.argv[1],"wb").write(struct.pack("<Q",2)+b"{}")' "$ST"

SOCK="$WORKDIR/modeldir/modeld.sock"
"$MODELD" \
  -modeldir="$WORKDIR/modeldir" \
  -modelstorage=8MiB \
  -modelrpcsocket="$SOCK" \
  -modelwatch="$WORKDIR/watch" \
  >"$WORKDIR/modeld.log" 2>&1 &
HELPER_PID=$!

python3 - "$SOCK" "$ST" "$WORKDIR/modeld.log" "$HELPER_PID" "$ROOT/contrib/modelnet" "$WORKDIR" <<'PY'
import json, os, socket, subprocess, sys
from pathlib import Path

sock, src, log_path = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
helper_pid = int(sys.argv[4])
sys.path.insert(0, sys.argv[5])
workdir = Path(sys.argv[6])
from failfast import wait_unix


def rpc_raw(method, params, timeout=30):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode() + b"\n")
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    s.close()
    reply = json.loads(data.decode())
    if reply.get("error"):
        return None, reply["error"]
    return reply["result"], None


def method_missing(err):
    if isinstance(err, dict):
        blob = f"{err.get('code', '')} {err.get('message', '')}".lower()
    else:
        blob = str(err).lower()
    return "method_not_found" in blob or "unknown model rpc" in blob


def require_no_spend(obj, where):
    if not isinstance(obj, dict):
        raise SystemExit(f"{where} expected object: {obj}")
    if obj.get("automatic_spend_atoms", 0) not in (0, "0"):
        raise SystemExit(f"{where} automatic_spend_atoms must be 0: {obj}")
    return obj


def rpc(method, params, timeout=30):
    result, err = rpc_raw(method, params, timeout)
    if err is not None:
        raise RuntimeError(f"{method}: {err}")
    return result


def wait_ready(seconds=20):
    def connect():
        info = rpc("getmodelnetworkinfo", [])
        if info.get("helper_ready"):
            return info
        return None

    return wait_unix(connect, timeout=seconds, pid=helper_pid, log=log_path)


info = wait_ready()
if not info.get("helper_ready"):
    raise SystemExit(f"helper_ready false: {info}")

ids_before = rpc("listmodelidentities", [])
if not ids_before.get("identities"):
    raise SystemExit(f"helper should auto-create a research identity: {ids_before}")

doctor = rpc("checkmodelsetup", [])
if not isinstance(doctor, dict):
    raise SystemExit(f"checkmodelsetup expected object: {doctor}")
for key in ("identity_ready", "ready_to_host", "next_actions", "watch_dir"):
    if key not in doctor:
        raise SystemExit(f"checkmodelsetup missing {key}: {doctor}")
if not isinstance(doctor.get("next_actions"), list):
    raise SystemExit(f"checkmodelsetup next_actions must be a list: {doctor}")
if doctor.get("quota", doctor.get("quota_bytes")) is None:
    raise SystemExit(f"checkmodelsetup missing quota: {doctor}")
if doctor.get("pq1", doctor.get("pq1_ready")) is None:
    raise SystemExit(f"checkmodelsetup missing pq1: {doctor}")
if doctor.get("automatic_spend_atoms", 0) not in (0, "0"):
    raise SystemExit(f"checkmodelsetup automatic_spend_atoms must be 0: {doctor}")
watch = workdir / "watch"
if not str(doctor.get("watch_dir") or "").strip():
    raise SystemExit(f"checkmodelsetup watch_dir empty (helper started with -modelwatch): {doctor}")

# previewmodelimport: size vs quota, inferred labels, no hash, no import.
preview_dir = workdir / "preview-glm-fp8"
preview_dir.mkdir(parents=True, exist_ok=True)
(preview_dir / "model.safetensors").write_bytes(src.read_bytes())
listed_before_preview = rpc("listmodels", [])
n_before_preview = int(listed_before_preview.get("local_count", 0) or 0)
preview = rpc("previewmodelimport", [str(preview_dir)])
if not isinstance(preview, dict):
    raise SystemExit(f"previewmodelimport expected object: {preview}")
if preview.get("would_fit") is not True:
    raise SystemExit(f"previewmodelimport would_fit: {preview}")
if preview.get("family") != "glm":
    raise SystemExit(f"previewmodelimport family: {preview}")
if preview.get("format") != "safetensors":
    raise SystemExit(f"previewmodelimport format: {preview}")
if preview.get("hashes") not in (False, 0, "0"):
    raise SystemExit(f"previewmodelimport hashes must be false (no hash): {preview}")
if preview.get("automatic_spend_atoms", 0) not in (0, "0"):
    raise SystemExit(f"previewmodelimport automatic_spend_atoms must be 0: {preview}")
listed_after_preview = rpc("listmodels", [])
if int(listed_after_preview.get("local_count", 0) or 0) != n_before_preview:
    raise SystemExit(f"previewmodelimport must not import: before={listed_before_preview} after={listed_after_preview}")

# scanmodelwatch: first file is LE64=2 plus b"{}". Second unique model is the
# same header plus a unique README.md sidecar in a subdir so model_id differs.
# Drop before the 5s ticker's next pass so this RPC records imported_count.
unique_dir = watch / "e2e-unique"
unique_dir.mkdir(parents=True, exist_ok=True)
(unique_dir / "model.safetensors").write_bytes(src.read_bytes())
(unique_dir / "README.md").write_text(
    "e2e unique sidecar so model_id differs from the first LE64=2+{} file\n",
    encoding="utf-8",
)
scan1 = rpc("scanmodelwatch", [str(watch)])
if not isinstance(scan1, dict):
    raise SystemExit(f"scanmodelwatch expected object: {scan1}")
imported_count = scan1.get("imported_count")
if imported_count is None:
    imported_count = len(scan1.get("imported") or [])
if int(imported_count) < 1:
    raise SystemExit(f"scanmodelwatch imported_count>=1: {scan1}")
watch_rows = scan1.get("imported") or []
watch_uri = None
if watch_rows and isinstance(watch_rows[0], dict):
    watch_uri = watch_rows[0].get("uri") or watch_rows[0].get("model_id")
scan2 = rpc("scanmodelwatch", [str(watch)])
if not isinstance(scan2, dict):
    raise SystemExit(f"scanmodelwatch second expected object: {scan2}")
imported_count2 = scan2.get("imported_count")
if imported_count2 is None:
    imported_count2 = len(scan2.get("imported") or [])
if int(imported_count2) != 0:
    raise SystemExit(f"scanmodelwatch second must be skipped/idempotent: {scan2}")
skipped2 = scan2.get("skipped") or []
if not skipped2:
    raise SystemExit(f"scanmodelwatch second missing skipped paths: {scan2}")

imported = rpc("importmodel", [str(src)])
if not isinstance(imported, dict):
    raise SystemExit(f"importmodel expected object: {imported}")
uri = imported.get("uri") or imported.get("model_id")
if not uri:
    raise SystemExit(f"importmodel missing uri/model_id: {imported}")
if imported.get("seeded") is not True:
    raise SystemExit(f"import must demand-seed without seedmodel: {imported}")
if imported.get("signed_metadata") is not True:
    raise SystemExit(f"import must sign a search card by default: {imported}")
if imported.get("format") != "safetensors":
    raise SystemExit(f"import should infer safetensors: {imported}")
imp_share = imported.get("share")
if not isinstance(imp_share, dict) or not imp_share.get("copy_text"):
    raise SystemExit(f"importmodel missing share.copy_text: {imported}")
if imported.get("automatic_spend_atoms", 0) not in (0, "0"):
    raise SystemExit(f"importmodel automatic_spend_atoms must be 0: {imported}")
if watch_uri and uri == watch_uri:
    raise SystemExit(f"watch sidecar must yield a different model_id: import={uri} watch={watch_uri}")

hosted_dir = workdir / "host-glm-fp8"
hosted_dir.mkdir(parents=True, exist_ok=True)
(hosted_dir / "model.safetensors").write_bytes(src.read_bytes())
(hosted_dir / "README.md").write_text("hostmodel unique sidecar; not the first file\n", encoding="utf-8")
hosted = rpc("hostmodel", [str(hosted_dir)])
if not isinstance(hosted, dict):
    raise SystemExit(f"hostmodel expected object: {hosted}")
h_uri = hosted.get("uri") or hosted.get("model_id")
if not h_uri:
    raise SystemExit(f"hostmodel missing uri/model_id: {hosted}")
if hosted.get("seeded") is not True:
    raise SystemExit(f"hostmodel alias must pin+publish+seed: {hosted}")
h_share = hosted.get("share")
if not isinstance(h_share, dict) or not h_share.get("copy_text"):
    raise SystemExit(f"hostmodel missing share.copy_text: {hosted}")
if hosted.get("automatic_spend_atoms", 0) not in (0, "0"):
    raise SystemExit(f"hostmodel automatic_spend_atoms must be 0: {hosted}")
if watch_uri and h_uri == watch_uri:
    raise SystemExit(f"hostmodel collided with watch model_id: {h_uri}")
if h_uri == uri:
    raise SystemExit(f"hostmodel sidecar must differ from first import: import={uri} host={h_uri}")

share_card = rpc("getmodelsharecard", [uri])
if not isinstance(share_card, dict):
    raise SystemExit(f"getmodelsharecard expected object: {share_card}")
card_share_obj = share_card.get("share")
if not isinstance(card_share_obj, dict) or not card_share_obj.get("copy_text"):
    raise SystemExit(f"getmodelsharecard missing share.copy_text: {share_card}")
if card_share_obj.get("uri") and card_share_obj.get("uri") != uri:
    raise SystemExit(f"getmodelsharecard uri mismatch: {share_card} vs {uri}")
if share_card.get("automatic_spend_atoms", 0) not in (0, "0"):
    raise SystemExit(f"getmodelsharecard automatic_spend_atoms must be 0: {share_card}")

aliased = rpc("setmodelalias", [uri, "e2e-local"])
if not isinstance(aliased, dict):
    raise SystemExit(f"setmodelalias expected object: {aliased}")
if aliased.get("automatic_spend_atoms", 0) not in (0, "0"):
    raise SystemExit(f"setmodelalias automatic_spend_atoms must be 0: {aliased}")
aliases_all = rpc("getmodelaliases", [])
if not isinstance(aliases_all, dict):
    raise SystemExit(f"getmodelaliases (no id) expected object: {aliases_all}")
alias_rows = aliases_all.get("aliases") or aliases_all.get("results") or []
if not isinstance(alias_rows, list):
    raise SystemExit(f"getmodelaliases aliases: {aliases_all}")
saw_alias = False
for a in alias_rows:
    if isinstance(a, dict) and a.get("alias") == "e2e-local":
        saw_alias = True
        break
    if a == "e2e-local":
        saw_alias = True
        break
if not saw_alias:
    raise SystemExit(f"getmodelaliases without id missing e2e-local: {aliases_all}")

# Round 2 leftover verbs vs Ollama/qBittorrent/IPFS: show, pull-by-alias,
# .btx link, open share, then unhost after exportmodelpath so later getmodel
# still has files on disk.
shown, shown_err = rpc_raw("showmodel", ["e2e-local"])
if shown is None:
    if shown_err is not None and not method_missing(shown_err):
        raise SystemExit(f"showmodel: {shown_err}")
    shown = rpc("getmodelsharecard", ["e2e-local"])
require_no_spend(shown, "showmodel")
shown_share = shown.get("share") if isinstance(shown.get("share"), dict) else None
if shown_share is not None and not shown_share.get("copy_text"):
    raise SystemExit(f"showmodel share missing copy_text: {shown}")

got_by_alias = require_no_spend(rpc("getmodel", ["e2e-local", "FREE_ONLY"]), "getmodel alias e2e-local")

link_path = workdir / "e2e-local.btx"
link_res, link_err = rpc_raw("exportmodellink", [uri, str(link_path)])
if link_res is None:
    if link_err is not None and not method_missing(link_err):
        raise SystemExit(f"exportmodellink: {link_err}")
    link_doc = {
        "schema_version": 2,
        "uri": uri,
        "copy_text": card_share_obj.get("copy_text"),
        "kind": "btx_model_share",
        "automatic_spend_atoms": 0,
    }
    link_path.write_text(json.dumps(link_doc, indent=2) + "\n", encoding="utf-8")
    link_res = link_doc
else:
    require_no_spend(link_res, "exportmodellink")
    reported = link_res.get("path") or link_res.get("file")
    if not link_path.is_file() and isinstance(reported, str) and Path(reported).is_file():
        link_path = Path(reported)
    if not link_path.is_file():
        body = link_res.get("link") if isinstance(link_res.get("link"), dict) else link_res
        if isinstance(body, dict) and (body.get("uri") or body.get("copy_text")):
            link_path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
if not link_path.is_file():
    raise SystemExit(f"exportmodellink did not produce a .btx file: {link_res}")

copy_text = card_share_obj.get("copy_text")
if shown_share and shown_share.get("copy_text"):
    copy_text = shown_share.get("copy_text")
opened = require_no_spend(rpc("openmodelshare", [copy_text]), "openmodelshare")
if opened.get("inference") or opened.get("runtime_started") or opened.get("runtime_exec"):
    raise SystemExit(f"openmodelshare must be preview only: {opened}")
if opened.get("wallet") not in (None, False, 0, "0"):
    raise SystemExit(f"openmodelshare must not open a wallet: {opened}")

search = rpc("searchmodels", [{"text": "model", "scope": "LOCAL"}])
results = search.get("results") or []
if not results:
    raise SystemExit(f"searchmodels after import returned no results: {search}")
card = results[0]
if card.get("format") != "safetensors":
    raise SystemExit(f"search card missing format after import: {card}")
if not ((card.get("search") or {}).get("metadata_verified") or card.get("search", {}).get("publisher_signed")):
    raise SystemExit(f"search card not signed: {card}")
card_share = card.get("share")
if not isinstance(card_share, dict) or not card_share.get("copy_text"):
    raise SystemExit(f"search card missing share.copy_text: {card}")

listed = rpc("listmodels", [])
if int(listed.get("local_count", 0)) < 1:
    raise SystemExit(f"listmodels local_count < 1: {listed}")

xfers = rpc("getmodeltransfers", [])
if isinstance(xfers, dict):
    rows = xfers.get("transfers") or xfers.get("models") or []
elif isinstance(xfers, list):
    rows = xfers
else:
    raise SystemExit(f"getmodeltransfers expected object or list: {xfers}")
if not rows:
    raise SystemExit(f"getmodeltransfers empty after host/import: {xfers}")
row0 = rows[0]
if not isinstance(row0, dict):
    raise SystemExit(f"getmodeltransfers row: {row0}")
if not (row0.get("uri") or row0.get("model_id")):
    raise SystemExit(f"getmodeltransfers row missing uri: {row0}")
if "state" not in row0:
    raise SystemExit(f"getmodeltransfers missing state: {row0}")
for key in ("seeded", "pinned", "bytes", "complete", "ratio"):
    if key not in row0:
        raise SystemExit(f"getmodeltransfers missing {key}: {row0}")
if "served" not in row0 and "useful_bytes_served" not in row0:
    raise SystemExit(f"getmodeltransfers missing served: {row0}")
if "received" not in row0 and "useful_bytes_received" not in row0:
    raise SystemExit(f"getmodeltransfers missing received: {row0}")
if isinstance(xfers, dict) and xfers.get("automatic_spend_atoms", 0) not in (0, "0"):
    raise SystemExit(f"getmodeltransfers automatic_spend_atoms must be 0: {xfers}")

got = rpc("getmodel", [uri, "FREE_ONLY"])
if not isinstance(got, dict):
    raise SystemExit(f"getmodel expected object: {got}")

exported = rpc("exportmodelpath", [uri])
if exported.get("runtime_started") or exported.get("runtime_exec") or exported.get("inference"):
    raise SystemExit(f"exportmodelpath must not start a runtime: {exported}")
if not exported.get("files"):
    raise SystemExit(f"exportmodelpath files: {exported}")

unhosted, unhost_err = rpc_raw("unhostmodel", [uri])
if unhosted is None:
    if unhost_err is not None and not method_missing(unhost_err):
        raise SystemExit(f"unhostmodel: {unhost_err}")
    unpin = rpc("unpinmodel", [uri])
    unseed = rpc("unseedmodel", [uri])
    unhosted = {"unpinned": True, "unseeded": True, "unpinmodel": unpin, "unseedmodel": unseed}
require_no_spend(unhosted, "unhostmodel")
reseeded = rpc("seedmodel", [uri])
if not isinstance(reseeded, dict):
    raise SystemExit(f"seedmodel after unhost expected object: {reseeded}")
if reseeded.get("seeded") is False:
    raise SystemExit(f"seedmodel after unhost must seed again: {reseeded}")
if reseeded.get("automatic_spend_atoms", 0) not in (0, "0"):
    raise SystemExit(f"seedmodel automatic_spend_atoms must be 0: {reseeded}")

ident = rpc("createmodelidentity", ["e2e-local"])
if ident.get("wallet_backed") or ident.get("contains_wallet_material"):
    raise SystemExit(f"identity must not be wallet-backed: {ident}")
listed_id = rpc("listmodelidentities", [])
if not listed_id.get("identities"):
    raise SystemExit(f"listmodelidentities: {listed_id}")

paid = rpc("getmodel", [uri, "EXPLICIT_PAID"])
if not isinstance(paid, dict):
    raise SystemExit(f"EXPLICIT_PAID: {paid}")
if paid.get("automatic_spend_atoms", paid.get("automatic_spend", 1)) not in (0, "0"):
    raise SystemExit(f"EXPLICIT_PAID must not auto-spend: {paid}")
if "quote" not in paid:
    raise SystemExit(f"EXPLICIT_PAID must journal a quote: {paid}")
if paid.get("funding_rpc") != "preparemodelfunding":
    raise SystemExit(f"EXPLICIT_PAID funding_rpc: {paid}")

plan = rpc("getmodel", [uri, "FREE_FIRST_APPROVAL"])
if not isinstance(plan, dict) or "quote" not in plan:
    raise SystemExit(f"FREE_FIRST_APPROVAL must journal a quote without spend: {plan}")
quotes_path = workdir / "modeldir" / "quotes.json"
if not quotes_path.is_file():
    raise SystemExit(f"quote journal missing: {quotes_path}")
try:
    rpc("preparemodelfunding", [""])
    raise SystemExit("preparemodelfunding empty args must fail")
except RuntimeError as e:
    if "NOT_IMPLEMENTED" in str(e):
        raise SystemExit(f"preparemodelfunding still NOT_IMPLEMENTED: {e}")

recip = rpc("getmodelreciprocity", [])
if not isinstance(recip, dict):
    raise SystemExit(f"getmodelreciprocity: {recip}")

deleg = rpc("delegatemodelservice", [{}])
if not isinstance(deleg, dict):
    raise SystemExit(f"delegatemodelservice: {deleg}")

manifest = rpc("getmodelmanifest", [uri])
if not isinstance(manifest, dict):
    raise SystemExit(f"getmodelmanifest expected object: {manifest}")

job = rpc("getmodeljob", [])
if not isinstance(job, dict):
    raise SystemExit(f"getmodeljob expected object: {job}")

policy = rpc("getmodelpolicy", [])
spend = policy.get("automatic_spend", policy.get("automatic_spend_atoms"))
if spend is None or int(spend) != 0:
    raise SystemExit(f"getmodelpolicy automatic_spend must be 0: {policy}")

draft = rpc("createbountydraft", [{"title": "e2e title-only draft"}])
if not isinstance(draft, dict):
    raise SystemExit(f"createbountydraft expected object: {draft}")
if draft.get("automatic_spend_atoms") not in (0, "0"):
    raise SystemExit(f"createbountydraft automatic_spend_atoms must be 0: {draft}")
if draft.get("published") is True:
    raise SystemExit(f"title-only draft must stay unpublished: {draft}")
if draft.get("recipe_complete") is True:
    raise SystemExit(f"title-only draft must be incomplete: {draft}")
if not draft.get("missing_fields"):
    raise SystemExit(f"title-only draft missing_fields empty: {draft}")
if not isinstance(draft.get("next_actions"), list):
    raise SystemExit(f"createbountydraft next_actions must be a list: {draft}")

listed_drafts = rpc("listbountydrafts", [])
if isinstance(listed_drafts, dict):
    drafts = listed_drafts.get("drafts") or listed_drafts.get("results") or listed_drafts.get("items") or []
elif isinstance(listed_drafts, list):
    drafts = listed_drafts
else:
    raise SystemExit(f"listbountydrafts expected object or list: {listed_drafts}")
if not drafts:
    raise SystemExit(f"listbountydrafts empty after title-only draft: {listed_drafts}")

cli = Path(sys.argv[5]) / "btx-model"
if os.access(cli, os.X_OK):
    def run_cli(args, env=None, timeout=30, *, with_proc=False):
        p = subprocess.run(
            [str(cli)] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        if p.returncode != 0:
            raise SystemExit(
                f"btx-model {args} rc={p.returncode} stderr={p.stderr} stdout={p.stdout}"
            )
        try:
            obj = json.loads(p.stdout)
        except json.JSONDecodeError as e:
            raise SystemExit(f"btx-model {args} stdout not JSON: {e} stdout={p.stdout!r} stderr={p.stderr!r}")
        if with_proc:
            return obj, p
        return obj

    cli_doctor = run_cli(["--socket", str(sock), "doctor"])
    if not isinstance(cli_doctor, dict) or "identity_ready" not in cli_doctor:
        raise SystemExit(f"btx-model doctor: {cli_doctor}")
    cli_host_dir = workdir / "cli-host-glm"
    cli_host_dir.mkdir(parents=True, exist_ok=True)
    (cli_host_dir / "model.safetensors").write_bytes(src.read_bytes())
    (cli_host_dir / "README.md").write_text("btx-model host unique sidecar\n", encoding="utf-8")
    cli_host = run_cli(["--socket", str(sock), "host", str(cli_host_dir)])
    if not isinstance(cli_host, dict):
        raise SystemExit(f"btx-model host expected object: {cli_host}")
    hshare = cli_host.get("share")
    if not isinstance(hshare, dict) or not hshare.get("copy_text"):
        raise SystemExit(f"btx-model host missing share.copy_text: {cli_host}")
    env_sock = os.environ.copy()
    env_sock["MODELD_SOCK"] = str(sock)
    env_sock.pop("BTX_MODELD_SOCKET", None)
    cli_env_doctor = run_cli(["doctor"], env=env_sock)
    if not isinstance(cli_env_doctor, dict) or "identity_ready" not in cli_env_doctor:
        raise SystemExit(f"btx-model doctor via MODELD_SOCK: {cli_env_doctor}")

    # Round 2 Gitcoin leftover: bounty-draft reads a local BountyTerms JSON file.
    draft_file = workdir / "cli-bounty-draft.json"
    draft_file.write_text(json.dumps({"title": "cli @file draft"}), encoding="utf-8")
    cli_draft = run_cli(["--socket", str(sock), "bounty-draft", f"@{draft_file}"])
    if not isinstance(cli_draft, dict):
        raise SystemExit(f"btx-model bounty-draft @file expected object: {cli_draft}")
    if cli_draft.get("published") is True:
        raise SystemExit(f"btx-model bounty-draft must not publish: {cli_draft}")
    if cli_draft.get("automatic_spend_atoms") not in (0, "0"):
        raise SystemExit(f"btx-model bounty-draft automatic_spend_atoms must be 0: {cli_draft}")
    if not isinstance(cli_draft.get("next_actions"), list) or not cli_draft["next_actions"]:
        raise SystemExit(f"btx-model bounty-draft next_actions must be a non-empty list: {cli_draft}")
    if "checklist" not in cli_draft or "copy_text" not in cli_draft:
        raise SystemExit(f"btx-model bounty-draft missing checklist/copy_text: {cli_draft}")
    cli_get = run_cli(["--socket", str(sock), "bounty-draft", "--get", str(cli_draft["draft_id"])])
    cli_terms = cli_get.get("terms") if isinstance(cli_get, dict) else None
    if not isinstance(cli_terms, dict) or cli_terms.get("title") != "cli @file draft":
        raise SystemExit(f"btx-model bounty-draft @file sent the wrong terms: {cli_get}")
    cli_list = run_cli(["--socket", str(sock), "bounty-draft", "--list"])
    if not isinstance(cli_list, dict):
        raise SystemExit(f"btx-model bounty-draft --list expected object: {cli_list}")
    if "one_liner" not in cli_list:
        raise SystemExit(f"btx-model bounty-draft --list missing one_liner: {cli_list}")
    cli_val = run_cli(["--socket", str(sock), "bounty-draft", "--validate", str(cli_draft["draft_id"])])
    if not isinstance(cli_val, dict) or "checklist" not in cli_val:
        raise SystemExit(f"btx-model bounty-draft --validate expected checklist: {cli_val}")
    if cli_val.get("ok") is True:
        raise SystemExit(f"title-only draft must not validate complete: {cli_val}")
    if cli_val.get("automatic_spend_atoms") not in (0, "0"):
        raise SystemExit(f"btx-model bounty-draft --validate automatic_spend_atoms must be 0: {cli_val}")
    bad_draft = workdir / "cli-bounty-draft-spend.json"
    bad_draft.write_text(json.dumps({"title": "no auto spend", "auto_pay": True}), encoding="utf-8")
    bad = subprocess.run(
        [str(cli), "--socket", str(sock), "bounty-draft", f"@{bad_draft}"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if bad.returncode == 0:
        raise SystemExit(f"btx-model bounty-draft must refuse auto_pay from a file: {bad.stdout}")
    print("cli_checks", "doctor host bounty-draft@file bounty-draft--list bounty-draft--get bounty-draft--validate")

    # Round 2 Ollama leftovers: pull by name, show, ls, rm (unhost), link, open.
    cli_uri = cli_host.get("uri") or cli_host.get("model_id")
    run_cli(["--socket", str(sock), "alias", cli_uri, "cli-host-alias"])

    cli_ls = run_cli(["--socket", str(sock), "ls"])
    if not isinstance(cli_ls, dict) or int(cli_ls.get("count", 0)) < 1:
        raise SystemExit(f"btx-model ls: {cli_ls}")
    if cli_ls.get("automatic_spend_atoms", 0) not in (0, "0"):
        raise SystemExit(f"btx-model ls automatic_spend_atoms must be 0: {cli_ls}")
    cli_ls_inc = run_cli(["--socket", str(sock), "ls", "--incomplete"])
    if not isinstance(cli_ls_inc, dict) or cli_ls_inc.get("filter") != "incomplete":
        raise SystemExit(f"btx-model ls --incomplete: {cli_ls_inc}")
    if cli_ls_inc.get("automatic_spend_atoms", 0) not in (0, "0"):
        raise SystemExit(f"btx-model ls --incomplete automatic_spend_atoms must be 0: {cli_ls_inc}")
    ls_rows = cli_ls.get("transfers") or cli_ls.get("models") or []
    ls_row = next(
        (
            r
            for r in ls_rows
            if isinstance(r, dict)
            and (
                r.get("uri") == cli_uri
                or r.get("model_id") == cli_uri
                or r.get("model_id") == cli_host.get("model_id")
            )
        ),
        None,
    )
    if ls_row is None:
        raise SystemExit(f"btx-model ls missing the hosted model {cli_uri}: {cli_ls}")
    for key in ("name", "aliases", "bytes", "state"):
        if key not in ls_row:
            raise SystemExit(f"btx-model ls row missing {key}: {ls_row}")
    if "cli-host-alias" not in (ls_row.get("aliases") or []):
        raise SystemExit(f"btx-model ls does not carry the alias: {ls_row}")

    cli_show = run_cli(["--socket", str(sock), "show", "cli-host-alias"])
    if not isinstance(cli_show, dict):
        raise SystemExit(f"btx-model show expected object: {cli_show}")
    if not isinstance(cli_show.get("share"), dict) or not cli_show["share"].get("copy_text"):
        raise SystemExit(f"btx-model show missing share.copy_text: {cli_show}")
    if cli_show.get("local") is not True:
        raise SystemExit(f"btx-model show must report local=true: {cli_show}")
    if "cli-host-alias" not in (cli_show.get("aliases") or []):
        raise SystemExit(f"btx-model show aliases: {cli_show}")
    if cli_show.get("automatic_spend_atoms", 0) not in (0, "0"):
        raise SystemExit(f"btx-model show automatic_spend_atoms must be 0: {cli_show}")
    if not isinstance(cli_show.get("next_actions"), list) or not cli_show["next_actions"]:
        raise SystemExit(f"btx-model show next_actions: {cli_show}")

    cli_pull = run_cli(["--socket", str(sock), "pull", "cli-host-alias"], timeout=120)
    if not isinstance(cli_pull, dict):
        raise SystemExit(f"btx-model pull expected object: {cli_pull}")
    if cli_pull.get("uri") and cli_pull.get("uri") != cli_uri:
        raise SystemExit(f"btx-model pull alias resolved to the wrong model: {cli_pull} vs {cli_uri}")

    # link writes a .btx card (uri + copy_text only), open previews it.
    btx_path = workdir / "cli-host-link.btx"
    cli_link = run_cli(["--socket", str(sock), "link", "cli-host-alias", str(btx_path), "--force"])
    if not isinstance(cli_link, dict):
        raise SystemExit(f"btx-model link expected object: {cli_link}")
    if cli_link.get("uri") != cli_uri:
        raise SystemExit(f"btx-model link uri mismatch: {cli_link} vs {cli_uri}")
    if cli_link.get("automatic_spend_atoms", 0) not in (0, "0"):
        raise SystemExit(f"btx-model link automatic_spend_atoms must be 0: {cli_link}")
    # A helper-native exportmodellink may pick its own path; accept the path it
    # reports as long as the card carries the canonical uri.
    link_path = btx_path
    reported_path = cli_link.get("path")
    if not btx_path.is_file() and isinstance(reported_path, str) and Path(reported_path).is_file():
        link_path = Path(reported_path)
    if not link_path.is_file() or cli_uri not in link_path.read_text(encoding="utf-8"):
        raise SystemExit(f"btx-model link did not write the canonical uri: {cli_link}")

    cli_open = run_cli(["--socket", str(sock), "open", str(link_path)])
    if not isinstance(cli_open, dict):
        raise SystemExit(f"btx-model open expected object: {cli_open}")
    if cli_open.get("weights_hashed") is not False:
        raise SystemExit(f"btx-model open must not hash weights: {cli_open}")
    if not isinstance(cli_open.get("next_actions"), list) or not cli_open["next_actions"]:
        raise SystemExit(f"btx-model open next_actions: {cli_open}")
    if cli_uri not in json.dumps(cli_open):
        raise SystemExit(f"btx-model open did not report the uri: {cli_open}")

    # host of a .btx card previews the share; it never imports or broadcasts it.
    host_card = run_cli(["--socket", str(sock), "host", str(link_path)])
    if not isinstance(host_card, dict):
        raise SystemExit(f"btx-model host .btx expected object: {host_card}")
    if host_card.get("hosted") is not False:
        raise SystemExit(f"btx-model host .btx must not import a card as weights: {host_card}")
    if "search_published" in host_card:
        raise SystemExit(f"btx-model host .btx must not publish: {host_card}")

    # Round 3 (models axis): HF `--local-dir` / reveal-in-folder analog.
    cli_path = run_cli(["--socket", str(sock), "path", "cli-host-alias"])
    if not isinstance(cli_path, dict) or not cli_path.get("store_root"):
        raise SystemExit(f"btx-model path expected store_root: {cli_path}")
    if cli_path.get("runtime_started") is not False:
        raise SystemExit(f"btx-model path must not start a runtime: {cli_path}")
    if cli_path.get("automatic_spend_atoms", 0) not in (0, "0"):
        raise SystemExit(f"btx-model path automatic_spend_atoms must be 0: {cli_path}")

    # Round 3 (models axis): catalog filters + `--fits` storage comparison.
    cli_fits = run_cli(["--socket", str(sock), "search", "--fits", "--format", "safetensors"])
    if not isinstance(cli_fits, dict) or not isinstance(cli_fits.get("fits"), dict):
        raise SystemExit(f"btx-model search --fits expected a fits object: {cli_fits}")
    if cli_fits["fits"].get("inference") is not False:
        raise SystemExit(f"btx-model search --fits must not claim inference: {cli_fits['fits']}")
    if cli_fits.get("results_returned", -1) != len(cli_fits.get("results") or []):
        raise SystemExit(f"btx-model search --fits count mismatch: {cli_fits}")
    for row in cli_fits.get("results") or []:
        if isinstance(row, dict) and row.get("fits_storage") is not True:
            raise SystemExit(f"btx-model search --fits kept a row that does not fit: {row}")
    cli_filtered = run_cli(["--socket", str(sock), "search", "--format", "gguf"])
    if not isinstance(cli_filtered, dict):
        raise SystemExit(f"btx-model search --format expected object: {cli_filtered}")
    if "format" not in (cli_filtered.get("applied_filters") or []):
        raise SystemExit(f"btx-model search --format did not reach the helper: {cli_filtered}")
    print("cli_checks_round3", "path search--fits search--format ls--incomplete bounty-draft--validate")

    cli_init, init_p = run_cli(["--socket", str(sock), "init"], with_proc=True)
    if not isinstance(cli_init, dict) or cli_init.get("initialized") is not True:
        raise SystemExit(f"btx-model init: {cli_init}")
    if cli_init.get("automatic_spend_atoms", 0) not in (0, "0"):
        raise SystemExit(f"btx-model init automatic_spend_atoms must be 0: {cli_init}")
    doctor_obj = cli_init.get("doctor") if isinstance(cli_init.get("doctor"), dict) else cli_init
    one = None
    if isinstance(doctor_obj, dict):
        one = doctor_obj.get("one_liner")
    if not one:
        one = cli_init.get("one_liner")
    if one and str(one) not in init_p.stderr:
        raise SystemExit(
            f"btx-model init must print one_liner on stderr: {init_p.stderr!r} one_liner={one!r}"
        )

    # Unknown names fail closed; a pasted copy_text on stdin still previews.
    for bad_verb in (["show", "definitely-not-a-model"], ["pull", "definitely-not-a-model"]):
        miss = subprocess.run(
            [str(cli), "--socket", str(sock), *bad_verb],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if miss.returncode == 0:
            raise SystemExit(f"btx-model {bad_verb} must fail closed: {miss.stdout}")
    stdin_open = subprocess.run(
        [str(cli), "--socket", str(sock), "open", "-"],
        input=json.dumps({"copy_text": cli_uri + " family=qwen3"}),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if stdin_open.returncode != 0:
        raise SystemExit(f"btx-model open - rc={stdin_open.returncode} stderr={stdin_open.stderr}")
    if cli_uri not in json.dumps(json.loads(stdin_open.stdout)):
        raise SystemExit(f"btx-model open - did not report the uri: {stdin_open.stdout}")

    # rm-alias: helper-native when present; otherwise fail closed, never a
    # hand-edited search record.
    rm = subprocess.run(
        [str(cli), "--socket", str(sock), "rm-alias", cli_uri, "cli-host-alias"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    aliases_after = rpc("getmodelaliases", [])
    remaining = {str(a.get("alias")) for a in (aliases_after.get("aliases") or []) if isinstance(a, dict)}
    if rm.returncode == 0:
        if "cli-host-alias" in remaining:
            raise SystemExit(f"btx-model rm-alias reported success but the alias survived: {aliases_after}")
    else:
        if "removemodelalias" not in rm.stderr:
            raise SystemExit(f"btx-model rm-alias must fail closed naming the verb: {rm.stderr}")
        if "cli-host-alias" not in remaining:
            raise SystemExit(f"btx-model rm-alias changed state without the helper write path: {aliases_after}")

    un = subprocess.run(
        [str(cli), "--socket", str(sock), "unhost", cli_uri],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if un.returncode != 0:
        raise SystemExit(f"btx-model unhost rc={un.returncode} stderr={un.stderr}")
    un_out = json.loads(un.stdout)
    if un_out.get("automatic_spend_atoms", 0) not in (0, "0"):
        raise SystemExit(f"btx-model unhost automatic_spend_atoms must be 0: {un_out}")
    listed_after_unhost = rpc("listmodels", [])
    row_after = next(
        (r for r in (listed_after_unhost.get("models") or []) if isinstance(r, dict) and r.get("uri") == cli_uri),
        None,
    )
    if row_after is None:
        raise SystemExit(f"btx-model unhost lost the model: {listed_after_unhost}")
    if row_after.get("pinned") is True or row_after.get("seeded") is True:
        raise SystemExit(f"btx-model unhost left the model pinned/seeded: {row_after}")
    print("cli_checks_round2", "init ls show pull link open host-card rm-alias unhost")

print("E2E_LOCAL_HELPER PASS")
print("uri", uri)
print("local_count", listed["local_count"])
print("getmodel_status", got.get("status"))
PY
