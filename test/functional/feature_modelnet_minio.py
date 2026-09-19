#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Isolated-regtest E2E for the cloud origin layout matrix against real MinIO.

Complements contrib/modelnet/e2e-minio-layouts.sh, which drives btx-modeld over
its unix socket. This test drives the same verbs through btxd's proxied RPCs, so
it covers the node -> helper hop as well.

Docker and MinIO are optional. When either is missing this test does NOT skip
itself: it records HONEST_NOT_RUN for the real-MinIO legs and still asserts the
whole matrix against in-process FakeS3. A missing container is not a pass for
the MinIO claim, and the log says so.

Honest scope, from this tree's source:
  - setcloudstorage `layout` is a CloudObjectLayout: AUTO|SOURCE_FILES|
    PIECE_OBJECTS. WHOLE_FILE and LARGE_EXTENTS are PhysicalObjectLayout names
    and are rejected here; getmodelobjectlayout reports them as arithmetic only.
  - AUTO, SOURCE_FILES, and PIECE_OBJECTS have a store/hydrate path.
    WHOLE_FILE and LARGE_EXTENTS remain PhysicalObjectLayout arithmetic.

Credentials are the fixed sentinels BTX_TEST_ACCESS_SENTINEL /
BTX_TEST_SECRET_SENTINEL, written once to a 0600 file outside the node datadir
and passed only as `credential_ref`. After every op the whole node datadir is
scanned and must not contain either sentinel. Nothing logged here contains them.

Never production btxd. Never SIGKILL the live GPU attestor. --timeout-factor=1.

  python3 test/functional/feature_modelnet_minio.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

import datetime
import hashlib
import hmac
import json
import os
import re
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import get_datadir_path

MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]

# MinIO requires MINIO_ROOT_USER >= 3 and MINIO_ROOT_PASSWORD >= 8 characters.
# Both sentinels are 24 characters, so no padding is needed.
ACCESS_SENTINEL = "BTX_TEST_ACCESS_SENTINEL"
SECRET_SENTINEL = "BTX_TEST_SECRET_SENTINEL"
SENTINELS = (ACCESS_SENTINEL, SECRET_SENTINEL)

BUCKET = "btx-e2e-models"
REGION = "us-east-1"
PREFIX = "v1"

CLOUD_LAYOUTS = ["AUTO", "SOURCE_FILES", "PIECE_OBJECTS"]
PHYSICAL_ONLY = ["WHOLE_FILE", "LARGE_EXTENTS"]


def redact(text):
    out = str(text)
    for needle, mask in ((ACCESS_SENTINEL, "BTX_TEST_ACCESS_[REDACTED]"),
                         (SECRET_SENTINEL, "BTX_TEST_SECRET_[REDACTED]")):
        out = out.replace(needle, mask)
    return out


def write_safetensors(path, marker):
    """Valid safetensors: LE64 header length, header JSON, then exactly the
    tensor bytes the header declares. Distinct markers give distinct artifacts."""
    tensor = (marker.encode() * 512)[:8192].ljust(8192, b"\0")
    header = json.dumps(
        {"w": {"dtype": "U8", "shape": [len(tensor)], "data_offsets": [0, len(tensor)]}},
        separators=(",", ":"),
    ).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<Q", len(header)) + header + tensor)
    return hashlib.sha384(path.read_bytes()).hexdigest()


class ModelNetMinioLayoutsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.modeld_proc = None
        self.modeld_log = None
        self.modeldir = None
        self.modeld_socket = None
        self.container = None
        self.endpoint = None
        self.docker = None
        self.not_run = []

    def skip_test_if_missing_module(self):
        # Platform only. Docker and MinIO absence is HONEST_NOT_RUN, not a skip.
        self.skip_if_platform_not_posix()

    # --- helper lifecycle ---------------------------------------------------
    def _modeld_path(self):
        exeext = self.config["environment"].get("EXEEXT", "")
        name = f"btx-modeld{exeext}"
        candidates = []
        for env_name in ("BTXMODELD", "BTX_MODELD"):
            env_val = os.environ.get(env_name)
            if env_val:
                candidates.append(Path(env_val))
        builddir = self.config["environment"].get("BUILDDIR")
        if builddir:
            candidates.append(Path(builddir) / "bin" / name)
        bitcoind = getattr(self.options, "bitcoind", None)
        if bitcoind:
            candidates.append(Path(bitcoind).resolve().parent / name)
        for cand in candidates:
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        return None

    def _start_helper(self):
        datadir = Path(get_datadir_path(self.options.tmpdir, 0))
        datadir.mkdir(parents=True, exist_ok=True)
        self.modeldir = datadir / "modeldir"
        self.modeldir.mkdir(parents=True, exist_ok=True)
        self.modeld_socket = self.modeldir / "modeld.sock"
        if self.modeld_socket.exists():
            self.modeld_socket.unlink()
        argv = [
            str(self._modeld_path()),
            f"-modeldir={self.modeldir}",
            "-modelstorage=64MiB",
            f"-modelrpcsocket={self.modeld_socket}",
        ]
        self.modeld_log = (self.modeldir / "modeld.log").open("a", encoding="utf-8")
        self.log.info("starting %s", " ".join(argv))
        self.modeld_proc = subprocess.Popen(
            argv, stdout=self.modeld_log, stderr=subprocess.STDOUT, cwd=str(datadir)
        )

    def _stop_helper(self):
        proc = self.modeld_proc
        self.modeld_proc = None
        if proc is None:
            return
        if proc.poll() is None:
            proc.terminate()  # test helper only; never a production btxd
            try:
                proc.wait(timeout=max(5.0, 30.0 * float(self.options.timeout_factor)))
            except subprocess.TimeoutExpired:
                self.log.warning("test helper ignored SIGTERM; killing the test child only")
                proc.kill()
                proc.wait(timeout=10)
        if self.modeld_log is not None:
            self.modeld_log.close()
            self.modeld_log = None

    def _wait_helper_ready(self):
        """Readiness probe must reach the helper. getmodelnetworkinfo is not
        one: btxd answers it locally while the helper socket is still down."""
        node = self.nodes[0]
        deadline = time.time() + 60 * float(self.options.timeout_factor)
        while time.time() < deadline:
            try:
                node.getcloudstorageinfo({})
                return
            except JSONRPCException:
                time.sleep(0.25)
        raise AssertionError("btx-modeld never became reachable again after restart")

    def _restart_helper(self):
        """Stop the helper, restart it, and wait for the node's proxy to work
        again. Forces cloud.json rediscovery rather than reusing warm state."""
        self._stop_helper()
        self._start_helper()
        self._wait_helper_ready()

    def setup_nodes(self):
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld not found; build it first (this test never compiles)")
        self._start_helper()
        if self.modeld_proc.poll() is not None:
            raise AssertionError(f"btx-modeld exited {self.modeld_proc.returncode}")
        self.extra_args = [[
            "-modelnet=1",
            f"-modelrpcsocket={self.modeld_socket}",
            *MATMUL_OFF_ARGS,
        ]]
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

    def shutdown(self):
        self._stop_helper()
        self._stop_container()
        return super().shutdown()

    # --- container lifecycle ------------------------------------------------
    def _docker_bin(self):
        cand = Path(os.environ.get("DOCKER_BIN", "/usr/bin/docker"))
        if not (cand.is_file() and os.access(cand, os.X_OK)):
            return None
        try:
            subprocess.run([str(cand), "version"], check=True, capture_output=True, timeout=30)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            return None
        return cand

    def _minio_image(self):
        for ref in (os.environ.get("BTX_MINIO_IMAGE"), "minio/minio:latest", "minio/minio"):
            if not ref:
                continue
            probe = subprocess.run([str(self.docker), "image", "inspect", ref], capture_output=True)
            if probe.returncode == 0:
                return ref
        # A dangling minio/minio (repo present, tag <none>) is still runnable by ID.
        listing = subprocess.run(
            [str(self.docker), "images", "--no-trunc", "--format", "{{.Repository}} {{.ID}}"],
            capture_output=True, text=True,
        )
        for line in listing.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == "minio/minio":
                return parts[1]
        return None

    def _start_container(self):
        """Return an http://127.0.0.1:<port> endpoint, or None with an
        HONEST_NOT_RUN note recorded."""
        self.docker = self._docker_bin()
        if self.docker is None:
            self.not_run.append("docker unusable (absent, or daemon/permission denied)")
            return None
        image = self._minio_image()
        if image is None:
            pull = subprocess.run(
                [str(self.docker), "pull", "minio/minio:latest"], capture_output=True, timeout=600
            )
            image = self._minio_image() if pull.returncode == 0 else None
        if image is None:
            self.not_run.append("docker cannot pull minio/minio (offline, rate limited, or blocked)")
            return None

        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        name = f"btx-func-minio-{os.getpid()}"
        # Loopback publish, never --network host, so this cannot clash with a
        # port already bound on the box.
        run = subprocess.run(
            [str(self.docker), "run", "-d", "--name", name, "--pull", "never",
             "-p", f"127.0.0.1:{port}:9000",
             "-e", f"MINIO_ROOT_USER={ACCESS_SENTINEL}",
             "-e", f"MINIO_ROOT_PASSWORD={SECRET_SENTINEL}",
             image, "server", "/data"],
            capture_output=True, text=True, timeout=180,
        )
        if run.returncode != 0:
            self.not_run.append(f"docker run failed: {redact(run.stderr.strip())}")
            return None
        self.container = name
        endpoint = f"http://127.0.0.1:{port}"
        deadline = time.time() + 90 * float(self.options.timeout_factor)
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"{endpoint}/minio/health/live", timeout=5) as resp:
                    if resp.status == 200:
                        self.log.info("MinIO live on %s", endpoint)
                        return endpoint
            except (urllib.error.URLError, OSError):
                time.sleep(0.5)
        self.not_run.append("MinIO container never became live on the published loopback port")
        return None

    def _stop_container(self):
        name = self.container
        self.container = None
        if name is None or self.docker is None:
            return
        subprocess.run([str(self.docker), "rm", "-f", name], capture_output=True)
        self.log.info("removed container %s", name)

    # --- minimal SigV4 S3, to create the bucket and verify it independently --
    def _sigv4(self, method, key="", query="", body=b""):
        now = datetime.datetime.now(datetime.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")
        host = self.endpoint.split("://", 1)[1]
        canonical_uri = "/" + BUCKET + (f"/{key}" if key else "")
        payload_hash = hashlib.sha256(body).hexdigest()
        canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
        signed_headers = "host;x-amz-content-sha256;x-amz-date"
        canonical_request = "\n".join(
            [method, canonical_uri, query, canonical_headers, signed_headers, payload_hash]
        )
        scope = f"{datestamp}/{REGION}/s3/aws4_request"
        to_sign = "\n".join(
            ["AWS4-HMAC-SHA256", amz_date, scope,
             hashlib.sha256(canonical_request.encode()).hexdigest()]
        )
        signing_key = ("AWS4" + SECRET_SENTINEL).encode()
        for part in (datestamp, REGION, "s3", "aws4_request"):
            signing_key = hmac.new(signing_key, part.encode(), hashlib.sha256).digest()
        signature = hmac.new(signing_key, to_sign.encode(), hashlib.sha256).hexdigest()
        url = self.endpoint + canonical_uri + (f"?{query}" if query else "")
        req = urllib.request.Request(url, method=method, data=body or None)
        req.add_header("x-amz-date", amz_date)
        req.add_header("x-amz-content-sha256", payload_hash)
        req.add_header(
            "Authorization",
            f"AWS4-HMAC-SHA256 Credential={ACCESS_SENTINEL}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}",
        )
        return req

    def _s3(self, method, key="", query="", body=b""):
        try:
            with urllib.request.urlopen(self._sigv4(method, key, query, body), timeout=30) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def _bucket_keys(self):
        status, body = self._s3("GET", query="list-type=2")
        if status != 200:
            return None
        ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
        return [el.text for el in ET.fromstring(body).iter(f"{ns}Key")]

    def _reconstruct_object(self, keys, artifact):
        if not artifact or not keys:
            return None
        files = [k for k in keys if artifact in k and re.search(r"/files/\d+$", k)]
        if files:
            status, body = self._s3("GET", key=sorted(files)[0])
            if status != 200:
                raise AssertionError(f"independent GET {files[0]} returned HTTP {status}")
            return body
        pieces = []
        for k in keys:
            m = re.search(r"/(\d+)/(\d+)\.piece$", k)
            if artifact in k and m:
                pieces.append((int(m.group(1)), int(m.group(2)), k))
        if not pieces:
            return None
        pieces.sort()
        buf = b""
        for _, _, k in pieces:
            status, body = self._s3("GET", key=k)
            if status != 200:
                raise AssertionError(f"independent GET {k} returned HTTP {status}")
            buf += body
        return buf

    # --- assertions --------------------------------------------------------
    def _zero_spend(self, obj, where):
        if not isinstance(obj, dict):
            raise AssertionError(f"{where} expected object: {redact(obj)}")
        if obj.get("automatic_spend_atoms", 0) not in (0, "0"):
            raise AssertionError(f"{where} automatic_spend_atoms={obj.get('automatic_spend_atoms')}")
        blob = json.dumps(obj)
        for needle in SENTINELS:
            if needle in blob:
                raise AssertionError(f"{where} leaked a sentinel credential into its RPC response")
        for needle in ("aws_secret_access_key", "secret_access_key"):
            if needle in blob.lower() and "***" not in blob:
                raise AssertionError(f"{where} leaked secret needle {needle}")
        return obj

    def _assert_no_sentinel_in_logs(self, where):
        """After every op: nothing in the node datadir (btxd debug.log, the
        helper's modeldir, cloud.json) may contain a sentinel."""
        datadir = Path(get_datadir_path(self.options.tmpdir, 0))
        hits = []
        for path in sorted(datadir.rglob("*")):
            if not path.is_file():
                continue
            try:
                blob = path.read_bytes()
            except OSError:
                continue
            if any(needle.encode() in blob for needle in SENTINELS):
                hits.append(str(path.relative_to(datadir)))
        if hits:
            raise AssertionError(f"{where}: sentinel credential found in datadir: {sorted(set(hits))}")

    def _try(self, fn, *args, where=""):
        """Call an RPC, returning (result, error). A missing method is recorded
        HONEST_NOT_RUN rather than failing the run."""
        try:
            return fn(*args), None
        except JSONRPCException as exc:
            err = exc.error if isinstance(exc.error, dict) else {"message": str(exc)}
            blob = f"{err.get('code', '')} {err.get('message', '')}".lower()
            if "method_not_found" in blob or "unknown model rpc" in blob:
                self.not_run.append(f"{where or 'rpc'}: {redact(err)}")
            return None, err

    # --- the matrix --------------------------------------------------------
    def _origin_get_ops(self, obj):
        ops = obj.get("origin_get_ops") if isinstance(obj, dict) else None
        try:
            return int(ops)
        except (TypeError, ValueError):
            return 0

    def _assert_piece_objects_hydrate_incomplete(self, mode, fake, uri, artifact_id, want_sha):
        """Unique incomplete-catalog hydrate after a PIECE_OBJECTS store.

        TryHydrateFromCloud only runs for catalog models[i].incomplete. A local
        import leaves entries complete, so this leg stops the helper, flips that
        flag, drops local *.piece files, and requires getmodel to hydrate.
        cloud_uploaded already proved the objects exist: failure here is FAIL
        for FakeS3 and MinIO, not HONEST_NOT_RUN.
        """
        node = self.nodes[0]
        if not uri:
            raise AssertionError(f"{mode} PIECE_OBJECTS hydrate-incomplete: missing uri")
        if not artifact_id:
            raise AssertionError(f"{mode} PIECE_OBJECTS hydrate-incomplete: missing artifact_id")

        self._stop_helper()
        catalog_path = Path(self.modeldir) / "catalog.json"
        if not catalog_path.is_file():
            raise AssertionError(f"{mode} PIECE_OBJECTS hydrate-incomplete: missing {catalog_path}")
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        models = catalog.get("models")
        if not isinstance(models, list):
            raise AssertionError(f"{mode} PIECE_OBJECTS hydrate-incomplete: catalog.json has no models[]")
        matched = False
        want = str(artifact_id).lower()
        for entry in models:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("artifact_id") or "").lower() != want:
                continue
            entry["incomplete"] = True
            matched = True
            break
        if not matched:
            raise AssertionError(
                f"{mode} PIECE_OBJECTS hydrate-incomplete: no catalog model with "
                f"artifact_id={artifact_id}")
        catalog_path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")

        art_dir = Path(self.modeldir) / "store" / "artifacts" / str(artifact_id)
        deleted = []
        if art_dir.is_dir():
            for piece in art_dir.rglob("*.piece"):
                piece.unlink()
                deleted.append(str(piece.relative_to(art_dir)))
        if not deleted:
            raise AssertionError(
                f"{mode} PIECE_OBJECTS hydrate-incomplete: no local *.piece files under {art_dir}")
        self.log.info("  hydrate-incomplete: marked catalog incomplete, deleted %d local piece(s)",
                      len(deleted))

        self._start_helper()
        self._wait_helper_ready()
        self._assert_no_sentinel_in_logs(f"{mode} PIECE_OBJECTS hydrate-incomplete helper ready")

        got = self._zero_spend(node.getmodel(uri), f"{mode} getmodel PIECE_OBJECTS hydrate-incomplete")
        if (got.get("uri") or "") != uri:
            raise AssertionError(
                f"getmodel uri changed on hydrate-incomplete: {redact(got)} vs {uri}")
        hydrated = got.get("cloud_hydrated") is True
        origin_gets = self._origin_get_ops(got)
        if not hydrated and origin_gets <= 0:
            raise AssertionError(
                f"{mode} PIECE_OBJECTS getmodel did not hydrate incomplete catalog "
                f"(cloud_uploaded was true; this is FAIL, not HONEST_NOT_RUN): {redact(got)}")
        self.log.info(
            "  hydrate-incomplete getmodel uri=%s cloud_hydrated=%s origin_get_ops=%s "
            "automatic_spend_atoms=%s",
            got.get("uri"), got.get("cloud_hydrated"), got.get("origin_get_ops"),
            got.get("automatic_spend_atoms"))
        self._assert_no_sentinel_in_logs(f"{mode} getmodel PIECE_OBJECTS hydrate-incomplete")

        if not fake:
            keys = self._bucket_keys()
            body = self._reconstruct_object(keys, artifact_id)
            if body is None:
                raise AssertionError(
                    f"{mode} PIECE_OBJECTS hydrate-incomplete: independent GET found no piece objects")
            if hashlib.sha384(body).hexdigest() != want_sha:
                raise AssertionError(
                    f"{mode} PIECE_OBJECTS hydrate-incomplete: independent GET sha384 mismatch")
            self.log.info("  hydrate-incomplete independent GET of piece objects sha384 matches")

    def _cloud_cfg(self, layout, fake):
        return {
            "endpoint": "https://fake.invalid" if fake else self.endpoint,
            "bucket": BUCKET,
            "prefix": PREFIX,
            "region": REGION,
            "provider": "MINIO",
            "layout": layout,
            "credential_ref": str(self.creds),
            "credential_ref_kind": "path",
            "use_fake": fake,
            "allow_http_loopback": not fake,
            "automatic_spend_atoms": 0,
            "idempotency_key": f"minio-{layout}-{'fake' if fake else 'live'}",
        }

    def _run_matrix(self, fake):
        node = self.nodes[0]
        mode = "FakeS3" if fake else "MinIO"
        self.log.info("=== %s layout matrix ===", mode)

        # Raw secrets in RPC JSON must always be refused, in either mode.
        try:
            node.setcloudstorage({
                "endpoint": "https://acct.r2.cloudflarestorage.com",
                "bucket": BUCKET,
                "aws_secret_access_key": "supersecretvalue",
                "idempotency_key": "minio-secret-reject",
            })
            raise AssertionError("setcloudstorage must reject raw secrets in RPC JSON")
        except JSONRPCException as exc:
            blob = str(exc.error if isinstance(exc.error, dict) else exc).lower()
            if "credential" not in blob and "secret" not in blob:
                raise AssertionError(f"setcloudstorage secret reject text: {exc}") from exc
        self._assert_no_sentinel_in_logs(f"{mode} raw-secret reject")

        # allow_link_local must stay refused even from a loopback config.
        try:
            cfg = self._cloud_cfg("AUTO", fake)
            cfg["allow_link_local"] = True
            cfg["idempotency_key"] = f"minio-link-local-{'fake' if fake else 'live'}"
            node.setcloudstorage(cfg)
            raise AssertionError("setcloudstorage must reject allow_link_local")
        except JSONRPCException as exc:
            blob = str(exc.error if isinstance(exc.error, dict) else exc).lower()
            if "link_local" not in blob and "link-local" not in blob:
                raise AssertionError(f"allow_link_local reject text: {exc}") from exc
        self._assert_no_sentinel_in_logs(f"{mode} allow_link_local reject")

        # The canonical artifact is imported once, then re-read under every
        # layout. Artifact identity is content-addressed, so importing the same
        # bytes twice is refused; each layout therefore gets its own payload for
        # the store path and shares the canonical one for the identity check.
        canon_src = Path(self.options.tmpdir) / f"canon-{mode.lower()}" / "model.safetensors"
        canon_sha = write_safetensors(canon_src, f"btx-minio-canonical-{mode}\n")
        self._zero_spend(node.setcloudstorage(self._cloud_cfg("SOURCE_FILES", fake)),
                         f"{mode} setcloudstorage canonical")
        canon, err = self._try(node.importmodel, str(canon_src), where="importmodel")
        if canon is None:
            self.not_run.append(f"{mode} canonical import failed: {redact(err)}")
            return
        self._zero_spend(canon, f"{mode} importmodel canonical")
        canon_uri = canon.get("uri") or canon.get("model_id")
        canon_artifact = canon.get("artifact_id")
        if not canon_uri:
            raise AssertionError(f"canonical import returned no uri: {redact(canon)}")
        self.log.info("%s canonical uri=%s cloud_uploaded=%s", mode, canon_uri, canon.get("cloud_uploaded"))
        self._assert_no_sentinel_in_logs(f"{mode} canonical import")

        uploaded_layouts = []
        for layout in CLOUD_LAYOUTS:
            self.log.info("--- %s layout %s ---", mode, layout)
            applied, err = self._try(node.setcloudstorage, self._cloud_cfg(layout, fake),
                                     where="setcloudstorage")
            if applied is None:
                self.log.info("HONEST_NOT_RUN %s setcloudstorage %s: %s", mode, layout, redact(err))
                continue
            self._zero_spend(applied, f"{mode} setcloudstorage {layout}")
            if applied.get("secrets_in_response") is not False:
                raise AssertionError(f"setcloudstorage must report secrets_in_response=false: {redact(applied)}")
            if applied.get("credential_ref") and str(self.creds) == applied.get("credential_ref"):
                raise AssertionError(f"getcloudstorageinfo must not echo the full credential path: {redact(applied)}")
            self.log.info("  applied=%s effective_layout=%s credential_ref=%s",
                          applied.get("applied"), applied.get("layout"), applied.get("credential_ref"))
            self._assert_no_sentinel_in_logs(f"{mode} setcloudstorage {layout}")

            probe = self._zero_spend(node.testcloudstorage({}), f"{mode} testcloudstorage {layout}")
            if probe.get("live_r2_wan") is True:
                raise AssertionError(f"testcloudstorage must not claim live WAN: {redact(probe)}")
            self.log.info("  testcloudstorage probe_ok=%s", probe.get("probe_ok"))
            self._assert_no_sentinel_in_logs(f"{mode} testcloudstorage {layout}")

            info = self._zero_spend(node.getcloudstorageinfo({}), f"{mode} getcloudstorageinfo {layout}")
            self.log.info("  getcloudstorageinfo configured=%s layout=%s auth_ok=%s",
                          info.get("configured"), info.get("layout"), info.get("auth_ok"))
            self._assert_no_sentinel_in_logs(f"{mode} getcloudstorageinfo {layout}")

            src = Path(self.options.tmpdir) / f"import-{mode.lower()}-{layout.lower()}" / "model.safetensors"
            src_sha = write_safetensors(src, f"btx-minio-{mode}-{layout}\n")
            imported, err = self._try(node.importmodel, str(src), where="importmodel")
            if imported is None:
                self.log.info("HONEST_NOT_RUN %s importmodel %s: %s", mode, layout, redact(err))
                continue
            self._zero_spend(imported, f"{mode} importmodel {layout}")
            uri = imported.get("uri") or imported.get("model_id")
            self.log.info("  importmodel uri=%s cloud_uploaded=%s cloud_error=%s",
                          uri, imported.get("cloud_uploaded"), imported.get("cloud_error", ""))
            self._assert_no_sentinel_in_logs(f"{mode} importmodel {layout}")

            self._restart_helper()
            self.log.info("  helper restarted; forcing cloud.json rediscovery")
            self._assert_no_sentinel_in_logs(f"{mode} helper restart {layout}")
            again = self._zero_spend(node.getcloudstorageinfo({}),
                                     f"{mode} getcloudstorageinfo after restart {layout}")
            if again.get("layout") != info.get("layout"):
                raise AssertionError(
                    f"layout not rediscovered after restart: {redact(again)} vs {redact(info)}")
            self.log.info("  rediscovered configured=%s layout=%s", again.get("configured"), again.get("layout"))
            residency = self._zero_spend(node.getmodelresidency({}), f"{mode} getmodelresidency {layout}")
            if residency.get("remote_existence_implies_verified_remote") is True:
                raise AssertionError(f"HeadObject must not imply VERIFIED_REMOTE: {redact(residency)}")
            self._assert_no_sentinel_in_logs(f"{mode} getmodelresidency {layout}")

            got = self._zero_spend(node.getmodel(uri), f"{mode} getmodel {layout}")
            if (got.get("uri") or "") != uri:
                raise AssertionError(f"getmodel returned a different uri after restart: {redact(got)}")
            self.log.info("  getmodel status=%s artifact_id=%s", got.get("status"), got.get("artifact_id"))
            self._assert_no_sentinel_in_logs(f"{mode} getmodel {layout}")

            # The identity check: the canonical btx:// must resolve to exactly
            # the same uri and artifact_id under this layout.
            canon_read = self._zero_spend(node.getmodel(canon_uri),
                                          f"{mode} getmodel canonical under {layout}")
            if (canon_read.get("uri") or "") != canon_uri:
                raise AssertionError(f"canonical uri changed under {layout}: {redact(canon_read)}")
            if canon_read.get("artifact_id") != canon_artifact:
                raise AssertionError(
                    f"canonical artifact_id changed under {layout}: "
                    f"{canon_read.get('artifact_id')} vs {canon_artifact}")
            self.log.info("  canonical btx:// unchanged under %s", layout)
            self._assert_no_sentinel_in_logs(f"{mode} canonical read under {layout}")

            if imported.get("cloud_uploaded"):
                uploaded_layouts.append(layout)

            # Independent reads straight out of the bucket, bypassing btxd and
            # the helper, so byte identity is checked against the stored objects
            # rather than against an RPC claim.
            if not fake:
                keys = self._bucket_keys()
                self.log.info("  bucket objects: %s", keys)
                for artifact, want_sha, tag in ((got.get("artifact_id"), src_sha, f"{layout} payload"),
                                                (canon_artifact, canon_sha, "canonical payload")):
                    body = self._reconstruct_object(keys, artifact)
                    if body is None:
                        self.log.info("  no source-file or piece object for the %s: nothing to read back", tag)
                        continue
                    if hashlib.sha384(body).hexdigest() != want_sha:
                        raise AssertionError(f"object bytes differ from the local file for the {tag}")
                    self.log.info("  independent GET of the %s sha384 matches the local file", tag)

            if layout == "PIECE_OBJECTS" and imported.get("cloud_uploaded"):
                self._assert_piece_objects_hydrate_incomplete(
                    mode, fake, uri,
                    imported.get("artifact_id") or got.get("artifact_id"),
                    src_sha,
                )

        # PhysicalObjectLayout names are not cloud layouts. Confirm
        # setcloudstorage says so, then record the arithmetic it does publish.
        for layout in PHYSICAL_ONLY:
            try:
                node.setcloudstorage(self._cloud_cfg(layout, fake))
                raise AssertionError(f"setcloudstorage accepted {layout} as a CloudObjectLayout")
            except JSONRPCException as exc:
                blob = str(exc.error if isinstance(exc.error, dict) else exc)
                if "layout must be" not in blob:
                    raise AssertionError(f"{layout} reject text: {exc}") from exc
                self.log.info("  setcloudstorage correctly rejects %s: %s", layout, blob)
            plan, err = self._try(node.getmodelobjectlayout,
                                  {"layout": layout, "file_size_bytes": canon_src.stat().st_size},
                                  where="getmodelobjectlayout")
            if plan is None:
                self.log.info("HONEST_NOT_RUN getmodelobjectlayout %s: %s", layout, redact(err))
            else:
                self._zero_spend(plan, f"getmodelobjectlayout {layout}")
                self.log.info("  getmodelobjectlayout effective=%s cloud_r2_auto=%s",
                              plan.get("effective"), plan.get("cloud_r2_auto"))
            self.log.info(
                "NOT_A_CLOUD_LAYOUT %s: PhysicalObjectLayout arithmetic only; no cloud "
                "representation, so cross-layout byte identity is unprovable by construction.", layout)
            self._assert_no_sentinel_in_logs(f"{mode} {layout} arithmetic")

        if fake:
            self.log.info(
                "%s store+read succeeded for %s. HONEST_NOT_RUN real S3 wire protocol: FakeS3 is "
                "in-process, so there was no socket and no independent reader.", mode, uploaded_layouts)
        elif uploaded_layouts:
            self.log.info("PROVEN cloud byte round-trip (store + independent GET + sha384) for %s",
                          uploaded_layouts)
        else:
            self.not_run.append("no layout completed a MinIO byte round-trip")
        for layout in CLOUD_LAYOUTS:
            if layout not in uploaded_layouts:
                self.log.info(
                    "NOT_IMPLEMENTED %s %s: config accepted and rediscovered, but no object was "
                    "stored.", mode, layout)

    def run_test(self):
        self.creds = Path(self.options.tmpdir) / "cloud-creds.ini"
        self.creds.write_text(
            f"access_key_id={ACCESS_SENTINEL}\nsecret_access_key={SECRET_SENTINEL}\n",
            encoding="utf-8",
        )
        os.chmod(self.creds, 0o600)
        self.log.info("wrote 0600 credential_ref file %s (values not logged)", self.creds.name)

        try:
            self.endpoint = self._start_container()
            if self.endpoint is not None:
                status, _ = self._s3("PUT")
                if status not in (200, 409):
                    self.not_run.append(f"bucket create PUT /{BUCKET} returned HTTP {status}")
                    self.endpoint = None
                else:
                    self.log.info("bucket %s ready (HTTP %d)", BUCKET, status)

            if self.endpoint is not None:
                self._run_matrix(fake=False)
            else:
                for note in self.not_run:
                    self.log.info("HONEST_NOT_RUN real MinIO: %s", note)
                self.log.info(
                    "falling back to in-process FakeS3: proves layout resolution, config "
                    "persistence, restart rediscovery and secret hygiene, but is NOT WAN evidence "
                    "and not evidence of a real S3 wire protocol.")
                self._run_matrix(fake=True)
        finally:
            self._stop_container()

        # Money RPCs must survive the helper going away.
        self._stop_helper()
        if not isinstance(self.nodes[0].getblockcount(), int):
            raise AssertionError("getblockcount broke after the test helper stopped")
        self._assert_no_sentinel_in_logs("helper down")

        for note in self.not_run:
            self.log.info("HONEST_NOT_RUN %s", note)
        self.log.info("modelnet MinIO layout e2e passed; HONEST_NOT_RUN=%d", len(self.not_run))


if __name__ == "__main__":
    ModelNetMinioLayoutsTest(__file__).main()
