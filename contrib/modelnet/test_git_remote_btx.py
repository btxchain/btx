#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Drive git-remote-btx through the remote-helper command loop.

The scratch repository lives under test-data/git-helper next to this repository
and is removed before this process exits. Nothing is created under /tmp.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import traceback
from pathlib import Path

HELPER = Path(__file__).resolve().parent / "git-remote-btx"
ROOT = Path(__file__).resolve().parents[3] / "test-data" / "git-helper"
STATE = ROOT / "state"
REPO = ROOT / "repo"
HOOKS = ROOT / "empty-hooks"
SCRATCH = ROOT / "tmp"


def run_helper(
    url: str,
    script: str,
    remote: str = "origin",
    extra_env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    env = None
    if extra_env is not None:
        env = os.environ.copy()
        env.update(extra_env)
    proc = subprocess.run(
        [sys.executable, str(HELPER), remote, url],
        input=script.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(ROOT),
        env=env,
        check=False,
    )
    return proc.returncode, proc.stdout.decode("utf-8"), proc.stderr.decode("utf-8")


def assert_true(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)


def assert_no_ok(out: str) -> None:
    bad = [line for line in out.splitlines() if line.startswith("ok ")]
    assert_true(not bad, out)


def journal_text() -> str:
    path = STATE / "btx-ref-journal"
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def test_helper_does_not_shell_or_spend() -> None:
    source = HELPER.read_text(encoding="utf-8")
    for banned in ("os.system", "shell=True", "automatic_spend"):
        assert_true(banned not in source, f"helper contains {banned}")


def test_capabilities_and_options() -> None:
    code, out, err = run_helper(str(STATE), "capabilities\n\n")
    assert_true(code == 0, f"capabilities exit {code} stderr={err!r}")
    assert_true(out == "option\npush\nfetch\nlist\nconnect\n\n", f"capabilities stdout={out!r}")
    assert_true("list\n" in out and "connect\n" in out, out)
    assert_true(err == "", err)

    code, out, err = run_helper(
        str(STATE),
        "capabilities\noption verbosity 1\noption nosuch 1\noption dry-run maybe\n\n",
    )
    assert_true(code == 0, err or out)
    assert_true(out.startswith("option\npush\nfetch\nlist\nconnect\n\n"), out)
    assert_true(out.endswith("ok\nunsupported\nerror BTX035_OPTION\n"), out)
    assert_true(err == "", err)


def test_empty_push_and_stock_refspec() -> None:
    code, out, err = run_helper(str(STATE), "capabilities\npush\n\nlist\n\n")
    assert_true(code == 0, err or out)
    assert_true("error BTX035_PUSH_EMPTY\n" in out, out)
    assert_no_ok(out)
    assert_true(journal_text() == "", "empty push wrote state")

    code, out, err = run_helper(
        str(STATE),
        "capabilities\npush refs/heads/main:refs/heads/main\n\nlist\n\n",
    )
    assert_true(code == 0, err or out)
    assert_true("error refs/heads/main BTX035_PUSH_FORMAT\n" in out, out)
    assert_true("ok refs/heads/main\n" not in out, out)
    assert_true(journal_text() == "", "format error wrote state")


def test_state_machine() -> None:
    url_local = "btx://local/" + str(STATE)
    code, out, err = run_helper(
        url_local,
        "\n".join(
            [
                "capabilities",
                "list for-push",
                "push refs/heads/ok:refs/heads/ok 0 aa -",
                "push refs/heads/bad:refs/heads/bad 4 bb -",
                "",
                "list",
                "",
            ]
        )
        + "\n",
    )
    assert_true(code == 0, err or out)
    assert_no_ok(out)
    assert_true("error refs/heads/ok BTX035_REJECTED\n" in out, out)
    assert_true("error refs/heads/bad BTX035_GAP\n" in out, out)
    assert_true(not any(line.startswith("? ") for line in out.splitlines()), out)
    assert_true(journal_text() == "", "failed batch wrote state")

    code, out, err = run_helper(
        str(STATE),
        "capabilities\npush refs/heads/ok:refs/heads/ok 0 aa -\n\nlist\n\n",
    )
    assert_true(code == 0, err or out)
    assert_true("ok refs/heads/ok\n" in out, out)
    assert_true("? refs/heads/ok sequence:0 id:aa\n" in out, out)
    assert_true("refs/heads/ok\t0\taa\n" in journal_text(), journal_text())

    before = journal_text()
    code, out, err = run_helper(
        url_local,
        "capabilities\npush refs/heads/ok:refs/heads/ok 0 aa -\n\n",
    )
    assert_true("error refs/heads/ok BTX035_DUPLICATE\n" in out, out)
    assert_no_ok(out)
    assert_true(journal_text() == before, "duplicate changed state")

    code, out, err = run_helper(
        str(STATE),
        "capabilities\npush refs/heads/ok:refs/heads/ok 0 cc -\n\n",
    )
    assert_true("error refs/heads/ok BTX035_EQUIVOCATION\n" in out, out)
    assert_true(journal_text() == before, "equivocation changed state")

    code, out, err = run_helper(
        str(STATE),
        "capabilities\npush refs/heads/new:refs/heads/new 0 ee aa\n\n",
    )
    assert_true("error refs/heads/new BTX035_GAP\n" in out, out)
    assert_true("refs/heads/new" not in journal_text(), journal_text())

    code, out, err = run_helper(
        str(STATE),
        "capabilities\npush refs/heads/ok:refs/heads/ok 1 bb aa\n\nlist for-push\n\n",
    )
    assert_true("ok refs/heads/ok\n" in out, out)
    assert_true("? refs/heads/ok sequence:1 id:bb\n" in out, out)

    before = journal_text()
    code, out, err = run_helper(
        str(STATE),
        "capabilities\npush refs/heads/ok:refs/heads/ok 0 aa -\n\n",
    )
    assert_true("error refs/heads/ok BTX035_ROLLBACK\n" in out, out)
    assert_true(journal_text() == before, "rollback changed state")

    code, out, err = run_helper(
        str(STATE),
        "capabilities\npush refs/heads/ok:refs/heads/ok 3 dd bb\n\n",
    )
    assert_true("error refs/heads/ok BTX035_GAP\n" in out, out)
    assert_true(journal_text() == before, "gap changed state")

    code, out, err = run_helper(
        str(STATE),
        "capabilities\npush refs/heads/ok:refs/heads/ok 2 dd aa\n\n",
    )
    assert_true("error refs/heads/ok BTX035_GAP\n" in out, out)
    assert_true(journal_text() == before, "previous mismatch changed state")

    code, out, err = run_helper(
        url_local,
        "\n".join(
            [
                "capabilities",
                "option dry-run true",
                "push refs/heads/ok:refs/heads/ok 2 dd bb",
                "",
                "list",
                "",
            ]
        )
        + "\n",
    )
    assert_true("ok refs/heads/ok\n" in out, out)
    assert_true("sequence:1 id:bb" in out, out)
    assert_true("sequence:2" not in journal_text(), journal_text())

    code, out, err = run_helper(
        str(STATE),
        "\n".join(
            [
                "capabilities",
                "option force true",
                "push refs/heads/side:refs/heads/side 0 ff -",
                "push refs/heads/ok:refs/heads/ok 2 dd bb",
                "",
                "list",
                "",
            ]
        )
        + "\n",
    )
    assert_true("ok refs/heads/side\n" in out, out)
    assert_true("ok refs/heads/ok\n" in out, out)
    text = journal_text()
    assert_true("refs/heads/ok\t2\tdd\n" in text, text)
    assert_true("refs/heads/side\t0\tff\n" in text, text)

    code, out, err = run_helper(
        str(STATE),
        "capabilities\npush :refs/heads/ok\n\nlist\n\n",
    )
    assert_true("error refs/heads/ok BTX035_PUSH_EMPTY\n" in out, out)
    assert_no_ok(out)
    assert_true("refs/heads/ok\t2\tdd\n" in journal_text(), "delete removed a ref")


RECORD_URI = "btx://p04w46h2at4w46h2at4w46h2at4w46h2at4w46h2at4w46h2at4w46h2at4w46h2at4w46h2at4w46kd5pzuz"


def test_connect_then_push_and_record_uri() -> None:
    connect_state = ROOT / "connect-state"
    connect_state.mkdir()
    embedded = "connect git-receive-pack refs/heads/ok:refs/heads/ok 0 aa -\n\n"
    code, out, err = run_helper(str(connect_state), embedded)
    assert_true(code != 0, "embedded ref update was accepted")
    assert_true("BTX035_PUSH_FORMAT" in out or "BTX035_PUSH_FORMAT" in err or "BTX035_CONNECT" in out or "BTX035_CONNECT" in err, out + err)
    assert_true("ok " not in out, out)
    assert_true(not (connect_state / "btx-ref-journal").exists(), "connect ticket wrote a journal")

    code, out, err = run_helper(str(connect_state), "connect git-receive-pack\n\n")
    assert_true(code == 0, err or out)
    assert_true(out == "fallback\n", out)
    assert_true(not (connect_state / "btx-ref-journal").exists(), "connect alone wrote a journal")

    code, out, err = run_helper(
        str(connect_state),
        "\n".join(
            [
                "connect git-receive-pack",
                "push refs/heads/ok:refs/heads/ok 0 aa -",
                "",
                "list",
                "",
            ]
        )
        + "\n",
    )
    assert_true(code == 0, err or out)
    assert_true(out.startswith("fallback\n"), out)
    assert_true("ok refs/heads/ok\n" in out, out)
    assert_true("? refs/heads/ok sequence:0 id:aa\n" in out, out)
    journal = (connect_state / "btx-ref-journal").read_text(encoding="utf-8")
    assert_true("refs/heads/ok\t0\taa\n" in journal, journal)

    record_root = ROOT / "record-root"
    record_root.mkdir()
    code, out, err = run_helper(
        "btx::" + RECORD_URI,
        "connect git-upload-pack\npush refs/heads/main:refs/heads/main 0 cc -\n\nlist\n\n",
        extra_env={"BTX_GIT_STATE": str(record_root)},
    )
    assert_true(code == 0, err or out)
    assert_true("ok refs/heads/main\n" in out, out)
    journals = list(record_root.glob("*/btx-ref-journal"))
    assert_true(len(journals) == 1, journals)
    assert_true(len(journals[0].parent.name) == 96, journals[0].parent.name)
    text = journals[0].read_text(encoding="utf-8")
    assert_true("refs/heads/main\t0\tcc\n" in text, text)

    code, out, err = run_helper(
        "btx::" + RECORD_URI.upper(),
        "push refs/heads/main:refs/heads/main 0 dd -\n\n",
        extra_env={"BTX_GIT_STATE": str(record_root)},
    )
    assert_true(code != 0, "uppercase record URI was accepted")
    assert_true("BTX035_URL" in err, err)
    code, out, err = run_helper(
        "btx::" + RECORD_URI + "?x=1",
        "push refs/heads/main:refs/heads/main 0 ee -\n\n",
        extra_env={"BTX_GIT_STATE": str(record_root)},
    )
    assert_true(code != 0, "query record URI was accepted")
    assert_true("BTX035_URL" in err, err)
    text = journals[0].read_text(encoding="utf-8")
    assert_true("\tee\n" not in text and "\tdd\n" not in text, text)


def test_bad_url() -> None:
    code, out, err = run_helper("btx://remote/nope", "capabilities\n\n")
    assert_true(code != 0, "bad url exited 0")
    assert_true(out == "", out)
    assert_true("BTX035_URL" in err, err)


def test_stock_git() -> None:
    env = os.environ.copy()
    env["PATH"] = str(HELPER.parent) + os.pathsep + env.get("PATH", "")
    env["TMPDIR"] = str(SCRATCH)
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    env["GIT_CONFIG_SYSTEM"] = "/dev/null"
    HOOKS.mkdir(parents=True, exist_ok=True)
    marker = ROOT / "hook-ran"
    subprocess.run(["git", "init", "-q", str(REPO)], cwd=str(ROOT), env=env, check=True)
    base = [
        "git",
        "-C",
        str(REPO),
        "-c",
        "user.email=test@example.com",
        "-c",
        "user.name=test",
        "-c",
        f"core.hooksPath={HOOKS}",
        "-c",
        "protocol.btx.allow=always",
    ]
    (REPO / "README").write_text("hello\n", encoding="utf-8")
    subprocess.run([*base, "add", "README"], cwd=str(ROOT), env=env, check=True)
    subprocess.run([*base, "commit", "-q", "-m", "init"], cwd=str(ROOT), env=env, check=True)
    git_state = ROOT / "git-state"
    url = "btx://local/" + str(git_state)
    listed = subprocess.run(
        [*base, "ls-remote", url],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert_true(listed.returncode == 0, listed.stderr.decode("utf-8", "replace"))
    assert_true(listed.stdout == b"", listed.stdout)
    pushed = subprocess.run(
        [*base, "push", url, "HEAD:refs/heads/main"],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert_true(pushed.returncode == 0, pushed.stderr.decode("utf-8", "replace") + pushed.stdout.decode("utf-8", "replace"))
    journal = git_state / "btx-ref-journal"
    assert_true(journal.exists(), "stock push did not write a ref")
    assert_true(not marker.exists(), "a hook ran")
    cloned = ROOT / "clone"
    cloning = subprocess.run(
        ["git", "-c", "protocol.btx.allow=always", "-c", f"core.hooksPath={HOOKS}", "clone", url, str(cloned)],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert_true(cloning.returncode == 0, cloning.stderr.decode("utf-8", "replace"))
    assert_true((cloned / "README").read_text(encoding="utf-8") == "hello\n", "clone missed README")
    (REPO / "README").write_text("hello\nagain\n", encoding="utf-8")
    subprocess.run([*base, "add", "README"], cwd=str(ROOT), env=env, check=True)
    subprocess.run([*base, "commit", "-q", "-m", "second"], cwd=str(ROOT), env=env, check=True)
    again = subprocess.run(
        [*base, "push", url, "HEAD:refs/heads/main"],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert_true(again.returncode == 0, again.stderr.decode("utf-8", "replace"))
    fetched = subprocess.run(
        ["git", "-C", str(cloned), "-c", "protocol.btx.allow=always", "pull", "--ff-only"],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert_true(fetched.returncode == 0, fetched.stderr.decode("utf-8", "replace"))
    assert_true("again" in (cloned / "README").read_text(encoding="utf-8"), "fetch missed the second commit")


def main() -> int:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir(parents=True)
    SCRATCH.mkdir()
    STATE.mkdir()
    code = 0
    try:
        test_helper_does_not_shell_or_spend()
        test_capabilities_and_options()
        test_empty_push_and_stock_refspec()
        test_state_machine()
        test_connect_then_push_and_record_uri()
        test_bad_url()
        test_stock_git()
        print("PASS")
    except Exception as exc:
        traceback.print_exc()
        print(f"FAIL {exc}", file=sys.stderr)
        code = 1
    finally:
        shutil.rmtree(ROOT, ignore_errors=True)
        if ROOT.exists():
            print(f"FAIL leftover {ROOT}", file=sys.stderr)
            code = 1
    return code


if __name__ == "__main__":
    raise SystemExit(main())
