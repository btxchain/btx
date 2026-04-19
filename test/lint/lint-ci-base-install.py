#!/usr/bin/env python3
# Copyright (c) 2026 The BTX Chain developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Regression test for ci/test/01_base_install.sh.

The base install script must work in minimal images that do not ship `git`.
Historically the script attempted `git config --global ...` before apt
dependencies were installed, which caused CI jobs to fail early.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path


def write_stub(path: Path, body: str) -> None:
    path.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"{body}\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def run_missing_git_regression(repo_root: Path) -> None:
    script = repo_root / "ci/test/01_base_install.sh"
    if not script.exists():
        raise RuntimeError(f"missing script: {script}")

    with tempfile.TemporaryDirectory(prefix="btx-lint-base-install-") as tmp:
        tmpdir = Path(tmp)
        fakebin = tmpdir / "bin"
        fakebin.mkdir()
        depends = tmpdir / "depends"
        home = tmpdir / "home"
        home.mkdir()
        apt_calls = tmpdir / "apt.calls"

        # Provide only commands needed for the code path under test.
        write_stub(fakebin / "nproc", "echo 2")
        write_stub(fakebin / "dpkg", "exit 0")
        write_stub(fakebin / "apt-get", f"printf '%s\\n' \"$*\" >> '{apt_calls}'")

        env = os.environ.copy()
        env.update(
            {
                "HOME": str(home),
                "PATH": f"{fakebin}:/bin",
                "DPKG_ADD_ARCH": "",
                "APT_LLVM_V": "",
                "CI_IMAGE_NAME_TAG": "mirror.gcr.io/ubuntu:noble",
                "CI_OS_NAME": "linux",
                "APPEND_APT_SOURCES_LIST": "",
                "CI_RETRY_EXE": "",
                "PACKAGES": "pkg-a",
                "CI_BASE_PACKAGES": "pkg-b",
                "PIP_PACKAGES": "",
                "USE_INSTRUMENTED_LIBCPP": "",
                "RUN_TIDY": "false",
                "DEPENDS_DIR": str(depends),
                "XCODE_VERSION": "",
                "XCODE_BUILD_ID": "",
                "SDK_URL": "",
                "LC_ALL": "C",
            }
        )

        # Intentionally omit git from PATH.
        completed = subprocess.run(
            ["/bin/bash", str(script)],
            env=env,
            cwd=repo_root,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"base install failed without git (exit {completed.returncode}):\n"
                f"{completed.stdout}"
            )
        if not apt_calls.exists():
            raise RuntimeError(
                "base install did not reach apt-get path in missing-git regression test"
            )


def main() -> int:
    repo_root = Path(
        subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], text=True
        ).strip()
    )
    try:
        run_missing_git_regression(repo_root)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"ERROR: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
