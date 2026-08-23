"""Built-image regressions for the fixed Prophet runtime identity."""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOCKER = shutil.which("docker")


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode:
        raise AssertionError(
            f"container command failed ({result.returncode}): {' '.join(args)}\n{result.stdout}"
        )
    return result


@unittest.skipUnless(DOCKER, "docker is required for production-image runtime tests")
class ProductionImageNonRootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.oracle_image = "prophet-p0c1-oracle-test"
        cls.keeper_image = "prophet-p0c1-keeper-test"
        _run(DOCKER, "build", "-f", "apps/oracle-attester/Dockerfile", "-t", cls.oracle_image, ".")
        _run(DOCKER, "build", "-f", "apps/matching-keeper/Dockerfile", "-t", cls.keeper_image, ".")

    def _shell(self, image: str, script: str) -> None:
        _run(DOCKER, "run", "--rm", "--entrypoint", "sh", image, "-ec", script)

    def test_oracle_runtime_identity_and_state_mountpoints(self) -> None:
        self._shell(
            self.oracle_image,
            """
            test "$(id -u)" = 10001
            test "$(id -g)" = 10001
            test "$HOME" = /nonexistent
            test "$TMPDIR" = /tmp
            test ! -w /app/apps/oracle-attester/src
            test ! -w /app/apps/oracle-attester/.venv
            test -w /app/resolver_store
            test -w /app/proof_store
            test -w /app/audit
            test -w /var/lib/prophet
            test -x /app/runtime
            test ! -w /app/runtime
            touch /tmp/nonroot-runtime-smoke
            """,
        )

    def test_keeper_runtime_identity_state_and_healthcheck_interpreter(self) -> None:
        self._shell(
            self.keeper_image,
            """
            test "$(id -u)" = 10001
            test "$(id -g)" = 10001
            test "$HOME" = /nonexistent
            test "$TMPDIR" = /tmp
            test ! -w /app/apps/matching-keeper/src
            test ! -w /app/apps/matching-keeper/.venv
            test -w /app/apps/matching-keeper/state
            touch /app/apps/matching-keeper/state/nonroot-runtime-smoke
            touch /tmp/nonroot-runtime-smoke
            python -c "import urllib.request"
            """,
        )
