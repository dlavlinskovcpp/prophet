"""Localtest-only fixed signer-A process; there is no runtime role selector."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.localtest_signer_worker_support import run_fixed_localtest_worker
from src.signer_a_main import create_signer_a_application


def main() -> None:
    run_fixed_localtest_worker(fixed_role="A", application_factory=create_signer_a_application)


if __name__ == "__main__":
    main()
