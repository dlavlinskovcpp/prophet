"""Localtest-only fixed signer-B process; there is no runtime role selector."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.localtest_signer_worker_support import run_fixed_localtest_worker
from src.signer_b_main import create_signer_b_application


def main() -> None:
    run_fixed_localtest_worker(fixed_role="B", application_factory=create_signer_b_application)


if __name__ == "__main__":
    main()
