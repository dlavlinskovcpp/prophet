import time

from solders.pubkey import Pubkey

from src.signer_allowlist import EnvSignerAllowlist, FileSignerAllowlist


def _pk(seed: int) -> str:
    return str(Pubkey.from_bytes(bytes([seed]) * 32))


def test_env_signer_allowlist_parses_newline_and_comma_delimited_pubkeys():
    first = _pk(1)
    second = _pk(2)
    allowlist = EnvSignerAllowlist(f"{first},\n{second}", required=True)

    assert allowlist.contains(first) is True
    assert allowlist.contains(second) is True
    assert allowlist.health()["allowlist_size"] == 2


def test_file_signer_allowlist_refreshes_entries(tmp_path):
    first = _pk(1)
    second = _pk(2)
    path = tmp_path / "allowlist.txt"
    path.write_text(first + "\n", encoding="utf-8")

    allowlist = FileSignerAllowlist(str(path), refresh_s=0.0 + 0.001, required=True)

    assert allowlist.contains(first) is True
    assert allowlist.contains(second) is False

    time.sleep(0.01)
    path.write_text(second + "\n", encoding="utf-8")

    assert allowlist.contains(first) is False
    assert allowlist.contains(second) is True
    assert allowlist.health()["allowlist_last_error"] == ""
