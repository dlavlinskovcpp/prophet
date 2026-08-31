#!/usr/bin/env python3
"""Acceptance checks for the production-shaped Prometheus contract."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROM = ROOT / "deploy/operated/public-devnet/prometheus.yml"
ALERTS = ROOT / "deploy/operated/public-devnet/alerts.yml"


def _fires(expr: str, values: dict[tuple[str, str], float]) -> bool:
    if "up{job=\"" in expr:
        job = re.search(r'job="([^"]+)"', expr).group(1)
        return values.get(("up", job), 1) == 0
    metric = re.search(r"increase\(([_a-zA-Z:][_a-zA-Z0-9:]*)", expr)
    if metric:
        return values.get((metric.group(1), ""), 0) > 0
    return False


def main() -> int:
    prometheus_text = PROM.read_text(encoding="utf-8")
    alerts_text = ALERTS.read_text(encoding="utf-8")
    jobs = set(re.findall(r"^\s*- job_name:\s*([^\s#]+)", prometheus_text, re.MULTILINE))
    required_jobs = {"prophet-verifier-a", "prophet-verifier-b", "prophet-coordinator", "prophet-resolver-registry", "prophet-matching-keeper", "vault"}
    if jobs != required_jobs:
        raise SystemExit(f"operated monitoring scrape jobs mismatch: {sorted(jobs)}")
    vault_start = prometheus_text.index("  - job_name: vault")
    vault_block = prometheus_text[vault_start:]
    if "    scheme: https" not in vault_block or "bearer_token_file:" not in vault_block or "ca_file:" not in vault_block or "insecure_skip_verify: false" not in vault_block:
        raise SystemExit("Vault monitoring must use authenticated HTTPS with CA validation")
    keeper_start = prometheus_text.index("  - job_name: prophet-matching-keeper")
    keeper_end = prometheus_text.find("  - job_name:", keeper_start + 1)
    keeper_block = prometheus_text[keeper_start:] if keeper_end < 0 else prometheus_text[keeper_start:keeper_end]
    if "bearer_token_file:" not in keeper_block:
        raise SystemExit("keeper monitoring must use an authenticated private scrape")
    required_alerts = {"ProphetSignerEquivocation", "ProphetKeeperUnavailable", "ProphetVaultUnavailable", "ProphetVerifierDisagreement"}
    if not required_alerts.issubset(set(re.findall(r"^\s*- alert:\s*(\S+)", alerts_text, re.MULTILINE))):
        raise SystemExit("operated monitoring acceptance alerts are incomplete")
    def expression(alert: str) -> str:
        match = re.search(rf"- alert: {re.escape(alert)}\s+expr: ([^\n]+)", alerts_text)
        if not match:
            raise SystemExit(f"missing expression for {alert}")
        return match.group(1)
    by_name = {name: expression(name) for name in required_alerts}
    equivocation = by_name["ProphetSignerEquivocation"]
    if 'prophet_resolver_v2_equivocation_total{kind="signer"}' not in equivocation:
        raise SystemExit("signer equivocation alert does not match emitted kind label")
    fixtures = {
        "signer": {("prophet_resolver_v2_equivocation_total", ""): 1},
        "keeper": {("up", "prophet-matching-keeper"): 0},
        "vault": {("up", "vault"): 0},
        "verifier": {("prophet_resolver_v2_verifier_disagreement_total", ""): 1},
    }
    for label, fixture in fixtures.items():
        name = {"signer": "ProphetSignerEquivocation", "keeper": "ProphetKeeperUnavailable", "vault": "ProphetVaultUnavailable", "verifier": "ProphetVerifierDisagreement"}[label]
        if not _fires(by_name[name], fixture):
            raise SystemExit(f"{name} does not fire against its acceptance fixture")
    print("OPERATED MONITORING: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
