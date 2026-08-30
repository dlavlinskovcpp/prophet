#!/usr/bin/env python3
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROMETHEUS_CONFIG = ROOT / "ops" / "monitoring" / "prometheus.yml"
ALERTS_CONFIG = ROOT / "ops" / "monitoring" / "alerts.yml"
METRIC_SOURCES = [
    ROOT / "apps" / "oracle-attester" / "src" / "resolver_registry_main.py",
    ROOT / "apps" / "matching-keeper" / "src" / "service.py",
]
PROMQL_KEYWORDS = {
    "and",
    "or",
    "unless",
    "by",
    "without",
    "on",
    "ignoring",
    "group_left",
    "group_right",
    "offset",
    "bool",
}
PROMQL_FUNCTIONS = {
    "absent",
    "avg_over_time",
    "clamp_max",
    "clamp_min",
    "count_over_time",
    "delta",
    "deriv",
    "increase",
    "irate",
    "max_over_time",
    "min_over_time",
    "predict_linear",
    "quantile_over_time",
    "rate",
    "resets",
    "sum_over_time",
}
BUILTIN_METRICS = {"up"}


def _parse_simple_mapping_list(path: Path):
    groups = []
    current_group = None
    current_rule = None
    current_block = None

    for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        if indent == 0 and line == "groups:":
            continue
        if indent == 2 and line.startswith("- name:"):
            current_group = {"name": line.split(":", 1)[1].strip(), "rules": [], "lineno": lineno}
            groups.append(current_group)
            current_rule = None
            current_block = None
            continue
        if indent == 4 and line == "rules:":
            continue
        if indent == 6 and line.startswith("- alert:"):
            if current_group is None:
                raise ValueError(f"{path}: rule declared before a group on line {lineno}")
            current_rule = {"alert": line.split(":", 1)[1].strip(), "lineno": lineno}
            current_group["rules"].append(current_rule)
            current_block = None
            continue
        if indent == 8 and ":" in line:
            if current_rule is None:
                raise ValueError(f"{path}: mapping entry without a rule on line {lineno}")
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key in {"labels", "annotations"}:
                current_rule[key] = {}
                current_block = key
                continue
            current_rule[key] = value
            current_block = None
            continue
        if indent == 10 and ":" in line:
            if current_rule is None or current_block is None:
                raise ValueError(f"{path}: nested mapping without a block on line {lineno}")
            key, value = line.split(":", 1)
            current_rule[current_block][key.strip()] = value.strip()
            continue
        raise ValueError(f"{path}: unsupported YAML shape on line {lineno}: {raw_line}")

    return groups


def _parse_prometheus_jobs(path: Path):
    jobs = []
    rule_files = []
    section = ""
    for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        if indent == 0 and line.endswith(":"):
            section = line[:-1]
            continue
        if section == "rule_files" and indent == 2 and line.startswith("- "):
            rule_files.append(line[2:].strip())
            continue
        if section == "scrape_configs" and indent == 2 and line.startswith("- job_name:"):
            jobs.append(line.split(":", 1)[1].strip())
            continue
    if not jobs:
        raise ValueError(f"{path}: no scrape jobs found")
    return jobs, rule_files


def _exported_metrics():
    metrics = set()
    inc_pattern = re.compile(r'metrics\.inc\("([A-Za-z_:][A-Za-z0-9_:]*)"')
    help_pattern = re.compile(r"# HELP ([A-Za-z_:][A-Za-z0-9_:]*) ")
    for path in METRIC_SOURCES:
        text = path.read_text(encoding="utf-8")
        metrics.update(inc_pattern.findall(text))
        metrics.update(help_pattern.findall(text))
    return metrics


def _extract_metric_names(expr: str):
    cleaned = re.sub(r'"[^"]*"', '""', expr)
    cleaned = re.sub(r"\{[^{}]*\}", "{}", cleaned)
    cleaned = re.sub(r"\[[^\]]+\]", "[]", cleaned)
    tokens = []
    for match in re.finditer(r"\b([A-Za-z_:][A-Za-z0-9_:]*)\b", cleaned):
        token = match.group(1)
        next_char = cleaned[match.end() : match.end() + 1]
        if token in PROMQL_KEYWORDS:
            continue
        if next_char == "(" and token in PROMQL_FUNCTIONS:
            continue
        tokens.append(token)
    return sorted(dict.fromkeys(tokens))


def main() -> int:
    jobs, rule_files = _parse_prometheus_jobs(PROMETHEUS_CONFIG)
    if "/etc/prometheus/alerts.yml" not in rule_files:
        raise SystemExit(f"{PROMETHEUS_CONFIG}: missing /etc/prometheus/alerts.yml in rule_files")

    exported_metrics = _exported_metrics() | BUILTIN_METRICS
    groups = _parse_simple_mapping_list(ALERTS_CONFIG)
    if not groups:
        raise SystemExit(f"{ALERTS_CONFIG}: no alert groups found")

    alert_names = set()
    referenced_jobs = set()

    for group in groups:
        if not group["name"]:
            raise SystemExit(f"{ALERTS_CONFIG}: group on line {group['lineno']} is missing a name")
        if not group["rules"]:
            raise SystemExit(f"{ALERTS_CONFIG}: group {group['name']} has no rules")

        for rule in group["rules"]:
            for field in ("alert", "expr", "for", "labels", "annotations"):
                if field not in rule or not rule[field]:
                    raise SystemExit(
                        f"{ALERTS_CONFIG}: alert on line {rule['lineno']} is missing required field {field}"
                    )
            if rule["alert"] in alert_names:
                raise SystemExit(f"{ALERTS_CONFIG}: duplicate alert name {rule['alert']}")
            alert_names.add(rule["alert"])

            for field in ("severity", "service"):
                if not rule["labels"].get(field):
                    raise SystemExit(
                        f"{ALERTS_CONFIG}: alert {rule['alert']} is missing labels.{field}"
                    )
            for field in ("summary", "description"):
                if not rule["annotations"].get(field):
                    raise SystemExit(
                        f"{ALERTS_CONFIG}: alert {rule['alert']} is missing annotations.{field}"
                    )

            for job in re.findall(r'job="([^"]+)"', rule["expr"]):
                if job not in jobs:
                    raise SystemExit(
                        f"{ALERTS_CONFIG}: alert {rule['alert']} references unknown scrape job {job}"
                    )
                referenced_jobs.add(job)

            unknown_metrics = sorted(
                metric
                for metric in _extract_metric_names(rule["expr"])
                if metric not in exported_metrics
            )
            if unknown_metrics:
                raise SystemExit(
                    f"{ALERTS_CONFIG}: alert {rule['alert']} references unknown metrics {unknown_metrics}"
                )

    missing_job_alerts = sorted(set(jobs) - referenced_jobs)
    if missing_job_alerts:
        raise SystemExit(
            f"{ALERTS_CONFIG}: scrape jobs missing explicit job-based alert coverage: {missing_job_alerts}"
        )

    print("alert rule validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
