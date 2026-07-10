"""Eight-phase recon pipeline built on Essam's phase runner."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlparse

from Essam.agent_loop import run_phase
from recon_tools import PHASE_TOOLS


JsonDict = Dict[str, Any]


@dataclass
class ReconResult:
    """Final normalized recon report."""

    target: str
    status: str
    started_at_utc: str
    finished_at_utc: str
    subdomains: List[str] = field(default_factory=list)
    candidates: List[str] = field(default_factory=list)
    live_hosts: List[JsonDict] = field(default_factory=list)
    open_ports: List[JsonDict] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    archived_urls: List[str] = field(default_factory=list)
    found_paths: List[JsonDict] = field(default_factory=list)
    findings: List[JsonDict] = field(default_factory=list)
    phases: JsonDict = field(default_factory=dict)
    errors: List[JsonDict] = field(default_factory=list)


def run_full_recon(
    target: str,
    *,
    output_dir: Path,
    coverage: Any | None = None,
) -> ReconResult:
    """Run all eight recon phases and return a final normalized report."""

    started_at = _utc_now()
    phases: JsonDict = {}
    errors: List[JsonDict] = []

    phase1 = run_phase("subdomain_enum", target, PHASE_TOOLS["subdomain_enum"])
    phases["subdomain_enum"] = phase1
    _collect_errors("subdomain_enum", phase1, errors)

    subdomains = list(phase1.get("subdomains", []))
    _mark_phase(coverage, target, "subdomain_enum", str(phase1.get("tool", "")))

    phase2 = run_phase(
        "permutation",
        {"target": target, "subdomains": subdomains},
        PHASE_TOOLS["permutation"],
    )
    phases["permutation"] = phase2
    _collect_errors("permutation", phase2, errors)

    candidates = list(phase2.get("candidates", []))
    all_hosts = _dedupe([*subdomains, *candidates, _domain(target)])
    _mark_phase(coverage, target, "permutation", str(phase2.get("tool", "")))

    phase3 = run_phase(
        "dns_resolution",
        {"target": target, "hosts": all_hosts},
        PHASE_TOOLS["dns_resolution"],
    )
    phases["dns_resolution"] = phase3
    _collect_errors("dns_resolution", phase3, errors)

    live_hosts = list(phase3.get("live_hosts", []))
    live_urls = _live_host_urls(live_hosts)
    resolved_hosts = _hostnames_from_live_hosts(live_hosts) or all_hosts[:20]
    _mark_phase(coverage, target, "dns_resolution", str(phase3.get("tool", "")))

    phase4 = run_phase(
        "port_scan",
        {"target": target, "hosts": resolved_hosts},
        PHASE_TOOLS["port_scan"],
    )
    phases["port_scan"] = phase4
    _collect_errors("port_scan", phase4, errors)
    _mark_phase(coverage, target, "port_scan", str(phase4.get("tool", "")))

    phase5 = run_phase(
        "crawl",
        {"target": target, "live_hosts": live_hosts, "urls": live_urls},
        PHASE_TOOLS["crawl"],
    )
    phases["crawl"] = phase5
    _collect_errors("crawl", phase5, errors)
    _mark_phase(coverage, target, "crawl", str(phase5.get("tool", "")))

    crawled_urls = list(phase5.get("urls", []))

    phase6 = run_phase("historical_urls", target, PHASE_TOOLS["historical_urls"])
    phases["historical_urls"] = phase6
    _collect_errors("historical_urls", phase6, errors)
    _mark_phase(coverage, target, "historical_urls", str(phase6.get("tool", "")))

    archived_urls = list(phase6.get("archived_urls", []))
    fuzz_base_urls = _dedupe([*live_urls, *crawled_urls, *_roots_from_urls(archived_urls)])

    phase7 = run_phase(
        "fuzzing",
        {"target": target, "base_urls": fuzz_base_urls, "urls": fuzz_base_urls},
        PHASE_TOOLS["fuzzing"],
    )
    phases["fuzzing"] = phase7
    _collect_errors("fuzzing", phase7, errors)
    _mark_phase(coverage, target, "fuzzing", str(phase7.get("tool", "")))

    found_paths = list(phase7.get("found_paths", []))
    fuzz_urls = [str(item.get("url", "")) for item in found_paths if item.get("url")]
    scan_urls = _dedupe([*live_urls, *crawled_urls, *archived_urls, *fuzz_urls])

    phase8 = run_phase(
        "vulnerability_scan",
        {"target": target, "urls": scan_urls, "live_hosts": live_hosts},
        PHASE_TOOLS["vulnerability_scan"],
    )
    phases["vulnerability_scan"] = phase8
    _collect_errors("vulnerability_scan", phase8, errors)
    _mark_phase(coverage, target, "vulnerability_scan", str(phase8.get("tool", "")))

    result = ReconResult(
        target=target,
        status="completed_with_errors" if errors else "completed",
        started_at_utc=started_at,
        finished_at_utc=_utc_now(),
        subdomains=subdomains,
        candidates=candidates,
        live_hosts=live_hosts,
        open_ports=list(phase4.get("open_ports", [])),
        urls=crawled_urls,
        archived_urls=archived_urls,
        found_paths=found_paths,
        findings=list(phase8.get("findings", [])),
        phases=phases,
        errors=errors,
    )
    return result


def save_recon_result(result: ReconResult, output_dir: Path) -> Path:
    """Save target-scoped recon output files.

    The returned path is the target folder. Each run writes separated category
    files plus ``full_report.json`` and a timestamped copy for history.
    """

    output_dir.mkdir(parents=True, exist_ok=True)
    safe_target = re.sub(r"[^a-zA-Z0-9_.-]+", "_", result.target).strip("_") or "target"
    target_dir = output_dir / safe_target
    target_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_payload = result.__dict__
    report_json = json.dumps(report_payload, indent=2, default=str)

    (target_dir / "full_report.json").write_text(report_json, encoding="utf-8")
    (target_dir / f"full_report_{timestamp}.json").write_text(report_json, encoding="utf-8")
    (output_dir / "recon_latest.json").write_text(report_json, encoding="utf-8")

    _write_json(target_dir / "subdomains.json", result.subdomains)
    _write_lines(target_dir / "subdomains.txt", result.subdomains)

    _write_json(target_dir / "candidates.json", result.candidates)
    _write_lines(target_dir / "candidates.txt", result.candidates)

    _write_json(target_dir / "live_hosts.json", result.live_hosts)
    _write_lines(target_dir / "live_hosts.txt", [str(item.get("host", "")) for item in result.live_hosts])

    _write_json(target_dir / "open_ports.json", result.open_ports)
    _write_lines(
        target_dir / "open_ports.txt",
        [f"{item.get('port', '')}/{item.get('service', '')}".rstrip("/") for item in result.open_ports],
    )

    _write_json(target_dir / "endpoints.json", result.urls)
    _write_lines(target_dir / "endpoints.txt", result.urls)

    _write_json(target_dir / "archived_urls.json", result.archived_urls)
    _write_lines(target_dir / "archived_urls.txt", result.archived_urls)

    _write_json(target_dir / "found_paths.json", result.found_paths)
    _write_lines(
        target_dir / "found_paths.txt",
        [
            f"{item.get('status', '')} {item.get('url') or item.get('path', '')}".strip()
            for item in result.found_paths
        ],
    )

    _write_json(target_dir / "findings.json", result.findings)
    _write_lines(
        target_dir / "findings.txt",
        [
            f"{item.get('severity', '')} | {item.get('name', '')} | {item.get('detail', '')}".strip()
            for item in result.findings
        ],
    )

    _write_json(target_dir / "phase_results.json", result.phases)
    _write_json(target_dir / "errors.json", result.errors)
    _write_lines(target_dir / "errors.txt", [json.dumps(error, default=str) for error in result.errors])

    summary = {
        "target": result.target,
        "status": result.status,
        "started_at_utc": result.started_at_utc,
        "finished_at_utc": result.finished_at_utc,
        "counts": {
            "subdomains": len(result.subdomains),
            "candidates": len(result.candidates),
            "live_hosts": len(result.live_hosts),
            "open_ports": len(result.open_ports),
            "endpoints": len(result.urls),
            "archived_urls": len(result.archived_urls),
            "found_paths": len(result.found_paths),
            "findings": len(result.findings),
            "errors": len(result.errors),
        },
    }
    _write_json(target_dir / "summary.json", summary)
    _write_lines(
        target_dir / "summary.txt",
        [
            f"target: {summary['target']}",
            f"status: {summary['status']}",
            f"started_at_utc: {summary['started_at_utc']}",
            f"finished_at_utc: {summary['finished_at_utc']}",
            *[f"{key}: {value}" for key, value in summary["counts"].items()],
        ],
    )

    return target_dir


def _mark_phase(coverage: Any | None, target: str, phase: str, tool_used: str) -> None:
    if coverage is None:
        return
    marker = getattr(coverage, "mark_vulnerability_tested", None)
    if callable(marker):
        marker(
            endpoint=target,
            parameter=phase,
            vulnerability_class="recon-phase",
            tool_used=tool_used or "unknown",
        )


def _collect_errors(phase_name: str, phase_result: Mapping[str, Any], errors: List[JsonDict]) -> None:
    if phase_result.get("error"):
        errors.append({"phase": phase_name, "error": phase_result.get("error"), "errors": phase_result.get("errors", [])})
    for item in phase_result.get("errors", []) or []:
        errors.append({"phase": phase_name, **dict(item)})


def _live_host_urls(live_hosts: List[JsonDict]) -> List[str]:
    urls: List[str] = []
    for item in live_hosts:
        host = str(item.get("host", "")).strip()
        if host.startswith("http"):
            urls.append(host)
    return _dedupe(urls)


def _hostnames_from_live_hosts(live_hosts: List[JsonDict]) -> List[str]:
    values: List[str] = []
    for item in live_hosts:
        host = str(item.get("host", "")).strip()
        if not host:
            continue
        parsed = urlparse(host if "://" in host else f"//{host}")
        values.append(parsed.hostname or host)
    return _dedupe(values)


def _roots_from_urls(urls: List[str]) -> List[str]:
    roots: List[str] = []
    for url in urls[:500]:
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            roots.append(f"{parsed.scheme}://{parsed.netloc}")
    return _dedupe(roots)


def _domain(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return (parsed.hostname or value).strip().lower().rstrip(".")


def _dedupe(values: List[str]) -> List[str]:
    output: List[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value).strip()
        if item and item not in seen:
            seen.add(item)
            output.append(item)
    return output


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _write_lines(path: Path, values: List[str]) -> None:
    path.write_text("\n".join(value for value in values if value) + ("\n" if values else ""), encoding="utf-8")
