"""Normalized recon tool wrappers for the AI Recon Agent.

Every wrapper returns one of the phase schemas expected by ``Essam.run_phase``.
Wrappers do not raise for missing binaries; they return an empty normalized
result with an error so fallback/merge mode can continue cleanly.
"""

from __future__ import annotations

from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
from typing import Any, Dict, Iterable, List, Mapping, Sequence
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET

import requests
from urllib3.exceptions import InsecureRequestWarning


requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


JsonDict = Dict[str, Any]

DEFAULT_TIMEOUT = 180
COMMON_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000, 22, 25, 53]
COMMON_PATHS = [
    "admin",
    "api",
    "backup",
    "config",
    "dashboard",
    "debug",
    "dev",
    "login",
    "robots.txt",
    "sitemap.xml",
    "uploads",
]
WORDLIST_PATH = Path(__file__).resolve().parent / "config" / "small_wordlist.txt"


class LinkParser(HTMLParser):
    """Extract links from a small HTML page without external dependencies."""

    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []

    def handle_starttag(self, tag: str, attrs: Sequence[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name.lower() in {"href", "src", "action"} and value:
                self.links.append(value)


def run_subfinder(target: str) -> JsonDict:
    """Run ProjectDiscovery subfinder."""

    domain = _domain(target)
    result = _run_tool(["subfinder", "-d", domain, "-silent"], timeout=DEFAULT_TIMEOUT)
    return _subdomain_result("subfinder", _filter_domains(_lines(result.stdout), domain), result)


def run_amass(target: str) -> JsonDict:
    """Run OWASP Amass passive enumeration."""

    domain = _domain(target)
    result = _run_tool(["amass", "enum", "-passive", "-d", domain, "-nocolor"], timeout=600)
    return _subdomain_result("amass", _filter_domains(_lines(result.stdout), domain), result)


def run_assetfinder(target: str) -> JsonDict:
    """Run assetfinder subdomain enumeration."""

    domain = _domain(target)
    result = _run_tool(["assetfinder", "--subs-only", domain], timeout=DEFAULT_TIMEOUT)
    return _subdomain_result("assetfinder", _filter_domains(_lines(result.stdout), domain), result)


def run_crtsh(target: str) -> JsonDict:
    """Query crt.sh certificate transparency data."""

    domain = _domain(target)
    try:
        response = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=30,
        )
        response.raise_for_status()
        names: List[str] = []
        for item in response.json():
            for value in str(item.get("name_value", "")).splitlines():
                names.append(value.lstrip("*.").lower())
        return {"tool": "crtsh", "subdomains": _dedupe(_filter_domains(names, domain))}
    except Exception as exc:  # noqa: BLE001 - network/API issues should not stop merge mode.
        return {"tool": "crtsh", "subdomains": [], "error": str(exc)}


def run_alterx(target: str, subdomains: Sequence[str] | None = None) -> JsonDict:
    """Run ProjectDiscovery alterx against known subdomains."""

    domain = _domain(target)
    inputs = _dedupe([*list(subdomains or []), domain])
    result = _run_tool(["alterx", "-silent"], input_text="\n".join(inputs), timeout=DEFAULT_TIMEOUT)
    return _candidate_result("alterx", _filter_domains(_lines(result.stdout), domain), result)


def run_dnsgen(target: str, subdomains: Sequence[str] | None = None) -> JsonDict:
    """Run dnsgen if installed."""

    domain = _domain(target)
    inputs = _dedupe([*list(subdomains or []), domain])
    result = _run_tool(["dnsgen", "-"], input_text="\n".join(inputs), timeout=DEFAULT_TIMEOUT)
    return _candidate_result("dnsgen", _filter_domains(_lines(result.stdout), domain), result)


def run_gotator(target: str, subdomains: Sequence[str] | None = None) -> JsonDict:
    """Run gotator if installed."""

    domain = _domain(target)
    inputs = _dedupe([*list(subdomains or []), domain])
    result = _run_tool(["gotator", "-sub", "-silent"], input_text="\n".join(inputs), timeout=DEFAULT_TIMEOUT)
    return _candidate_result("gotator", _filter_domains(_lines(result.stdout), domain), result)


def run_builtin_permutations(target: str, subdomains: Sequence[str] | None = None) -> JsonDict:
    """Generate a small conservative permutation set without external tools."""

    domain = _domain(target)
    seeds = _dedupe([*list(subdomains or []), domain])
    words = ["dev", "test", "stage", "staging", "api", "admin", "portal", "beta"]
    candidates: List[str] = []
    for host in seeds[:200]:
        label = host.removesuffix(f".{domain}").split(".")[0]
        for word in words:
            candidates.extend([f"{word}-{label}.{domain}", f"{label}-{word}.{domain}", f"{word}.{domain}"])
    return {"tool": "builtin_permutations", "candidates": _dedupe(_filter_domains(candidates, domain))}


def run_httpx(target: str, hosts: Sequence[str] | None = None) -> JsonDict:
    """Run ProjectDiscovery httpx live-host probing."""

    domain = _domain(target)
    inputs = _dedupe([_domain(host) for host in (hosts or [domain])])
    result = _run_tool(
        ["httpx", "-silent", "-json", "-status-code", "-title", "-follow-host-redirects"],
        input_text="\n".join(inputs),
        timeout=600,
    )
    records: List[JsonDict] = []
    for item in _json_lines(result.stdout):
        host = str(item.get("url") or item.get("input") or "")
        if host:
            records.append(
                {
                    "host": host,
                    "status": str(item.get("status_code", "")),
                    "title": str(item.get("title", "")),
                }
            )
    return _live_host_result("httpx", records, result)


def run_dnsx(target: str, hosts: Sequence[str] | None = None) -> JsonDict:
    """Run ProjectDiscovery dnsx as a resolved-host fallback."""

    domain = _domain(target)
    inputs = _dedupe([_domain(host) for host in (hosts or [domain])])
    result = _run_tool(["dnsx", "-silent"], input_text="\n".join(inputs), timeout=DEFAULT_TIMEOUT)
    records = [{"host": host, "status": "resolved", "title": ""} for host in _filter_domains(_lines(result.stdout), domain)]
    return _live_host_result("dnsx", records, result)


def run_httprobe(target: str, hosts: Sequence[str] | None = None) -> JsonDict:
    """Run httprobe if installed."""

    domain = _domain(target)
    inputs = _dedupe([_domain(host) for host in (hosts or [domain])])
    result = _run_tool(["httprobe"], input_text="\n".join(inputs), timeout=DEFAULT_TIMEOUT)
    records = [{"host": url, "status": "live", "title": ""} for url in _lines(result.stdout) if url.startswith("http")]
    return _live_host_result("httprobe", records, result)


def run_builtin_dns_resolution(target: str, hosts: Sequence[str] | None = None) -> JsonDict:
    """Resolve hostnames with Python sockets."""

    domain = _domain(target)
    records: List[JsonDict] = []
    for host in _dedupe([_domain(host) for host in (hosts or [domain])])[:500]:
        try:
            socket.gethostbyname(host)
            records.append({"host": host, "status": "resolved", "title": ""})
        except OSError:
            continue
    return {"tool": "builtin_dns_resolution", "live_hosts": records}


def run_naabu(target: str, hosts: Sequence[str] | None = None) -> JsonDict:
    """Run ProjectDiscovery naabu."""

    host = _first_host(target, hosts)
    result = _run_tool(["naabu", "-host", host, "-silent", "-json", "-top-ports", "100"], timeout=600)
    ports: List[JsonDict] = []
    for item in _json_lines(result.stdout):
        port = item.get("port")
        if port:
            ports.append({"port": int(port), "service": str(item.get("protocol") or _service_name(int(port)))})
    return _port_result("naabu", ports, result)


def run_nmap_ports(target: str, hosts: Sequence[str] | None = None) -> JsonDict:
    """Run nmap top-port TCP scan."""

    host = _first_host(target, hosts)
    result = _run_tool(["nmap", "-Pn", "-T3", "--top-ports", "100", "-oX", "-", host], timeout=900)
    ports: List[JsonDict] = []
    if result.ok:
        try:
            root = ET.fromstring(result.stdout)
            for port_node in root.findall(".//port"):
                state = port_node.find("state")
                if state is not None and state.attrib.get("state") != "open":
                    continue
                port_id = int(port_node.attrib["portid"])
                service = port_node.find("service")
                ports.append({"port": port_id, "service": service.attrib.get("name", "") if service is not None else ""})
        except ET.ParseError:
            pass
    return _port_result("nmap", ports, result)


def run_builtin_tcp_probe(target: str, hosts: Sequence[str] | None = None) -> JsonDict:
    """Probe a conservative set of common TCP ports."""

    host = _first_host(target, hosts)
    ports: List[JsonDict] = []
    for port in COMMON_PORTS:
        try:
            with socket.create_connection((host, port), timeout=2):
                ports.append({"port": port, "service": _service_name(port)})
        except OSError:
            continue
    return {"tool": "builtin_tcp_probe", "open_ports": ports}


def run_masscan(target: str, hosts: Sequence[str] | None = None) -> JsonDict:
    """Run masscan on a very small default port set. Requires raw packet privileges."""

    host = _first_host(target, hosts)
    result = _run_tool(["masscan", host, "-p80,443,8080,8443", "--rate", "500", "--wait", "2"], timeout=300)
    ports = [{"port": int(port), "service": _service_name(int(port))} for port in re.findall(r"port\s+(\d+)/tcp", result.stdout)]
    return _port_result("masscan", ports, result)


def run_katana(target: str, urls: Sequence[str] | None = None, live_hosts: Sequence[Mapping[str, Any]] | None = None) -> JsonDict:
    """Run ProjectDiscovery katana."""

    start_urls = _start_urls(target, urls, live_hosts)
    found: List[str] = []
    errors: List[str] = []
    for url in start_urls[:20]:
        result = _run_tool(["katana", "-u", url, "-silent", "-json", "-depth", "2"], timeout=600)
        if not result.ok:
            errors.append(result.error or result.stderr)
            continue
        for item in _json_lines(result.stdout):
            found.append(str(item.get("request", {}).get("endpoint") or item.get("url") or item.get("endpoint") or ""))
    response = {"tool": "katana", "urls": _dedupe([url for url in found if url.startswith("http")])}
    if errors and not response["urls"]:
        response["error"] = "; ".join(errors[:3])
    return response


def run_hakrawler(target: str, urls: Sequence[str] | None = None, live_hosts: Sequence[Mapping[str, Any]] | None = None) -> JsonDict:
    """Run hakrawler if installed."""

    start_urls = _start_urls(target, urls, live_hosts)
    result = _run_tool(["hakrawler", "-plain"], input_text="\n".join(start_urls), timeout=600)
    return _url_result("hakrawler", [url for url in _lines(result.stdout) if url.startswith("http")], result)


def run_gospider(target: str, urls: Sequence[str] | None = None, live_hosts: Sequence[Mapping[str, Any]] | None = None) -> JsonDict:
    """Run gospider if installed."""

    start_urls = _start_urls(target, urls, live_hosts)
    found: List[str] = []
    errors: List[str] = []
    for url in start_urls[:10]:
        result = _run_tool(["gospider", "-s", url, "-d", "1", "-q"], timeout=600)
        if not result.ok:
            errors.append(result.error or result.stderr)
            continue
        found.extend(re.findall(r"https?://[^\s\"'<>]+", result.stdout))
    response = {"tool": "gospider", "urls": _dedupe(found)}
    if errors and not response["urls"]:
        response["error"] = "; ".join(errors[:3])
    return response


def run_builtin_crawl(target: str, urls: Sequence[str] | None = None, live_hosts: Sequence[Mapping[str, Any]] | None = None) -> JsonDict:
    """Fetch start pages and extract same-site links."""

    found: List[str] = []
    for url in _start_urls(target, urls, live_hosts)[:10]:
        try:
            response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            parser = LinkParser()
            parser.feed(response.text[:500_000])
            base_host = urlparse(response.url).netloc
            for link in parser.links:
                absolute = urljoin(response.url, link)
                if urlparse(absolute).netloc == base_host:
                    found.append(absolute)
        except requests.RequestException:
            continue
    return {"tool": "builtin_crawl", "urls": _dedupe(found)}


def run_gau(target: str) -> JsonDict:
    """Run gau for historical URLs."""

    domain = _domain(target)
    result = _run_tool(["gau", "--subs", domain], timeout=600)
    return _archive_result("gau", [url for url in _lines(result.stdout) if url.startswith("http")], result)


def run_waybackurls(target: str) -> JsonDict:
    """Run waybackurls if installed."""

    domain = _domain(target)
    result = _run_tool(["waybackurls"], input_text=domain, timeout=600)
    return _archive_result("waybackurls", [url for url in _lines(result.stdout) if url.startswith("http")], result)


def run_urlfinder(target: str) -> JsonDict:
    """Run urlfinder if installed."""

    domain = _domain(target)
    result = _run_tool(["urlfinder", "-d", domain, "-silent"], timeout=600)
    return _archive_result("urlfinder", [url for url in _lines(result.stdout) if url.startswith("http")], result)


def run_commoncrawl_index(target: str) -> JsonDict:
    """Query Common Crawl index for known URLs."""

    domain = _domain(target)
    try:
        index_response = requests.get("https://index.commoncrawl.org/collinfo.json", timeout=20)
        index_response.raise_for_status()
        indexes = index_response.json()
        if not indexes:
            return {"tool": "commoncrawl", "archived_urls": []}
        api_url = indexes[0]["cdx-api"]
        response = requests.get(
            api_url,
            params={"url": f"*.{domain}/*", "output": "json", "fl": "url", "filter": "status:200", "collapse": "urlkey"},
            timeout=30,
        )
        urls = [json.loads(line).get("url", "") for line in response.text.splitlines() if line.strip()]
        return {"tool": "commoncrawl", "archived_urls": _dedupe([url for url in urls if url.startswith("http")])}
    except Exception as exc:  # noqa: BLE001
        return {"tool": "commoncrawl", "archived_urls": [], "error": str(exc)}


def run_ffuf(target: str, base_urls: Sequence[str] | None = None, urls: Sequence[str] | None = None) -> JsonDict:
    """Run ffuf content discovery."""

    base_url = _first_url(target, base_urls or urls)
    _ensure_wordlist()
    output_file = Path(tempfile.gettempdir()) / "ai_recon_ffuf.json"
    result = _run_tool(
        [
            "ffuf",
            "-u",
            f"{base_url.rstrip('/')}/FUZZ",
            "-w",
            str(WORDLIST_PATH),
            "-mc",
            "200,201,204,301,302,307,401,403",
            "-of",
            "json",
            "-o",
            str(output_file),
            "-s",
        ],
        timeout=600,
    )
    paths: List[JsonDict] = []
    if output_file.exists():
        try:
            payload = json.loads(output_file.read_text(encoding="utf-8"))
            for item in payload.get("results", []):
                paths.append({"path": urlparse(str(item.get("url", ""))).path or "/", "status": int(item.get("status", 0)), "url": item.get("url")})
        except json.JSONDecodeError:
            pass
    return _path_result("ffuf", paths, result)


def run_feroxbuster(target: str, base_urls: Sequence[str] | None = None, urls: Sequence[str] | None = None) -> JsonDict:
    """Run feroxbuster if installed."""

    base_url = _first_url(target, base_urls or urls)
    _ensure_wordlist()
    result = _run_tool(["feroxbuster", "-u", base_url, "-w", str(WORDLIST_PATH), "--json", "-q", "-k", "-d", "1"], timeout=600)
    paths = []
    for item in _json_lines(result.stdout):
        url = str(item.get("url") or "")
        status = int(item.get("status") or item.get("status_code") or 0)
        if url:
            paths.append({"path": urlparse(url).path or "/", "status": status, "url": url})
    return _path_result("feroxbuster", paths, result)


def run_gobuster(target: str, base_urls: Sequence[str] | None = None, urls: Sequence[str] | None = None) -> JsonDict:
    """Run gobuster dir if installed."""

    base_url = _first_url(target, base_urls or urls)
    _ensure_wordlist()
    result = _run_tool(["gobuster", "dir", "-u", base_url, "-w", str(WORDLIST_PATH), "-q", "-k", "--no-error"], timeout=600)
    paths = []
    for line in _lines(result.stdout):
        match = re.match(r"(/[^\s]+).*Status:\s*(\d+)", line)
        if match:
            paths.append({"path": match.group(1), "status": int(match.group(2)), "url": urljoin(base_url, match.group(1))})
    return _path_result("gobuster", paths, result)


def run_builtin_path_probe(target: str, base_urls: Sequence[str] | None = None, urls: Sequence[str] | None = None) -> JsonDict:
    """Probe a small built-in path list."""

    base_url = _first_url(target, base_urls or urls)
    found: List[JsonDict] = []
    for path in COMMON_PATHS:
        url = f"{base_url.rstrip('/')}/{path}"
        try:
            response = requests.get(url, timeout=8, allow_redirects=False, verify=False)
            if response.status_code in {200, 201, 204, 301, 302, 307, 401, 403}:
                found.append({"path": f"/{path}", "status": response.status_code, "url": url})
        except requests.RequestException:
            continue
    return {"tool": "builtin_path_probe", "found_paths": found}


def run_nuclei(target: str, urls: Sequence[str] | None = None, live_hosts: Sequence[Mapping[str, Any]] | None = None) -> JsonDict:
    """Run nuclei against discovered URLs."""

    targets = _start_urls(target, urls, live_hosts)
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".txt") as handle:
        handle.write("\n".join(targets))
        target_file = handle.name
    result = _run_tool(
        ["nuclei", "-l", target_file, "-jsonl", "-silent", "-severity", "critical,high,medium", "-retries", "1", "-timeout", "5"],
        timeout=900,
    )
    findings: List[JsonDict] = []
    for item in _json_lines(result.stdout):
        info = item.get("info", {}) if isinstance(item.get("info"), Mapping) else {}
        findings.append(
            {
                "severity": str(info.get("severity") or item.get("severity") or ""),
                "name": str(info.get("name") or item.get("template-id") or "nuclei finding"),
                "detail": str(item.get("matched-at") or item.get("host") or item.get("template-id") or ""),
            }
        )
    return _finding_result("nuclei", findings, result)


def run_nikto(target: str, urls: Sequence[str] | None = None, live_hosts: Sequence[Mapping[str, Any]] | None = None) -> JsonDict:
    """Run nikto against the first URL if installed."""

    url = _first_url(target, urls or [str(item.get("host", "")) for item in live_hosts or []])
    result = _run_tool(["nikto", "-h", url, "-nointeractive"], timeout=900)
    findings = [{"severity": "medium", "name": "nikto finding", "detail": line} for line in _lines(result.stdout) if line.startswith("+")]
    return _finding_result("nikto", findings, result)


def run_wapiti(target: str, urls: Sequence[str] | None = None, live_hosts: Sequence[Mapping[str, Any]] | None = None) -> JsonDict:
    """Run wapiti against the first URL if installed."""

    url = _first_url(target, urls or [str(item.get("host", "")) for item in live_hosts or []])
    result = _run_tool(["wapiti", "-u", url, "-f", "json", "-o", "-"], timeout=900)
    findings: List[JsonDict] = []
    if result.ok:
        try:
            payload = json.loads(result.stdout)
            for category, items in payload.get("vulnerabilities", {}).items():
                for item in items:
                    findings.append({"severity": str(item.get("level", "")), "name": str(category), "detail": str(item.get("info", ""))})
        except json.JSONDecodeError:
            pass
    return _finding_result("wapiti", findings, result)


def run_builtin_security_headers(
    target: str,
    urls: Sequence[str] | None = None,
    live_hosts: Sequence[Mapping[str, Any]] | None = None,
) -> JsonDict:
    """Check for missing basic HTTP security headers."""

    findings: List[JsonDict] = []
    required = ["content-security-policy", "x-frame-options", "x-content-type-options"]
    for url in _start_urls(target, urls, live_hosts)[:20]:
        try:
            response = requests.get(url, timeout=10, verify=False)
        except requests.RequestException:
            continue
        lower_headers = {key.lower() for key in response.headers}
        for header in required:
            if header not in lower_headers:
                findings.append({"severity": "low", "name": f"Missing {header}", "detail": url})
    return {"tool": "builtin_security_headers", "findings": findings}


PHASE_TOOLS: Dict[str, List[JsonDict]] = {
    "subdomain_enum": [
        {"name": "subfinder", "function": run_subfinder},
        {"name": "amass", "function": run_amass},
        {"name": "assetfinder", "function": run_assetfinder},
        {"name": "crtsh", "function": run_crtsh},
    ],
    "permutation": [
        {"name": "alterx", "function": run_alterx},
        {"name": "dnsgen", "function": run_dnsgen},
        {"name": "gotator", "function": run_gotator},
        {"name": "builtin_permutations", "function": run_builtin_permutations},
    ],
    "dns_resolution": [
        {"name": "httpx", "function": run_httpx},
        {"name": "dnsx", "function": run_dnsx},
        {"name": "httprobe", "function": run_httprobe},
        {"name": "builtin_dns_resolution", "function": run_builtin_dns_resolution},
    ],
    "port_scan": [
        {"name": "naabu", "function": run_naabu},
        {"name": "nmap", "function": run_nmap_ports},
        {"name": "builtin_tcp_probe", "function": run_builtin_tcp_probe},
        {"name": "masscan", "function": run_masscan},
    ],
    "crawl": [
        {"name": "katana", "function": run_katana},
        {"name": "hakrawler", "function": run_hakrawler},
        {"name": "gospider", "function": run_gospider},
        {"name": "builtin_crawl", "function": run_builtin_crawl},
    ],
    "historical_urls": [
        {"name": "gau", "function": run_gau},
        {"name": "waybackurls", "function": run_waybackurls},
        {"name": "urlfinder", "function": run_urlfinder},
        {"name": "commoncrawl", "function": run_commoncrawl_index},
    ],
    "fuzzing": [
        {"name": "ffuf", "function": run_ffuf},
        {"name": "feroxbuster", "function": run_feroxbuster},
        {"name": "gobuster", "function": run_gobuster},
        {"name": "builtin_path_probe", "function": run_builtin_path_probe},
    ],
    "vulnerability_scan": [
        {"name": "nuclei", "function": run_nuclei},
        {"name": "nikto", "function": run_nikto},
        {"name": "wapiti", "function": run_wapiti},
        {"name": "builtin_security_headers", "function": run_builtin_security_headers},
    ],
}


class CommandResult:
    """Small subprocess result wrapper."""

    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0, error: str = "") -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.error = error

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.error


def _run_tool(args: Sequence[str], input_text: str | None = None, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
    binary = args[0]
    if shutil.which(binary) is None:
        return CommandResult(returncode=127, error=f"Required binary not found on PATH: {binary}")
    try:
        completed = subprocess.run(
            list(args),
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(completed.stdout, completed.stderr, completed.returncode)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(exc.stdout or "", exc.stderr or "", returncode=124, error=f"{binary} timed out after {timeout}s")
    except OSError as exc:
        return CommandResult(returncode=1, error=str(exc))


def _subdomain_result(tool: str, values: Sequence[str], result: CommandResult) -> JsonDict:
    return _with_error({"tool": tool, "subdomains": _dedupe(values)}, result)


def _candidate_result(tool: str, values: Sequence[str], result: CommandResult) -> JsonDict:
    return _with_error({"tool": tool, "candidates": _dedupe(values)}, result)


def _live_host_result(tool: str, values: Sequence[JsonDict], result: CommandResult) -> JsonDict:
    return _with_error({"tool": tool, "live_hosts": _dedupe_records(values, ("host", "status", "title"))}, result)


def _port_result(tool: str, values: Sequence[JsonDict], result: CommandResult) -> JsonDict:
    return _with_error({"tool": tool, "open_ports": _dedupe_records(values, ("port", "service"))}, result)


def _url_result(tool: str, values: Sequence[str], result: CommandResult) -> JsonDict:
    return _with_error({"tool": tool, "urls": _dedupe(values)}, result)


def _archive_result(tool: str, values: Sequence[str], result: CommandResult) -> JsonDict:
    return _with_error({"tool": tool, "archived_urls": _dedupe(values)}, result)


def _path_result(tool: str, values: Sequence[JsonDict], result: CommandResult) -> JsonDict:
    return _with_error({"tool": tool, "found_paths": _dedupe_records(values, ("path", "status"))}, result)


def _finding_result(tool: str, values: Sequence[JsonDict], result: CommandResult) -> JsonDict:
    return _with_error({"tool": tool, "findings": _dedupe_records(values, ("severity", "name", "detail"))}, result)


def _with_error(payload: JsonDict, result: CommandResult) -> JsonDict:
    if result.error:
        payload["error"] = result.error
    elif result.returncode not in {0} and not any(payload.get(key) for key in payload if isinstance(payload.get(key), list)):
        payload["error"] = result.stderr.strip() or f"command exited with code {result.returncode}"
    return payload


def _domain(value: str) -> str:
    raw = str(value).strip()
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = (parsed.hostname or raw).strip().lower().rstrip(".")
    if "/" in host:
        host = host.split("/", 1)[0]
    if ":" in host and not _is_ip(host):
        host = host.split(":", 1)[0]
    return host.lstrip("*.")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _filter_domains(values: Iterable[str], domain: str) -> List[str]:
    return [
        value.lower().rstrip(".")
        for value in values
        if value and (value.lower().rstrip(".") == domain or value.lower().rstrip(".").endswith(f".{domain}"))
    ]


def _lines(text: str) -> List[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _json_lines(text: str) -> List[JsonDict]:
    parsed: List[JsonDict] = []
    for line in _lines(text):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            parsed.append(item)
    return parsed


def _dedupe(values: Iterable[str]) -> List[str]:
    output: List[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value).strip()
        if item and item not in seen:
            seen.add(item)
            output.append(item)
    return output


def _dedupe_records(values: Sequence[JsonDict], fields: Sequence[str]) -> List[JsonDict]:
    output: List[JsonDict] = []
    seen: set[str] = set()
    for value in values:
        key = "|".join(str(value.get(field, "")) for field in fields)
        if key not in seen:
            seen.add(key)
            output.append(dict(value))
    return output


def _first_host(target: str, hosts: Sequence[str] | None = None) -> str:
    for host in hosts or []:
        value = _domain(str(host))
        if value:
            return value
    return _domain(target)


def _start_urls(
    target: str,
    urls: Sequence[str] | None = None,
    live_hosts: Sequence[Mapping[str, Any]] | None = None,
) -> List[str]:
    output: List[str] = []
    for url in urls or []:
        value = str(url)
        if value.startswith("http"):
            output.append(value)
    for item in live_hosts or []:
        value = str(item.get("host", ""))
        if value.startswith("http"):
            output.append(value)
    if not output:
        domain = _domain(target)
        output.extend([f"https://{domain}", f"http://{domain}"])
    return _dedupe(output)


def _first_url(target: str, urls: Sequence[str] | None = None) -> str:
    for url in urls or []:
        value = str(url).strip()
        if value.startswith("http"):
            return value
    return f"https://{_domain(target)}"


def _service_name(port: int) -> str:
    common = {22: "ssh", 25: "smtp", 53: "dns", 80: "http", 443: "https", 8080: "http-alt", 8443: "https-alt"}
    return common.get(port, "")


def _ensure_wordlist() -> None:
    WORDLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not WORDLIST_PATH.exists():
        WORDLIST_PATH.write_text("\n".join(COMMON_PATHS) + "\n", encoding="utf-8")


__all__ = ["PHASE_TOOLS"] + [name for name in globals() if name.startswith("run_")]
