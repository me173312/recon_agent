"""Core agent loop for the AI recon agent.

The loop is intentionally small and dependency-inverted:
- Omar's backend adapter is expected to provide ``send(messages, tools)``.
- Mazen's gated tool layer is expected to provide a callable execution method.
- Sherif's coverage tracker and Kero's skill loader plug in through stubs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
import inspect
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Sequence


Message = Dict[str, Any]
ToolSpec = Dict[str, Any]
PhaseResult = Dict[str, Any]
PhaseTool = Callable[[Any], Any] | Mapping[str, Any] | Any


PHASE_MODES: Dict[str, str] = {
    "subdomain_enum": "merge",
    "permutation": "fallback",
    "dns_resolution": "fallback",
    "port_scan": "fallback",
    "crawl": "fallback",
    "historical_urls": "merge",
    "fuzzing": "fallback",
    "vulnerability_scan": "fallback",
}

PHASE_RESULT_FIELDS: Dict[str, str] = {
    "subdomain_enum": "subdomains",
    "permutation": "candidates",
    "dns_resolution": "live_hosts",
    "port_scan": "open_ports",
    "crawl": "urls",
    "historical_urls": "archived_urls",
    "fuzzing": "found_paths",
    "vulnerability_scan": "findings",
}


class LoopPhase(str, Enum):
    PLAN = "plan"
    ACT = "act"
    OBSERVE = "observe"
    VERIFY = "verify"
    REPORT = "report"


@dataclass
class LoopEvent:
    phase: LoopPhase
    message: str
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LoopResult:
    status: str
    report: str
    steps_taken: int
    events: List[LoopEvent]
    messages: List[Message]


class BackendAdapterInterface(Protocol):
    """Expected Omar adapter contract."""

    def send(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> Any:
        """Send chat messages and optional tool specs to the model."""


class GatedToolLayerInterface(Protocol):
    """Expected Mazen tool-layer contract."""

    def execute(self, tool_name: str, arguments: Mapping[str, Any]) -> Any:
        """Execute a permission-gated tool call."""


class CoverageTrackerInterface:
    """Stub integration point for Sherif's coverage tracker."""

    def mark_tested(self, item: str) -> None:
        return None

    def get_untested(self) -> List[str]:
        return []


class SkillLoaderInterface:
    """Stub integration point for Kero's skill files."""

    def __init__(self, skill_dir: Optional[str | Path] = None) -> None:
        self.skill_dir = Path(skill_dir) if skill_dir else None

    def load_skills(self) -> Dict[str, str]:
        if not self.skill_dir or not self.skill_dir.exists():
            return {"placeholder": "Skill loader is ready; no skill directory is configured yet."}

        skills: Dict[str, str] = {}
        for path in sorted(self.skill_dir.glob("*.md")):
            skills[path.stem] = path.read_text(encoding="utf-8")
        return skills


def run_phase(
    phase_name: str,
    target: Any,
    tools_for_phase: Sequence[PhaseTool],
    mode: str = "fallback",
) -> PhaseResult:
    """Run one recon phase with configurable merge or fallback semantics.

    ``tools_for_phase`` intentionally accepts wrapper callables without importing
    or implementing them here. A tool may be a bare callable, a mapping with
    ``name`` and ``function``/``callable``, or an object exposing ``run``.
    """

    selected_mode = PHASE_MODES.get(phase_name, mode)
    if selected_mode not in {"merge", "fallback"}:
        raise ValueError(f"Unsupported phase execution mode: {selected_mode}")
    if phase_name not in MERGE_FUNCTIONS:
        raise ValueError(f"No merge function registered for phase: {phase_name}")
    if not tools_for_phase:
        return _phase_error(phase_name, [], "No tools configured for phase.")

    if selected_mode == "merge":
        return _run_phase_merge(phase_name, target, tools_for_phase)
    return _run_phase_fallback(phase_name, target, tools_for_phase)


def merge_subdomains(results: Sequence[PhaseResult]) -> PhaseResult:
    """Merge Phase 1 subdomain enumeration results."""

    subdomains: List[str] = []
    seen: set[str] = set()
    for result in results:
        _append_unique_scalars(subdomains, seen, result.get("subdomains", []))
    return {"tool": _joined_tool_names(results), "subdomains": subdomains}


def merge_candidates(results: Sequence[PhaseResult]) -> PhaseResult:
    """Merge Phase 2 permutation candidate results."""

    candidates: List[str] = []
    seen: set[str] = set()
    for result in results:
        _append_unique_scalars(candidates, seen, result.get("candidates", []))
    return {"tool": _joined_tool_names(results), "candidates": candidates}


def merge_live_hosts(results: Sequence[PhaseResult]) -> PhaseResult:
    """Merge Phase 3 live host records."""

    live_hosts: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for result in results:
        _append_unique_records(live_hosts, seen, result.get("live_hosts", []), ("host", "status", "title"))
    return {"tool": _joined_tool_names(results), "live_hosts": live_hosts}


def merge_ports(results: Sequence[PhaseResult]) -> PhaseResult:
    """Merge Phase 4 open port records."""

    open_ports: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for result in results:
        _append_unique_records(open_ports, seen, result.get("open_ports", []), ("port", "service"))
    return {"tool": _joined_tool_names(results), "open_ports": open_ports}


def merge_urls(results: Sequence[PhaseResult]) -> PhaseResult:
    """Merge Phase 5 crawl URL results."""

    urls: List[str] = []
    seen: set[str] = set()
    for result in results:
        _append_unique_scalars(urls, seen, result.get("urls", []))
    return {"tool": _joined_tool_names(results), "urls": urls}


def merge_archived_urls(results: Sequence[PhaseResult]) -> PhaseResult:
    """Merge Phase 6 historical URL results."""

    archived_urls: List[str] = []
    seen: set[str] = set()
    for result in results:
        _append_unique_scalars(archived_urls, seen, result.get("archived_urls", []))
    return {"tool": _joined_tool_names(results), "archived_urls": archived_urls}


def merge_found_paths(results: Sequence[PhaseResult]) -> PhaseResult:
    """Merge Phase 7 fuzzing path results."""

    found_paths: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for result in results:
        _append_unique_records(found_paths, seen, result.get("found_paths", []), ("path", "status"))
    return {"tool": _joined_tool_names(results), "found_paths": found_paths}


def merge_findings(results: Sequence[PhaseResult]) -> PhaseResult:
    """Merge Phase 8 vulnerability findings."""

    findings: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for result in results:
        _append_unique_records(findings, seen, result.get("findings", []), ("severity", "name", "detail"))
    return {"tool": _joined_tool_names(results), "findings": findings}


MERGE_FUNCTIONS: Dict[str, Callable[[Sequence[PhaseResult]], PhaseResult]] = {
    "subdomain_enum": merge_subdomains,
    "permutation": merge_candidates,
    "dns_resolution": merge_live_hosts,
    "port_scan": merge_ports,
    "crawl": merge_urls,
    "historical_urls": merge_archived_urls,
    "fuzzing": merge_found_paths,
    "vulnerability_scan": merge_findings,
}


def _run_phase_merge(phase_name: str, target: Any, tools_for_phase: Sequence[PhaseTool]) -> PhaseResult:
    successful_results: List[PhaseResult] = []
    errors: List[Dict[str, str]] = []

    for tool in tools_for_phase:
        tool_name = _tool_name(tool)
        try:
            result = _execute_phase_tool(tool, target)
            normalized = _normalize_phase_result(result, tool_name)
            if _is_successful_phase_output(normalized):
                successful_results.append(normalized)
            else:
                errors.append({"tool": tool_name, "error": "Tool returned an empty or unsuccessful result."})
        except Exception as exc:  # noqa: BLE001 - phase runner records wrapper failures.
            errors.append({"tool": tool_name, "error": str(exc), "error_type": type(exc).__name__})

    if not successful_results:
        return _phase_error(phase_name, errors, "All tools failed or returned empty results.")

    merged = MERGE_FUNCTIONS[phase_name](successful_results)
    if errors:
        merged["errors"] = errors
    return merged


def _run_phase_fallback(phase_name: str, target: Any, tools_for_phase: Sequence[PhaseTool]) -> PhaseResult:
    errors: List[Dict[str, str]] = []

    for tool in tools_for_phase:
        tool_name = _tool_name(tool)
        try:
            result = _execute_phase_tool(tool, target)
            normalized = _normalize_phase_result(result, tool_name)
            if _is_successful_phase_output(normalized):
                return MERGE_FUNCTIONS[phase_name]([normalized])
            errors.append({"tool": tool_name, "error": "Tool returned an empty or unsuccessful result."})
        except Exception as exc:  # noqa: BLE001 - fallback proceeds to the next wrapper.
            errors.append({"tool": tool_name, "error": str(exc), "error_type": type(exc).__name__})

    return _phase_error(phase_name, errors, "All fallback tools failed or returned empty results.")


def _execute_phase_tool(tool: PhaseTool, target: Any) -> Any:
    callable_tool = _tool_callable(tool)
    signature = inspect.signature(callable_tool)

    if isinstance(target, Mapping):
        parameters = signature.parameters
        if any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()):
            return callable_tool(**dict(target))
        accepted_arguments = {
            name: value
            for name, value in target.items()
            if name in parameters
        }
        if accepted_arguments:
            return callable_tool(**accepted_arguments)

    return callable_tool(target)


def _tool_callable(tool: PhaseTool) -> Callable[..., Any]:
    if callable(tool):
        return tool

    if isinstance(tool, Mapping):
        for key in ("function", "callable", "runner", "run"):
            candidate = tool.get(key)
            if callable(candidate):
                return candidate

    candidate = getattr(tool, "run", None)
    if callable(candidate):
        return candidate

    raise TypeError(f"Configured tool is not callable: {_tool_name(tool)}")


def _tool_name(tool: PhaseTool) -> str:
    if isinstance(tool, Mapping):
        name = tool.get("name") or tool.get("tool") or tool.get("tool_name")
        if name:
            return str(name)
        candidate = tool.get("function") or tool.get("callable") or tool.get("runner") or tool.get("run")
        if callable(candidate):
            return getattr(candidate, "__name__", candidate.__class__.__name__)

    return getattr(tool, "__name__", tool.__class__.__name__)


def _normalize_phase_result(result: Any, fallback_tool_name: str) -> PhaseResult:
    if hasattr(result, "model_dump") and callable(result.model_dump):
        normalized = result.model_dump()
    elif hasattr(result, "dict") and callable(result.dict):
        normalized = result.dict()
    elif is_dataclass(result) and not isinstance(result, type):
        normalized = asdict(result)
    elif isinstance(result, Mapping):
        normalized = dict(result)
    else:
        raise TypeError(f"Tool {fallback_tool_name} returned unsupported result type: {type(result).__name__}")

    normalized.setdefault("tool", _extract_tool_name(normalized, fallback_tool_name))
    return normalized


def _extract_tool_name(result: Mapping[str, Any], fallback_tool_name: str) -> str:
    metadata = result.get("metadata")
    if isinstance(metadata, Mapping):
        metadata_tool = metadata.get("tool") or metadata.get("tool_name") or metadata.get("name")
        if metadata_tool:
            return str(metadata_tool)
    return str(result.get("tool") or fallback_tool_name)


def _is_successful_phase_output(result: Mapping[str, Any]) -> bool:
    metadata = result.get("metadata")
    if isinstance(metadata, Mapping) and metadata.get("success") is False:
        return False
    if result.get("success") is False or result.get("error"):
        return False

    for field_name in PHASE_RESULT_FIELDS.values():
        value = result.get(field_name)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) and len(value) > 0:
            return True
    return False


def _append_unique_scalars(output: List[str], seen: set[str], values: Any) -> None:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        return
    for value in values:
        key = str(value)
        if key not in seen:
            seen.add(key)
            output.append(key)


def _append_unique_records(
    output: List[Dict[str, Any]],
    seen: set[str],
    records: Any,
    key_fields: Sequence[str],
) -> None:
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        return

    for record in records:
        normalized = _record_to_mapping(record)
        if not normalized:
            continue
        key = "|".join(str(normalized.get(field, "")) for field in key_fields)
        if key not in seen:
            seen.add(key)
            output.append(dict(normalized))


def _record_to_mapping(record: Any) -> Dict[str, Any]:
    if hasattr(record, "model_dump") and callable(record.model_dump):
        return dict(record.model_dump())
    if hasattr(record, "dict") and callable(record.dict):
        return dict(record.dict())
    if is_dataclass(record) and not isinstance(record, type):
        return dict(asdict(record))
    if isinstance(record, Mapping):
        return dict(record)
    return {}


def _joined_tool_names(results: Sequence[PhaseResult]) -> str:
    names: List[str] = []
    seen: set[str] = set()
    for result in results:
        name = str(result.get("tool") or "unknown")
        if name not in seen:
            seen.add(name)
            names.append(name)
    return ",".join(names)


def _phase_error(phase_name: str, errors: Sequence[Mapping[str, str]], message: str) -> PhaseResult:
    field_name = PHASE_RESULT_FIELDS.get(phase_name)
    result: PhaseResult = {
        "tool": "",
        "error": message,
        "errors": [dict(error) for error in errors],
    }
    if field_name:
        result[field_name] = []
    return result


class AgentLoop:
    """Plan -> act -> observe -> verify -> report orchestration."""

    def __init__(
        self,
        adapter: BackendAdapterInterface,
        tool_layer: Any,
        *,
        tools: Optional[Sequence[ToolSpec]] = None,
        max_steps: int = 30,
        max_tool_calls: Optional[int] = None,
        coverage_tracker: Optional[CoverageTrackerInterface] = None,
        skill_loader: Optional[SkillLoaderInterface] = None,
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be at least 1")
        if max_tool_calls is not None and max_tool_calls < 1:
            raise ValueError("max_tool_calls must be at least 1")

        self.adapter = adapter
        self.tool_layer = tool_layer
        self.tools = list(tools or [])
        self.max_steps = max_steps
        self.max_tool_calls = max_tool_calls or max_steps
        self.coverage_tracker = coverage_tracker or CoverageTrackerInterface()
        self.skill_loader = skill_loader or SkillLoaderInterface()
        self.events: List[LoopEvent] = []

    def run(self, goal: str) -> LoopResult:
        messages: List[Message] = [
            {
                "role": "system",
                "content": (
                    "You are the core recon agent loop. Work in phases: "
                    "plan, act with tools, observe, verify, then report."
                ),
            },
            {"role": "user", "content": goal},
            {"role": "system", "content": f"Loaded skills: {json.dumps(self.skill_loader.load_skills())}"},
        ]

        status = "completed"
        steps_taken = 0
        tool_calls_taken = 0

        for step_number in range(1, self.max_steps + 1):
            steps_taken = step_number
            self._event(LoopPhase.PLAN, "planning step", {"step": step_number})
            plan_response = self._safe_send(messages + [self._phase_message(LoopPhase.PLAN)], [])
            messages.append(self._assistant_message(plan_response, LoopPhase.PLAN))

            self._event(LoopPhase.ACT, "acting step", {"step": step_number})
            act_response = self._safe_send(messages + [self._phase_message(LoopPhase.ACT)], self.tools)
            messages.append(self._assistant_message(act_response, LoopPhase.ACT))

            tool_calls = self._extract_tool_calls(act_response)
            if tool_calls:
                for call in tool_calls:
                    if tool_calls_taken >= self.max_tool_calls:
                        status = "tool_call_cap_reached"
                        self._event(
                            LoopPhase.OBSERVE,
                            "maximum tool-call cap reached; terminating cleanly",
                            {"max_tool_calls": self.max_tool_calls},
                        )
                        break
                    observation = self._execute_tool_call(call)
                    tool_calls_taken += 1
                    messages.append({"role": "tool", "content": json.dumps(observation, default=str)})
                if status == "tool_call_cap_reached":
                    break
            else:
                self._event(LoopPhase.OBSERVE, "no tool calls requested", {"step": step_number})

            self.coverage_tracker.mark_tested(f"step:{step_number}")

            self._event(LoopPhase.VERIFY, "verifying step", {"step": step_number})
            verify_response = self._safe_send(messages + [self._phase_message(LoopPhase.VERIFY)], [])
            messages.append(self._assistant_message(verify_response, LoopPhase.VERIFY))

            if self._is_done(verify_response):
                break
        else:
            status = "step_cap_reached"
            self._event(
                LoopPhase.OBSERVE,
                "maximum step cap reached; terminating cleanly",
                {"max_steps": self.max_steps},
            )

        self._event(LoopPhase.REPORT, "reporting result", {"status": status})
        report_response = self._safe_send(messages + [self._phase_message(LoopPhase.REPORT)], [])
        report = self._extract_content(report_response) or self._fallback_report(status)
        messages.append({"role": "assistant", "content": report})

        return LoopResult(
            status=status,
            report=report,
            steps_taken=steps_taken,
            events=list(self.events),
            messages=messages,
        )

    def _safe_send(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> Any:
        try:
            return self.adapter.send(messages, tools)
        except Exception as exc:  # noqa: BLE001 - adapter failures become observations.
            event = self._event(
                LoopPhase.OBSERVE,
                "adapter call failed",
                {"error_type": type(exc).__name__, "error": str(exc)},
            )
            return {"content": event.message, "error": event.data}

    def _execute_tool_call(self, call: Mapping[str, Any]) -> Dict[str, Any]:
        name = str(call.get("name") or call.get("tool_name") or call.get("function", {}).get("name") or "")
        arguments = self._normalize_arguments(call.get("arguments") or call.get("args") or call.get("function", {}).get("arguments") or {})

        try:
            result = self._call_tool_layer(name, arguments)
            return self._event(
                LoopPhase.OBSERVE,
                "tool call completed",
                {"tool": name, "arguments": arguments, "result": result},
            ).data
        except Exception as exc:  # noqa: BLE001 - denied/blocklisted/failed tools become observations.
            return self._event(
                LoopPhase.OBSERVE,
                "tool call failed",
                {
                    "tool": name,
                    "arguments": arguments,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            ).data

    def _call_tool_layer(self, name: str, arguments: Mapping[str, Any]) -> Any:
        for method_name in ("execute", "execute_tool", "call_tool", "run_tool", "run"):
            method = getattr(self.tool_layer, method_name, None)
            if not callable(method):
                continue

            signature = inspect.signature(method)
            parameters = list(signature.parameters)
            if len(parameters) >= 2:
                return method(name, arguments)
            return method({"name": name, "arguments": dict(arguments)})

        if callable(self.tool_layer):
            return self.tool_layer(name, arguments)

        direct_method = getattr(self.tool_layer, name, None)
        if callable(direct_method):
            return direct_method(**dict(arguments))

        raise TypeError("tool_layer exposes no supported execution method")

    def _extract_tool_calls(self, response: Any) -> List[Dict[str, Any]]:
        response = self._normalize_response(response)
        calls = response.get("tool_calls") or response.get("tools") or []

        if not calls and "function_call" in response:
            calls = [response["function_call"]]

        normalized: List[Dict[str, Any]] = []
        for call in calls:
            if not isinstance(call, Mapping):
                function = getattr(call, "function", None)
                normalized.append(
                    {
                        "name": getattr(function, "name", getattr(call, "name", None)),
                        "arguments": getattr(function, "arguments", getattr(call, "arguments", {})),
                    }
                )
                continue

            function = call.get("function")
            if isinstance(function, Mapping):
                normalized.append(
                    {
                        "name": function.get("name"),
                        "arguments": function.get("arguments", {}),
                    }
                )
            else:
                normalized.append(dict(call))
        return normalized

    def _extract_content(self, response: Any) -> str:
        normalized = self._normalize_response(response)
        content = normalized.get("content") or normalized.get("report") or normalized.get("message")
        if content is None:
            return ""
        return str(content)

    def _normalize_response(self, response: Any) -> Dict[str, Any]:
        if isinstance(response, Mapping):
            return dict(response)

        choices = getattr(response, "choices", None)
        if choices:
            message = getattr(choices[0], "message", None)
            if isinstance(message, Mapping):
                return dict(message)
            if message is not None:
                return {
                    "content": getattr(message, "content", ""),
                    "tool_calls": getattr(message, "tool_calls", []),
                }

        return {"content": str(response)}

    def _normalize_arguments(self, arguments: Any) -> Dict[str, Any]:
        if isinstance(arguments, str):
            try:
                decoded = json.loads(arguments)
                return decoded if isinstance(decoded, dict) else {"value": decoded}
            except json.JSONDecodeError:
                return {"value": arguments}
        if isinstance(arguments, Mapping):
            return dict(arguments)
        return {"value": arguments}

    def _is_done(self, response: Any) -> bool:
        normalized = self._normalize_response(response)
        if bool(normalized.get("done") or normalized.get("verified")):
            return True
        content = self._extract_content(normalized).strip().lower()
        return content in {"done", "complete", "completed", "verified"}

    def _assistant_message(self, response: Any, phase: LoopPhase) -> Message:
        return {"role": "assistant", "content": self._extract_content(response), "phase": phase.value}

    def _phase_message(self, phase: LoopPhase) -> Message:
        return {
            "role": "system",
            "content": (
                f"Phase: {phase.value}. Return structured JSON when possible. "
                "For act, include tool_calls when execution is needed."
            ),
        }

    def _fallback_report(self, status: str) -> str:
        untested = self.coverage_tracker.get_untested()
        return f"Loop finished with status={status}. Untested coverage items: {untested}"

    def _event(self, phase: LoopPhase, message: str, data: Optional[Dict[str, Any]] = None) -> LoopEvent:
        event = LoopEvent(phase=phase, message=message, data=data or {})
        self.events.append(event)
        return event


__all__ = [
    "AgentLoop",
    "BackendAdapterInterface",
    "CoverageTrackerInterface",
    "GatedToolLayerInterface",
    "LoopEvent",
    "LoopPhase",
    "LoopResult",
    "MERGE_FUNCTIONS",
    "PHASE_MODES",
    "PHASE_RESULT_FIELDS",
    "merge_archived_urls",
    "merge_candidates",
    "merge_findings",
    "merge_found_paths",
    "merge_live_hosts",
    "merge_ports",
    "merge_subdomains",
    "merge_urls",
    "run_phase",
    "SkillLoaderInterface",
]
