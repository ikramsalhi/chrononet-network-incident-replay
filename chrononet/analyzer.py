from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Iterable


@dataclass(frozen=True)
class Finding:
    key: str
    title: str
    confidence: int
    severity: str
    evidence: list[str]
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _value(event: dict[str, Any], name: str, default: float = 0.0) -> float:
    try:
        return float(event.get(name, default))
    except (TypeError, ValueError):
        return default


def _contains(event: dict[str, Any], *terms: str) -> bool:
    haystack = " ".join(
        str(event.get(key, ""))
        for key in ("type", "service", "status", "message", "target", "source")
    ).lower()
    return all(term.lower() in haystack for term in terms)


def analyze_events(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    events = sorted(list(events), key=lambda event: event.get("timestamp", ""))
    if not events:
        return {
            "event_count": 0,
            "duration_seconds": 0,
            "affected_nodes": [],
            "severity_counts": {},
            "top_event_types": [],
            "findings": [],
            "health_score": 100,
            "summary": "No events were provided.",
        }

    severity_counts = Counter(str(e.get("severity", "info")).lower() for e in events)
    event_types = Counter(str(e.get("type", "unknown")) for e in events)
    affected = sorted({str(e.get("source")) for e in events if e.get("source")})

    findings: list[Finding] = []

    dns_timeouts = [e for e in events if _contains(e, "dns") and ("timeout" in str(e.get("status", "")).lower() or _value(e, "latency_ms") >= 600)]
    dns_nodes = sorted({str(e.get("source")) for e in dns_timeouts if e.get("source")})
    if len(dns_timeouts) >= 3:
        confidence = min(98, 68 + len(dns_timeouts) * 4 + min(len(dns_nodes), 5) * 2)
        findings.append(
            Finding(
                key="dns-degradation",
                title="DNS resolver degradation",
                confidence=confidence,
                severity="high" if len(dns_nodes) >= 3 else "medium",
                evidence=[
                    f"{len(dns_timeouts)} slow or timed-out DNS observations",
                    f"{len(dns_nodes)} client node(s) show the same symptom",
                    "Application failures follow name-resolution errors" if any(_contains(e, "application") for e in events) else "Repeated resolver failures occur within one incident window",
                ],
                recommendation="Check resolver reachability, upstream DNS health, forwarding rules, and resolver CPU/load before investigating individual clients.",
            )
        )

    gateway_loss = [
        e for e in events
        if (_contains(e, "gateway") or str(e.get("target", "")).lower() in {"default-gateway", "gateway"})
        and (_value(e, "packet_loss_pct") >= 15 or "unreachable" in str(e.get("status", "")).lower())
    ]
    gateway_nodes = sorted({str(e.get("source")) for e in gateway_loss if e.get("source")})
    if len(gateway_loss) >= 2:
        confidence = min(97, 72 + len(gateway_loss) * 5 + min(len(gateway_nodes), 4) * 2)
        findings.append(
            Finding(
                key="gateway-instability",
                title="Default gateway instability",
                confidence=confidence,
                severity="critical" if any(_value(e, "packet_loss_pct") >= 60 for e in gateway_loss) else "high",
                evidence=[
                    f"{len(gateway_loss)} gateway-loss observations",
                    f"Observed from {len(gateway_nodes)} node(s)",
                    f"Peak packet loss: {max((_value(e, 'packet_loss_pct') for e in gateway_loss), default=0):.0f}%",
                ],
                recommendation="Inspect gateway interface errors, uplink state, ARP/MAC stability, power, and switch port health. Correlate with interface counters.",
            )
        )

    dhcp_events = [e for e in events if _contains(e, "dhcp")]
    lease_failures = [e for e in dhcp_events if any(term in str(e.get("status", "")).lower() for term in ("failed", "no lease", "timeout", "exhausted"))]
    if len(lease_failures) >= 3:
        findings.append(
            Finding(
                key="dhcp-pressure",
                title="DHCP address-pool pressure",
                confidence=min(96, 70 + len(lease_failures) * 5),
                severity="high",
                evidence=[
                    f"{len(lease_failures)} failed lease observations",
                    f"{len({e.get('source') for e in lease_failures if e.get('source')})} client(s) affected",
                    "Multiple clients fail during the same allocation window",
                ],
                recommendation="Check pool utilization, lease duration, stale reservations, relay configuration, and duplicate DHCP servers.",
            )
        )

    link_flaps = [e for e in events if _contains(e, "link") and any(term in str(e.get("status", "")).lower() for term in ("down", "up", "flap"))]
    per_target: dict[str, int] = defaultdict(int)
    for event in link_flaps:
        per_target[str(event.get("target", "unknown"))] += 1
    unstable = [(target, count) for target, count in per_target.items() if count >= 3]
    if unstable:
        target, count = max(unstable, key=lambda item: item[1])
        findings.append(
            Finding(
                key="link-flapping",
                title="Unstable network link",
                confidence=min(95, 74 + count * 4),
                severity="high",
                evidence=[f"{count} state transitions on {target}", "Rapid up/down transitions indicate an unstable physical or negotiated link"],
                recommendation="Inspect cable/SFP condition, duplex negotiation, switch-port counters, PoE/power stability, and spanning-tree events.",
            )
        )

    findings.sort(key=lambda finding: (finding.confidence, {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(finding.severity, 0)), reverse=True)

    critical_weight = severity_counts.get("critical", 0) * 12
    high_weight = severity_counts.get("high", 0) * 7
    medium_weight = severity_counts.get("medium", 0) * 3
    finding_weight = sum(max(0, finding.confidence - 60) // 6 for finding in findings[:3])
    health_score = max(0, min(100, 100 - critical_weight - high_weight - medium_weight - finding_weight))

    try:
        start = datetime.fromisoformat(str(events[0]["timestamp"]).replace("Z", "+00:00"))
        end = datetime.fromisoformat(str(events[-1]["timestamp"]).replace("Z", "+00:00"))
        duration = max(0, int((end - start).total_seconds()))
    except (KeyError, TypeError, ValueError):
        duration = 0

    if findings:
        top = findings[0]
        summary = f"Most likely root cause: {top.title} ({top.confidence}% confidence)."
    else:
        summary = "No high-confidence root cause matched the current explainable rule set."

    return {
        "event_count": len(events),
        "duration_seconds": duration,
        "affected_nodes": affected,
        "severity_counts": dict(severity_counts),
        "top_event_types": [{"type": key, "count": value} for key, value in event_types.most_common(6)],
        "findings": [finding.to_dict() for finding in findings],
        "health_score": health_score,
        "summary": summary,
    }
