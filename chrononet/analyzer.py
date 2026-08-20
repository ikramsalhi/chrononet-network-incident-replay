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


def _source_node(event: dict[str, Any]) -> str:
    return str(event.get("source_ip") or event.get("source") or "")


def _target_node(event: dict[str, Any]) -> str:
    return str(event.get("target_ip") or event.get("target") or "")


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
    affected = sorted({_source_node(e) for e in events if _source_node(e)})
    findings: list[Finding] = []

    dns_timeouts = [e for e in events if _contains(e, "dns") and ("timeout" in str(e.get("status", "")).lower() or _value(e, "latency_ms") >= 600)]
    dns_nodes = sorted({_source_node(e) for e in dns_timeouts if _source_node(e)})
    if len(dns_timeouts) >= 3:
        confidence = min(98, 68 + len(dns_timeouts) * 4 + min(len(dns_nodes), 5) * 2)
        findings.append(Finding(
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
        ))

    gateway_loss = [
        e for e in events
        if (_contains(e, "gateway") or str(e.get("target", "")).lower() in {"default-gateway", "gateway"})
        and (_value(e, "packet_loss_pct") >= 15 or "unreachable" in str(e.get("status", "")).lower())
    ]
    gateway_nodes = sorted({_source_node(e) for e in gateway_loss if _source_node(e)})
    if len(gateway_loss) >= 2:
        confidence = min(97, 72 + len(gateway_loss) * 5 + min(len(gateway_nodes), 4) * 2)
        findings.append(Finding(
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
        ))

    dhcp_events = [e for e in events if _contains(e, "dhcp")]
    lease_failures = [e for e in dhcp_events if any(term in str(e.get("status", "")).lower() for term in ("failed", "no lease", "timeout", "exhausted"))]
    if len(lease_failures) >= 3:
        findings.append(Finding(
            key="dhcp-pressure",
            title="DHCP address-pool pressure",
            confidence=min(96, 70 + len(lease_failures) * 5),
            severity="high",
            evidence=[
                f"{len(lease_failures)} failed lease observations",
                f"{len({_source_node(e) for e in lease_failures if _source_node(e)})} client(s) affected",
                "Multiple clients fail during the same allocation window",
            ],
            recommendation="Check pool utilization, lease duration, stale reservations, relay configuration, and duplicate DHCP servers.",
        ))

    link_flaps = [e for e in events if _contains(e, "link") and any(term in str(e.get("status", "")).lower() for term in ("down", "up", "flap"))]
    per_target: dict[str, int] = defaultdict(int)
    for event in link_flaps:
        per_target[str(event.get("target", "unknown"))] += 1
    unstable = [(target, count) for target, count in per_target.items() if count >= 3]
    if unstable:
        target, count = max(unstable, key=lambda item: item[1])
        findings.append(Finding(
            key="link-flapping",
            title="Unstable network link",
            confidence=min(95, 74 + count * 4),
            severity="high",
            evidence=[f"{count} state transitions on {target}", "Rapid up/down transitions indicate an unstable physical or negotiated link"],
            recommendation="Inspect cable/SFP condition, duplex negotiation, switch-port counters, PoE/power stability, and spanning-tree events.",
        ))

    tcp_resets = [e for e in events if str(e.get("protocol", "")).upper() == "TCP" and "reset" in str(e.get("status", "")).lower()]
    if len(tcp_resets) >= 4:
        reset_targets = Counter(_target_node(e) for e in tcp_resets if _target_node(e))
        top_target, top_count = reset_targets.most_common(1)[0] if reset_targets else ("multiple destinations", 0)
        findings.append(Finding(
            key="tcp-reset-storm",
            title="Elevated TCP reset activity",
            confidence=min(94, 66 + len(tcp_resets) * 3 + min(top_count, 6)),
            severity="high" if len(tcp_resets) >= 8 else "medium",
            evidence=[
                f"{len(tcp_resets)} TCP RST observations in the capture",
                f"Most reset traffic targets {top_target} ({top_count} observation(s))",
                f"{len({_source_node(e) for e in tcp_resets if _source_node(e)})} source host(s) involved",
            ],
            recommendation="Check whether the destination service is rejecting sessions, restarting, overloaded, blocked by a firewall, or receiving connections on a closed port.",
        ))

    unreachable = [e for e in events if str(e.get("protocol", "")).upper() in {"ICMP", "ICMPV6"} and "unreachable" in str(e.get("status", "")).lower()]
    if len(unreachable) >= 3:
        targets = Counter(_target_node(e) for e in unreachable if _target_node(e))
        top_target, top_count = targets.most_common(1)[0] if targets else ("multiple destinations", 0)
        findings.append(Finding(
            key="destination-unreachable",
            title="Repeated destination-unreachable errors",
            confidence=min(93, 69 + len(unreachable) * 4),
            severity="high" if len(unreachable) >= 6 else "medium",
            evidence=[
                f"{len(unreachable)} ICMP unreachable errors observed",
                f"Most frequent unreachable destination: {top_target} ({top_count} observation(s))",
                "Network-layer rejection is repeated rather than isolated",
            ],
            recommendation="Verify routing, ACL/firewall policy, destination host availability, VLAN reachability, and whether the destination service or network actually exists.",
        ))

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
