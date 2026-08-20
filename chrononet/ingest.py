from __future__ import annotations

import csv
import io
import ipaddress
import json
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class IngestError(ValueError):
    """Raised when an uploaded capture cannot be safely parsed."""


def _iso_timestamp(seconds: int, fraction: int, divisor: int) -> str:
    value = seconds + (fraction / divisor)
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _service_name(protocol: str, source_port: int | None, destination_port: int | None) -> str:
    ports = {port for port in (source_port, destination_port) if port is not None}
    if 53 in ports:
        return "DNS"
    if ports & {67, 68}:
        return "DHCP"
    if 443 in ports:
        return "HTTPS" if protocol == "TCP" else "QUIC"
    if 80 in ports:
        return "HTTP"
    if 22 in ports:
        return "SSH"
    if 123 in ports:
        return "NTP"
    if 25 in ports or 587 in ports:
        return "SMTP"
    if 110 in ports:
        return "POP3"
    if 143 in ports:
        return "IMAP"
    return protocol


def _endpoint(address: str, port: int | None) -> str:
    if port is None:
        return address
    if ":" in address:
        return f"[{address}]:{port}"
    return f"{address}:{port}"


def _dns_details(payload: bytes) -> dict[str, Any]:
    if len(payload) < 12:
        return {}
    transaction_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", payload[:12])
    response = bool(flags & 0x8000)
    rcode = flags & 0x000F
    result: dict[str, Any] = {
        "dns_transaction_id": transaction_id,
        "dns_response": response,
        "dns_rcode": rcode,
        "dns_questions": qdcount,
        "dns_answers": ancount,
    }
    if response and rcode:
        result["status"] = "dns-error"
        result["severity"] = "medium"
        result["message"] = f"DNS response error code {rcode}"
    elif response:
        result["status"] = "response"
        result["message"] = f"DNS response with {ancount} answer(s)"
    else:
        result["status"] = "query"
        result["message"] = "DNS query observed"
    return result


def _transport_event(
    timestamp: str,
    source_ip: str,
    destination_ip: str,
    protocol_number: int,
    payload: bytes,
) -> dict[str, Any] | None:
    if protocol_number == 6 and len(payload) >= 20:  # TCP
        source_port, destination_port = struct.unpack("!HH", payload[:4])
        data_offset = ((payload[12] >> 4) & 0x0F) * 4
        flags = payload[13]
        tcp_payload = payload[data_offset:] if data_offset >= 20 and data_offset <= len(payload) else b""
        status = "observed"
        severity = "info"
        message = "TCP segment observed"
        if flags & 0x04:
            status = "reset"
            severity = "high"
            message = "TCP reset (RST) observed"
        elif flags & 0x02 and not flags & 0x10:
            status = "syn"
            message = "TCP connection attempt"
        elif flags & 0x01:
            status = "fin"
            message = "TCP connection close"
        service = _service_name("TCP", source_port, destination_port)
        event: dict[str, Any] = {
            "timestamp": timestamp,
            "type": service if service != "TCP" else "TCP",
            "service": service,
            "protocol": "TCP",
            "status": status,
            "severity": severity,
            "source": _endpoint(source_ip, source_port),
            "target": _endpoint(destination_ip, destination_port),
            "source_ip": source_ip,
            "target_ip": destination_ip,
            "source_port": source_port,
            "target_port": destination_port,
            "message": message,
        }
        if service == "DNS":
            event.update(_dns_details(tcp_payload[2:] if len(tcp_payload) >= 2 else tcp_payload))
        return event

    if protocol_number == 17 and len(payload) >= 8:  # UDP
        source_port, destination_port, length, _ = struct.unpack("!HHHH", payload[:8])
        udp_payload = payload[8:min(len(payload), length)] if length >= 8 else payload[8:]
        service = _service_name("UDP", source_port, destination_port)
        event = {
            "timestamp": timestamp,
            "type": service if service != "UDP" else "UDP",
            "service": service,
            "protocol": "UDP",
            "status": "observed",
            "severity": "info",
            "source": _endpoint(source_ip, source_port),
            "target": _endpoint(destination_ip, destination_port),
            "source_ip": source_ip,
            "target_ip": destination_ip,
            "source_port": source_port,
            "target_port": destination_port,
            "message": "UDP datagram observed",
        }
        if service == "DNS":
            event.update(_dns_details(udp_payload))
        elif service == "DHCP":
            event["status"] = "dhcp-traffic"
            event["message"] = "DHCP exchange observed"
        return event

    if protocol_number == 1 and len(payload) >= 4:  # ICMPv4
        icmp_type, code = payload[0], payload[1]
        status = "observed"
        severity = "info"
        message = f"ICMP type {icmp_type} code {code}"
        if icmp_type == 3:
            status = "unreachable"
            severity = "high"
            message = f"ICMP destination unreachable (code {code})"
        return {
            "timestamp": timestamp,
            "type": "ICMP",
            "service": "ICMP",
            "protocol": "ICMP",
            "status": status,
            "severity": severity,
            "source": source_ip,
            "target": destination_ip,
            "source_ip": source_ip,
            "target_ip": destination_ip,
            "message": message,
        }

    if protocol_number == 58 and len(payload) >= 4:  # ICMPv6
        icmp_type, code = payload[0], payload[1]
        status = "unreachable" if icmp_type == 1 else "observed"
        severity = "high" if status == "unreachable" else "info"
        return {
            "timestamp": timestamp,
            "type": "ICMPv6",
            "service": "ICMPv6",
            "protocol": "ICMPv6",
            "status": status,
            "severity": severity,
            "source": source_ip,
            "target": destination_ip,
            "source_ip": source_ip,
            "target_ip": destination_ip,
            "message": f"ICMPv6 type {icmp_type} code {code}",
        }
    return None


def _decode_ip_packet(timestamp: str, packet: bytes) -> dict[str, Any] | None:
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4 and len(packet) >= 20:
        ihl = (packet[0] & 0x0F) * 4
        if ihl < 20 or len(packet) < ihl:
            return None
        protocol = packet[9]
        source_ip = str(ipaddress.IPv4Address(packet[12:16]))
        destination_ip = str(ipaddress.IPv4Address(packet[16:20]))
        return _transport_event(timestamp, source_ip, destination_ip, protocol, packet[ihl:])

    if version == 6 and len(packet) >= 40:
        next_header = packet[6]
        source_ip = str(ipaddress.IPv6Address(packet[8:24]))
        destination_ip = str(ipaddress.IPv6Address(packet[24:40]))
        # Extension headers are intentionally not walked in this lightweight parser.
        return _transport_event(timestamp, source_ip, destination_ip, next_header, packet[40:])
    return None


def _decode_link_packet(timestamp: str, packet: bytes, link_type: int) -> dict[str, Any] | None:
    if link_type == 101:  # raw IP
        return _decode_ip_packet(timestamp, packet)
    if link_type != 1 or len(packet) < 14:  # Ethernet
        return None

    ethertype = struct.unpack("!H", packet[12:14])[0]
    offset = 14
    if ethertype in {0x8100, 0x88A8} and len(packet) >= 18:
        ethertype = struct.unpack("!H", packet[16:18])[0]
        offset = 18
    if ethertype not in {0x0800, 0x86DD}:
        return None
    return _decode_ip_packet(timestamp, packet[offset:])


def _infer_dns_timeouts(events: list[dict[str, Any]]) -> None:
    if not events:
        return
    try:
        capture_end = datetime.fromisoformat(events[-1]["timestamp"].replace("Z", "+00:00")).timestamp()
    except (KeyError, ValueError):
        return

    responses: set[tuple[str, str, int, int]] = set()
    queries: list[dict[str, Any]] = []
    for event in events:
        if event.get("service") != "DNS" or "dns_transaction_id" not in event:
            continue
        txid = int(event["dns_transaction_id"])
        source_ip = str(event.get("source_ip", ""))
        target_ip = str(event.get("target_ip", ""))
        source_port = int(event.get("source_port", 0) or 0)
        if event.get("dns_response"):
            responses.add((target_ip, source_ip, int(event.get("target_port", 0) or 0), txid))
        else:
            queries.append(event)

    inferred: list[dict[str, Any]] = []
    for query in queries:
        key = (
            str(query.get("source_ip", "")),
            str(query.get("target_ip", "")),
            int(query.get("source_port", 0) or 0),
            int(query.get("dns_transaction_id", 0)),
        )
        if key in responses:
            continue
        try:
            query_time = datetime.fromisoformat(str(query["timestamp"]).replace("Z", "+00:00")).timestamp()
        except (KeyError, ValueError):
            continue
        if capture_end - query_time < 1.0:
            continue
        timeout = dict(query)
        timeout["timestamp"] = datetime.fromtimestamp(query_time + 1.0, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        timeout["status"] = "timeout"
        timeout["severity"] = "medium"
        timeout["latency_ms"] = 1000
        timeout["message"] = "No matching DNS response observed within the capture window"
        timeout["inferred"] = True
        inferred.append(timeout)

    events.extend(inferred)
    events.sort(key=lambda item: item.get("timestamp", ""))


def parse_pcap(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if len(data) < 24:
        raise IngestError("PCAP file is too small to contain a valid global header.")

    magic = data[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic == b"\x0a\x0d\x0d\x0a":
        raise IngestError("PCAPNG is not supported yet. Save/export the capture as classic .pcap and upload it again.")
    if magic not in formats:
        raise IngestError("Unsupported capture format. ChronoNet currently accepts classic PCAP files.")

    endian, divisor = formats[magic]
    try:
        _, major, minor, _, _, snaplen, link_type = struct.unpack(f"{endian}IHHIIII", data[:24])
    except struct.error as exc:
        raise IngestError("Invalid PCAP global header.") from exc
    if major != 2:
        raise IngestError(f"Unsupported PCAP version {major}.{minor}.")
    if link_type not in {1, 101}:
        raise IngestError(f"Unsupported PCAP link type {link_type}. Use Ethernet or raw-IP captures.")

    offset = 24
    packets_total = 0
    decoded = 0
    captured_bytes = 0
    events: list[dict[str, Any]] = []
    protocols: Counter[str] = Counter()

    while offset + 16 <= len(data):
        try:
            ts_sec, ts_fraction, included_length, _ = struct.unpack(
                f"{endian}IIII", data[offset:offset + 16]
            )
        except struct.error:
            break
        offset += 16
        if included_length > snaplen or included_length > len(data) - offset:
            raise IngestError("PCAP packet record is truncated or has an invalid length.")
        packet = data[offset:offset + included_length]
        offset += included_length
        packets_total += 1
        captured_bytes += included_length
        timestamp = _iso_timestamp(ts_sec, ts_fraction, divisor)
        event = _decode_link_packet(timestamp, packet, link_type)
        if event:
            decoded += 1
            protocols[str(event.get("protocol", "OTHER"))] += 1
            events.append(event)

    _infer_dns_timeouts(events)
    unique_sources = sorted({str(event.get("source_ip")) for event in events if event.get("source_ip")})
    unique_destinations = sorted({str(event.get("target_ip")) for event in events if event.get("target_ip")})
    summary = {
        "format": "pcap",
        "packets_total": packets_total,
        "packets_decoded": decoded,
        "captured_bytes": captured_bytes,
        "protocols": dict(protocols),
        "unique_sources": len(unique_sources),
        "unique_destinations": len(unique_destinations),
        "link_type": "Ethernet" if link_type == 1 else "Raw IP",
    }
    return events, summary


def _normalise_event(event: dict[str, Any], index: int) -> dict[str, Any]:
    cleaned = {str(key): value for key, value in event.items()}
    if not cleaned.get("timestamp"):
        cleaned["timestamp"] = datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
    cleaned.setdefault("type", cleaned.get("service", "event"))
    cleaned.setdefault("service", cleaned.get("type", "event"))
    cleaned.setdefault("status", "observed")
    cleaned.setdefault("severity", "info")
    cleaned.setdefault("source", f"event-{index + 1}")
    cleaned.setdefault("target", "unknown")
    cleaned.setdefault("message", "Imported network event")
    return cleaned


def parse_json_events(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    try:
        payload = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IngestError("The JSON file is not valid UTF-8 JSON.") from exc
    if isinstance(payload, dict):
        raw_events = payload.get("events")
    else:
        raw_events = payload
    if not isinstance(raw_events, list):
        raise IngestError('JSON must be an event array or an object containing an "events" array.')
    events = [_normalise_event(event, index) for index, event in enumerate(raw_events) if isinstance(event, dict)]
    return events, {"format": "json", "records": len(events)}


def parse_jsonl_events(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestError("The JSONL file must be UTF-8 text.") from exc
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise IngestError(f"Invalid JSON on line {line_number}.") from exc
        if not isinstance(item, dict):
            raise IngestError(f"JSONL line {line_number} must contain an object.")
        events.append(_normalise_event(item, len(events)))
    return events, {"format": "jsonl", "records": len(events)}


def parse_csv_events(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestError("The CSV file must be UTF-8 text.") from exc
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise IngestError("CSV file has no header row.")
    events = [_normalise_event(dict(row), index) for index, row in enumerate(reader)]
    return events, {"format": "csv", "records": len(events), "columns": reader.fieldnames}


def parse_upload(data: bytes, filename: str) -> dict[str, Any]:
    if not data:
        raise IngestError("The uploaded file is empty.")
    suffix = Path(filename).suffix.lower()
    if suffix == ".pcap":
        events, capture = parse_pcap(data)
    elif suffix == ".json":
        events, capture = parse_json_events(data)
    elif suffix in {".jsonl", ".ndjson"}:
        events, capture = parse_jsonl_events(data)
    elif suffix == ".csv":
        events, capture = parse_csv_events(data)
    elif suffix == ".pcapng":
        raise IngestError("PCAPNG is not supported yet. Export it as classic PCAP first.")
    else:
        raise IngestError("Unsupported file type. Use .pcap, .json, .jsonl, .ndjson, or .csv.")

    if not events:
        raise IngestError("The file was readable, but no supported network events were found.")
    if len(events) > 50_000:
        events = events[:50_000]
        capture["truncated"] = True
    capture["filename"] = Path(filename).name
    capture["event_records"] = len(events)
    return {"events": events, "capture": capture}
