from __future__ import annotations

import json
import mimetypes
import os
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from chrononet.analyzer import analyze_events
from chrononet.report import build_markdown_report

ROOT = Path(__file__).resolve().parent
WEB_DIR = ROOT / "web"
SCENARIO_DIR = ROOT / "data" / "scenarios"

# Local development stays on 127.0.0.1:8765.
# Cloud platforms provide PORT; when PORT exists we bind publicly inside the container.
IS_HOSTED = bool(os.getenv("PORT") or os.getenv("RENDER"))
HOST = os.getenv("HOST", "0.0.0.0" if IS_HOSTED else "127.0.0.1")
PORT = int(os.getenv("PORT", "8765"))


def load_scenario(scenario_id: str) -> dict:
    safe_id = "".join(ch for ch in scenario_id if ch.isalnum() or ch in "-_")
    path = SCENARIO_DIR / f"{safe_id}.json"
    if not path.is_file():
        raise FileNotFoundError(safe_id)
    return json.loads(path.read_text(encoding="utf-8"))


def list_scenarios() -> list[dict]:
    scenarios = []
    for path in sorted(SCENARIO_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        scenarios.append({
            "id": data["id"],
            "name": data["name"],
            "description": data.get("description", ""),
            "category": data.get("category", "incident"),
            "event_count": len(data.get("events", [])),
        })
    return scenarios


class ChronoNetHandler(BaseHTTPRequestHandler):
    server_version = "ChronoNet/1.3"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[chrononet] {self.address_string()} - {fmt % args}")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._send(
            status,
            json.dumps(payload, indent=2).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)

        if path == "/api/health":
            return self._json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "service": "chrononet",
                    "version": "1.3.0",
                    "mode": "online" if IS_HOSTED else "local",
                },
            )
        if path == "/api/scenarios":
            return self._json(HTTPStatus.OK, {"scenarios": list_scenarios()})
        if path.startswith("/api/scenarios/"):
            rest = path.removeprefix("/api/scenarios/").strip("/")
            if rest.endswith("/report"):
                scenario_id = rest[:-7].strip("/")
                try:
                    scenario = load_scenario(scenario_id)
                except FileNotFoundError:
                    return self._json(HTTPStatus.NOT_FOUND, {"error": "scenario_not_found"})
                analysis = analyze_events(scenario.get("events", []))
                report = build_markdown_report(scenario, analysis)
                return self._send(
                    HTTPStatus.OK,
                    report.encode("utf-8"),
                    "text/markdown; charset=utf-8",
                )
            try:
                scenario = load_scenario(rest)
            except FileNotFoundError:
                return self._json(HTTPStatus.NOT_FOUND, {"error": "scenario_not_found"})
            scenario["analysis"] = analyze_events(scenario.get("events", []))
            return self._json(HTTPStatus.OK, scenario)

        relative = "index.html" if path in {"", "/"} else path.lstrip("/")
        candidate = (WEB_DIR / relative).resolve()
        if WEB_DIR.resolve() not in candidate.parents and candidate != WEB_DIR.resolve():
            return self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
        if not candidate.is_file():
            candidate = WEB_DIR / "index.html"
        mime, _ = mimetypes.guess_type(candidate.name)
        self._send(
            HTTPStatus.OK,
            candidate.read_bytes(),
            (mime or "application/octet-stream") + "; charset=utf-8",
        )

    def do_POST(self) -> None:
        if self.path != "/api/analyze":
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 2_000_000)
            payload = json.loads(self.rfile.read(length) or b"{}")
            events = payload.get("events", [])
            if not isinstance(events, list):
                raise ValueError("events must be a list")
            return self._json(HTTPStatus.OK, {"analysis": analyze_events(events)})
        except (json.JSONDecodeError, ValueError) as exc:
            return self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_payload", "detail": str(exc)},
            )


def main() -> None:
    port = PORT
    if len(sys.argv) > 1:
        port = int(sys.argv[1])

    server = ThreadingHTTPServer((HOST, port), ChronoNetHandler)
    mode = "ONLINE/HOSTED" if IS_HOSTED else "LOCAL"

    print("\nChronoNet — Network Incident Replay & Root-Cause Workbench")
    print(f"Mode: {mode}")
    if IS_HOSTED:
        print(f"Listening publicly on {HOST}:{port}")
    else:
        print(f"Open: http://{HOST}:{port}")
    print("Press Ctrl+C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nChronoNet stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
