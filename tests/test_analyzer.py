import json
import unittest
from pathlib import Path

from chrononet.analyzer import analyze_events

ROOT = Path(__file__).resolve().parents[1]


class AnalyzerTests(unittest.TestCase):
    def scenario(self, name: str):
        path = ROOT / "data" / "scenarios" / f"{name}.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_dns_scenario_detected(self):
        result = analyze_events(self.scenario("dns-storm")["events"])
        self.assertEqual(result["findings"][0]["key"], "dns-degradation")
        self.assertGreaterEqual(result["findings"][0]["confidence"], 80)

    def test_gateway_and_link_scenario_detected(self):
        result = analyze_events(self.scenario("gateway-flap")["events"])
        keys = {finding["key"] for finding in result["findings"]}
        self.assertIn("gateway-instability", keys)
        self.assertIn("link-flapping", keys)

    def test_dhcp_scenario_detected(self):
        result = analyze_events(self.scenario("dhcp-pressure")["events"])
        self.assertEqual(result["findings"][0]["key"], "dhcp-pressure")

    def test_empty_input_is_safe(self):
        result = analyze_events([])
        self.assertEqual(result["health_score"], 100)
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
