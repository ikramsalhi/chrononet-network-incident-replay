import unittest

from app import list_scenarios, load_scenario


class AppDataTests(unittest.TestCase):
    def test_scenarios_are_available(self):
        scenarios = list_scenarios()
        self.assertGreaterEqual(len(scenarios), 3)

    def test_load_known_scenario(self):
        scenario = load_scenario("dns-storm")
        self.assertEqual(scenario["id"], "dns-storm")

    def test_path_like_id_cannot_escape_data_dir(self):
        with self.assertRaises(FileNotFoundError):
            load_scenario("../../README")


if __name__ == "__main__":
    unittest.main()
