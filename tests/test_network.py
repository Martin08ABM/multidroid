import unittest
from multiinstance.network import plan, plan_many


class NetworkPlanTest(unittest.TestCase):
    def test_preview_avoids_routes_and_reserved_subnets(self):
        identifier = "0" * 32
        result = plan(identifier, ["default", "10.240.0.0/24"], [], [], ["10.240.1.0/24"])
        self.assertEqual(result["subnet"], "10.240.2.0/24")
        self.assertEqual(result["gateway"], "10.240.2.1")
        self.assertFalse(result["allocated"])
        self.assertFalse(result["nft_checked_on_host"])
        self.assertLessEqual(len(result["bridge"]), 15)

    def test_refuses_collisions_and_invalid_inputs(self):
        identifier = "a" * 32
        result = plan(identifier, [], [], [])
        for interfaces, macs, tables in (([result["bridge"]], [], []), ([], [result["mac"]], []), ([], [], [result["nft_table"]])):
            with self.assertRaises(ValueError):
                plan(identifier, [], interfaces, macs, reserved_tables=tables)
        with self.assertRaises(ValueError):
            plan("../bad", [], [], [])
        with self.assertRaises(ValueError):
            plan(identifier, ["10.0.0.0/8"], [], [])
        with self.assertRaises(ValueError):
            plan(identifier, ["not-a-route"], [], [])

    def test_batch_previews_distinct_networks_without_allocating(self):
        a, b = "a" * 32, "b" * 32
        results = plan_many([a, b], [], [], [])
        self.assertNotEqual(results[a]["subnet"], results[b]["subnet"])
        self.assertNotEqual(results[a]["bridge"], results[b]["bridge"])
        self.assertTrue(all(not item["allocated"] for item in results.values()))
        with self.assertRaises(ValueError):
            plan_many([a, a], [], [], [])
        with self.assertRaises(ValueError):
            plan_many([], [], [], [])

    def test_batch_rejects_shared_generated_bridge(self):
        with self.assertRaisesRegex(ValueError, "bridge"):
            plan_many(["a" * 32, "a" * 11 + "b" * 21], [], [], [])


if __name__ == "__main__":
    unittest.main()
