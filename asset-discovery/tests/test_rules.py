import unittest

from discovery.rules import connection_rule, dhcp_rule, software_rule


class RuleTests(unittest.TestCase):
    def test_unanswered_connection_is_target_only(self):
        result = connection_rule({
            "src_ip": "10.10.10.112", "dst_ip": "10.10.35.10", "src_port": 40000,
            "dst_port": 22, "transport": "tcp", "conn_state": "S0", "resp_pkts": 0,
            "resp_bytes": 0, "service_hints": [],
        })
        self.assertTrue(result["target_only"])
        self.assertFalse(result["service_supported"])

    def test_dhcp_request_is_not_assignment(self):
        result = dhcp_rule({
            "client_mac": "aa:bb:cc:dd:ee:ff", "requested_ip": "10.10.20.20",
            "assigned_ip": None, "hostname": None,
        })
        self.assertEqual(result["requested_ip"], "10.10.20.20")
        self.assertIsNone(result["assigned_ip"])
        self.assertFalse(result["assigned"])

    def test_software_roles_and_versions_are_unchanged(self):
        version = {"major": 1, "minor": 30, "minor2": 7}
        result = software_rule({
            "host_ip": "10.10.20.20", "host_port": 80, "software_type": "HTTP::SERVER",
            "software_name": "nginx", "version": version, "unparsed_version": "nginx/1.30.7",
        })
        self.assertEqual(result["role"], "server")
        self.assertEqual(result["version"], version)
        self.assertEqual(result["unparsed_version"], "nginx/1.30.7")


if __name__ == "__main__":
    unittest.main()
