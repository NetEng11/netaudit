import unittest

from netaudit.parser import parse_config
from netaudit.rules import audit

HARDENED = """
hostname sw-test
service password-encryption
enable secret 9 $9$EXAMPLE
ip ssh version 2
ntp server 192.0.2.10
logging host 192.0.2.50
banner motd ^CSolo personal autorizado^C
!
interface GigabitEthernet0/1
 description Uplink
 switchport mode trunk
 switchport trunk allowed vlan 10,20
!
line vty 0 15
 transport input ssh
!
"""


def ids(findings):
    return {f.rule_id for f in findings}


class ParserTests(unittest.TestCase):
    def test_hostname_and_blocks(self):
        cfg = parse_config(HARDENED)
        self.assertEqual(cfg.hostname, "sw-test")
        iface = cfg.blocks_starting("interface ")[0]
        self.assertTrue(iface.has_child("switchport mode trunk"))

    def test_bang_closes_block(self):
        cfg = parse_config("interface Gi0/1\n description a\n!\n description suelta\n")
        self.assertEqual(cfg.blocks_starting("interface ")[0].children, ["description a"])


class RuleTests(unittest.TestCase):
    def test_hardened_config_has_no_findings(self):
        self.assertEqual(audit(parse_config(HARDENED)), [])

    def test_telnet_on_vty_is_high(self):
        cfg = parse_config(HARDENED.replace("transport input ssh", "transport input ssh telnet"))
        found = [f for f in audit(cfg) if f.rule_id == "NA-001"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "high")

    def test_default_snmp_community_is_high(self):
        cfg = parse_config(HARDENED + "snmp-server community public RO\n")
        found = [f for f in audit(cfg) if f.rule_id == "NA-003"]
        self.assertEqual([f.severity for f in found], ["high"])

    def test_snmp_rw_with_custom_name_is_medium(self):
        cfg = parse_config(HARDENED + "snmp-server community Xk93-demo RW\n")
        found = [f for f in audit(cfg) if f.rule_id == "NA-003"]
        self.assertEqual([f.severity for f in found], ["medium"])

    def test_missing_enable_secret(self):
        cfg = parse_config(HARDENED.replace("enable secret 9 $9$EXAMPLE", "enable password abc"))
        self.assertIn("NA-002", ids(audit(cfg)))

    def test_trunk_without_allowed_vlans(self):
        cfg = parse_config(HARDENED.replace(" switchport trunk allowed vlan 10,20\n", ""))
        self.assertIn("NA-009", ids(audit(cfg)))

    def test_descriptions_ignore_shutdown_interfaces(self):
        extra = "interface GigabitEthernet0/9\n shutdown\n!\ninterface GigabitEthernet0/8\n switchport mode access\n!\n"
        findings = [f for f in audit(parse_config(HARDENED + extra)) if f.rule_id == "NA-010"]
        self.assertEqual(len(findings), 1)
        self.assertIn("GigabitEthernet0/8", findings[0].detail)
        self.assertNotIn("GigabitEthernet0/9", findings[0].detail)

    def test_findings_sorted_by_severity(self):
        findings = audit(parse_config("hostname x\n"))
        order = {"high": 0, "medium": 1, "low": 2}
        sev = [order[f.severity] for f in findings]
        self.assertEqual(sev, sorted(sev))


if __name__ == "__main__":
    unittest.main()
