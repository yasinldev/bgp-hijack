"""Offline validation of observed inventory; does not substitute for real lab tests."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lab


def inventory():
    result = {}
    for node, own, peer in (("dut", 7, 8), ("peer", 8, 7)):
        addresses = lab.ADDRESSES[node]
        result[node] = {
            "namespace": "net:" + node,
            "inspect": {"HostConfig": {"NetworkMode": "none", "PortBindings": {}},
                        "Image": "sha256:test", "NetworkSettings": {"Networks": {"none": {}}}},
            "links": [{"ifname": "lo"}, {"ifname": "eth1", "ifindex": own, "link_index": peer,
                                         "linkinfo": {"info_kind": "veth"}}],
            "addresses": [{"ifname": "eth1", "addr_info": [
                {"local": addresses[0], "prefixlen": 30, "scope": "global"},
                {"local": addresses[1], "prefixlen": 64, "scope": "global"},
                {"local": "fe80::1", "prefixlen": 64, "scope": "link"}]}],
            "routes4": [{"dst": "198.51.100.0/30", "dev": "eth1"}],
            "routes6": [{"dst": "2001:db8:2::/64", "dev": "eth1"}],
            "rules4": [{"table": "local", "src": "all"}, {"table": "main", "src": "all"}],
            "rules6": [{"table": "local", "src": "all"}, {"table": "main", "src": "all"}],
        }
    return result


class InventoryTests(unittest.TestCase):
    def test_closed_pair_and_pinned_topology(self):
        lab.validate_inventory(inventory(), "net:host", "sha256:test")
        lab.validate_topology(json.loads(lab.TOPOLOGY.read_text()), lab.versions())

    def test_rejects_unexpected_interfaces_defaults_and_external_routes(self):
        mutations = [
            ("links", {"ifname": "eth0"}),
            ("routes4", {"dst": "default", "gateway": "198.51.100.2", "dev": "eth1"}),
            ("routes6", {"dst": "default", "gateway": "2001:db8:2::2", "dev": "eth1"}),
            ("routes4", {"dst": "203.0.113.0/24", "dev": "eth1"}),
            ("rules4", {"table": 100, "src": "all"}),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                observed = inventory()
                observed["dut"][key].append(value)
                with self.assertRaises(lab.LabError):
                    lab.validate_inventory(observed, "net:host", "sha256:test")

    def test_rejects_namespace_image_network_and_peer_mismatches(self):
        for mode in ("host_namespace", "shared_namespace", "image", "network", "port", "pair", "address"):
            observed = inventory()
            node = observed["dut"]
            if mode == "host_namespace": node["namespace"] = "net:host"
            if mode == "shared_namespace": node["namespace"] = observed["peer"]["namespace"]
            if mode == "image": node["inspect"]["Image"] = "other"
            if mode == "network": node["inspect"]["NetworkSettings"]["Networks"]["bridge"] = {}
            if mode == "port": node["inspect"]["HostConfig"]["PortBindings"] = {"179/tcp": [{}]}
            if mode == "pair": node["links"][1]["link_index"] = 999
            if mode == "address": node["addresses"][0]["addr_info"][0]["local"] = "8.8.8.8"
            with self.subTest(mode=mode), self.assertRaises(lab.LabError):
                lab.validate_inventory(observed, "net:host", "sha256:test")

    def test_foreign_containers_are_never_owned(self):
        owned = {lab.container("dut"): {"Config": {"Labels": {"containerlab": lab.NAME, "bgp-hijack.fixture": lab.LABEL}}}}
        lab.require_owned(owned)
        for label in ("containerlab", "bgp-hijack.fixture"):
            foreign = copy.deepcopy(owned)
            del foreign[lab.container("dut")]["Config"]["Labels"][label]
            with self.assertRaises(lab.LabError): lab.require_owned(foreign)

    def test_topology_rejects_host_mode_external_links_and_image_changes(self):
        good = json.loads(lab.TOPOLOGY.read_text())
        for field, value in (("network-mode", "host"), ("image", "image:latest")):
            changed = copy.deepcopy(good)
            changed["topology"]["defaults"][field] = value
            with self.assertRaises(lab.LabError): lab.validate_topology(changed, lab.versions())
        changed = copy.deepcopy(good)
        changed["topology"]["links"].append({"endpoints": ["dut:eth2", "host:outside"]})
        with self.assertRaises(lab.LabError): lab.validate_topology(changed, lab.versions())


if __name__ == "__main__":
    unittest.main()
