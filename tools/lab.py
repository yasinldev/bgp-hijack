#!/usr/bin/env python3
"""Explicit lifecycle for the closed, two-node Sprint 2 developer fixture."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "lab/s02"
TOPOLOGY = FIXTURE / "topology.clab.yml"
CLAB = ROOT / ".cache/tools/containerlab"
WORKDIR = ROOT / ".cache/labs"
NAME = "bgp-codec-s02"
LABEL = "bgp-codec-s02-v1"
NODES = ("dut", "peer")
ADDRESSES = {"dut": ("198.51.100.1", "2001:db8:2::1"), "peer": ("198.51.100.2", "2001:db8:2::2")}


class LabError(RuntimeError):
    pass


def command(args, timeout=30, cwd=None):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True,
                            timeout=timeout, cwd=cwd or ROOT)
    if result.returncode:
        raise LabError(f"{' '.join(map(str, args))}: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def privileged(args, **kwargs):
    return command(["sudo", "-n", *args], **kwargs)


def docker(*args, **kwargs):
    return privileged(["docker", "--host", "unix:///var/run/docker.sock", *args], **kwargs)


def container(node):
    return f"clab-{NAME}-{node}"


def versions():
    return json.loads((FIXTURE / "versions.json").read_text())


def validate_topology(topology, pins):
    expected = {
        "name": NAME, "mgmt": {"skip-when-unused": True},
        "topology": {
            "defaults": {"kind": "linux", "image": pins["frr_image"], "network-mode": "none",
                         "restart-policy": "no", "labels": {"bgp-hijack.fixture": LABEL},
                         "sysctls": {"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"}},
            "nodes": {node: {"binds": [f"{node}.conf:/etc/frr/frr.conf:ro", f"{node}.daemons:/etc/frr/daemons:ro"]}
                      for node in NODES},
            "links": [{"endpoints": ["dut:eth1", "peer:eth1"]}]}}
    if topology != expected:
        raise LabError("fixture differs from the closed two-node topology contract")


def check_tools():
    for tool in ("sudo", "docker", "ip", "nsenter", "readlink", "ping", "ss"):
        if not shutil.which(tool):
            raise LabError(f"missing host prerequisite: {tool}")
    pins = versions()
    validate_topology(json.loads(TOPOLOGY.read_text()), pins)
    if not CLAB.exists():
        raise LabError("run python3 tools/prepare_lab.py before lab operations")
    metadata = json.loads(CLAB.with_suffix(".json").read_text())
    if metadata["containerlab_archive_sha256"] != pins["containerlab_archive_sha256"]:
        raise LabError("cached Containerlab release does not match the fixture")
    if hashlib.sha256(CLAB.read_bytes()).hexdigest() != pins["containerlab_binary_sha256"]:
        raise LabError("cached Containerlab binary checksum mismatch")
    installed = command([CLAB, "version"])
    if pins["containerlab_version"] not in installed:
        raise LabError("Containerlab version mismatch")
    return pins


def preflight():
    pins = check_tools()
    privileged(["true"])
    server = json.loads(docker("version", "--format", "{{json .Server}}"))
    image = json.loads(docker("image", "inspect", pins["frr_image"]))[0]
    return {"pins": pins, "docker_server": server, "image_id": image["Id"]}


def existing():
    ids = docker("ps", "-aq").split()
    if not ids:
        return {}
    found = {}
    for item in json.loads(docker("inspect", *ids)):
        name = item["Name"].lstrip("/")
        if name in [container(node) for node in NODES]:
            found[name] = item
    return found


def require_owned(items):
    for name, item in items.items():
        labels = item.get("Config", {}).get("Labels") or {}
        if labels.get("bgp-hijack.fixture") != LABEL or labels.get("containerlab") != NAME:
            raise LabError(f"refusing to modify an unowned container: {name}")


def collect_node(node, item):
    pid = item["State"]["Pid"]
    if not item["State"]["Running"] or pid <= 0:
        raise LabError(f"{node} is not running")
    prefix = ["nsenter", "-t", str(pid), "-n"]
    def ip(*args):
        return json.loads(privileged([*prefix, "ip", "-j", *args]))
    return {"inspect": item, "namespace": privileged(["readlink", f"/proc/{pid}/ns/net"]).strip(),
            "links": ip("-d", "link", "show"), "addresses": ip("address", "show"),
            "routes4": ip("-4", "route", "show", "table", "all"),
            "routes6": ip("-6", "route", "show", "table", "all"),
            "rules4": ip("-4", "rule", "show"), "rules6": ip("-6", "rule", "show")}


def validate_inventory(inventory, host_namespace, image_id):
    if set(inventory) != set(NODES):
        raise LabError("both declared nodes must be present")
    namespaces = {node["namespace"] for node in inventory.values()}
    if len(namespaces) != 2 or host_namespace in namespaces:
        raise LabError("lab nodes must have distinct non-host network namespaces")
    veths = {}
    allowed4 = [ipaddress.ip_network(net) for net in ("127.0.0.0/8", "198.51.100.0/30")]
    allowed6 = [ipaddress.ip_network(net) for net in ("::1/128", "fe80::/10", "ff00::/8", "2001:db8:2::/64")]
    for node, data in inventory.items():
        item = data["inspect"]
        if item["HostConfig"]["NetworkMode"] != "none" or item["Image"] != image_id:
            raise LabError(f"{node}: unexpected network mode or image")
        if set(item["NetworkSettings"]["Networks"]) - {"none"}:
            raise LabError(f"{node}: unexpected Docker network attachment")
        if item["HostConfig"].get("PortBindings"):
            raise LabError(f"{node}: published ports are not allowed")
        links = {link["ifname"]: link for link in data["links"]}
        if set(links) != {"lo", "eth1"} or links["eth1"].get("linkinfo", {}).get("info_kind") != "veth":
            raise LabError(f"{node}: unexpected interface inventory")
        veths[node] = links["eth1"]
        addresses = {entry["ifname"]: entry for entry in data["addresses"]}
        actual = {(addr["local"], addr["prefixlen"]) for addr in addresses["eth1"]["addr_info"]
                  if addr["scope"] == "global"}
        expected = {(ADDRESSES[node][0], 30), (ADDRESSES[node][1], 64)}
        if actual != expected:
            raise LabError(f"{node}: lab addresses differ from the fixture")
        for key, allowed in (("routes4", allowed4), ("routes6", allowed6)):
            for route in data[key]:
                destination = route.get("dst", "default")
                if destination == "default":
                    raise LabError(f"{node}: default route is forbidden")
                network = ipaddress.ip_network(destination, strict=False)
                if not any(network.subnet_of(parent) for parent in allowed):
                    raise LabError(f"{node}: route leaves the fixture: {destination}")
                if route.get("gateway") or route.get("nexthops") or route.get("dev") not in ("lo", "eth1"):
                    raise LabError(f"{node}: unexpected forwarding route")
        for key in ("rules4", "rules6"):
            if any(rule.get("table") not in ("local", "main", "default", 255, 254, 253)
                   or rule.get("src", "all") != "all" or rule.get("dst", "all") != "all"
                   or rule.get("fwmark") or rule.get("iif") or rule.get("oif") or rule.get("action") in ("goto", "nat")
                   for rule in data[key]):
                raise LabError(f"{node}: unexpected policy routing rule")
    for node, other in (("dut", "peer"), ("peer", "dut")):
        if veths[node].get("link_index") != veths[other]["ifindex"]:
            raise LabError("lab veth endpoints do not form the declared pair")


def verify():
    ready = preflight()
    items = existing()
    require_owned(items)
    if set(items) != {container(node) for node in NODES}:
        raise LabError("the fixture is not fully deployed")
    inventory = {node: collect_node(node, items[container(node)]) for node in NODES}
    validate_inventory(inventory, os.readlink("/proc/self/ns/net"), ready["image_id"])
    observations = {}
    for node, other in (("dut", "peer"), ("peer", "dut")):
        pid = items[container(node)]["State"]["Pid"]
        prefix = ["nsenter", "-t", str(pid), "-n"]
        observations[node] = {
            "ipv4_ping": privileged([*prefix, "ping", "-4", "-I", "eth1", "-c", "2", "-W", "2", ADDRESSES[other][0]]),
            "ipv6_ping": privileged([*prefix, "ping", "-6", "-I", "eth1", "-c", "2", "-W", "2", ADDRESSES[other][1]])}
        listeners = privileged([*prefix, "ss", "-H", "-lnt", "sport", "=", ":179"])
        if bool(listeners.strip()) != (node == "peer"):
            raise LabError(f"{node}: unexpected BGP listener state")
        observations[node]["bgp_listeners"] = listeners
    version = docker("exec", container("peer"), "vtysh", "-c", "show version")
    if ready["pins"]["frr_version"] not in version:
        raise LabError("FRR runtime version mismatch")
    observations["frr_version"] = version
    observations["bgp_summary"] = json.loads(docker("exec", container("peer"), "vtysh", "-c", "show bgp summary json"))
    return {**ready, "inventory": inventory, "observations": observations}


def down():
    check_tools()
    items = existing()
    require_owned(items)
    if items:
        WORKDIR.mkdir(parents=True, exist_ok=True)
        privileged([CLAB, "destroy", "--topo", TOPOLOGY, "--cleanup"], cwd=WORKDIR, timeout=90)
    remaining = existing()
    namespaces = [container(node) for node in NODES if Path("/run/netns", container(node)).exists()]
    if remaining or namespaces:
        raise LabError("fixture cleanup left containers or network namespace handles")
    return {"remaining_containers": [], "remaining_namespaces": []}


def up():
    preflight()
    if existing():
        raise LabError("fixture container names already exist; use down before a fresh deployment")
    WORKDIR.mkdir(parents=True, exist_ok=True)
    try:
        privileged([CLAB, "deploy", "--topo", TOPOLOGY], cwd=WORKDIR, timeout=90)
        deadline = time.monotonic() + 30
        while True:
            try:
                return verify()
            except LabError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)
    except BaseException as error:
        try:
            down()
        except Exception as cleanup:
            raise LabError(f"deployment failed: {error}; cleanup also failed: {cleanup}") from error
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "up", "verify", "down"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = {"schema_version": 1, "fixture_id": LABEL, "action": args.action, "result": "failed"}
    code = 0
    try:
        result["evidence"] = globals()[args.action]()
        result["result"] = "passed"
    except (OSError, ValueError, KeyError, LabError, subprocess.SubprocessError) as error:
        result["error"] = str(error)
        code = 2
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        with args.output.open("x") as output:
            output.write(text)
    print(text, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
