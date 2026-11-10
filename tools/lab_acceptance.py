#!/usr/bin/env python3
"""Run two real fixture cycles and isolated negative tests; preserve all evidence."""
import argparse
import json
from pathlib import Path
import signal
import subprocess
import sys
import time

import lab


def reject_mutation(family, add, remove, expected):
    item = lab.existing()[lab.container("dut")]
    prefix = ["nsenter", "-t", str(item["State"]["Pid"]), "-n", "ip"]
    lab.privileged([*prefix, *add])
    try:
        try:
            lab.verify()
        except lab.LabError as error:
            if expected not in str(error):
                raise
            return {"case": family, "result": "passed", "expected_rejection": str(error)}
        raise lab.LabError(f"isolation checker accepted {family}")
    finally:
        lab.privileged([*prefix, *remove])


def run(output):
    output.mkdir(parents=True, exist_ok=False)
    summary = {"schema_version": 1, "fixture_id": lab.LABEL, "result": "failed",
               "complete": False, "cycles": []}
    start = time.monotonic()
    try:
        lab.check_tools()
        lab.privileged(["true"])
        if lab.existing():
            raise lab.LabError("fixture already exists; acceptance requires an unused fixture")
        print("Fetching pinned image before lab activation...", flush=True)
        lab.docker("pull", lab.versions()["frr_image"], timeout=180)
        summary["preflight"] = lab.preflight()
        for cycle in range(1, 3):
            print(f"Fixture cycle {cycle}/2", flush=True)
            entry = {"cycle": cycle}
            summary["cycles"].append(entry)
            try:
                entry["deployment"] = lab.up()
                entry["verification"] = lab.verify()
                entry["negative_tests"] = [
                    reject_mutation("unexpected_interface", ["link", "add", "s02-extra", "type", "dummy"],
                                    ["link", "del", "s02-extra"], "unexpected interface"),
                    reject_mutation("ipv4_default", ["-4", "route", "add", "default", "via", "198.51.100.2"],
                                    ["-4", "route", "del", "default"], "default route"),
                    reject_mutation("ipv6_default", ["-6", "route", "add", "default", "via", "2001:db8:2::2"],
                                    ["-6", "route", "del", "default"], "default route"),
                ]
                entry["restored_verification"] = lab.verify()
            finally:
                entry["cleanup"] = lab.down()
            entry["repeated_cleanup"] = lab.down()
        summary["result"] = "passed"
        summary["complete"] = True
    except (Exception, KeyboardInterrupt) as error:
        summary["error"] = str(error) or type(error).__name__
    finally:
        summary["elapsed_seconds"] = round(time.monotonic() - start, 3)
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"{summary['result']}: {output / 'summary.json'}")
    if summary.get("error"):
        print(summary["error"], file=sys.stderr)
    return 0 if summary["complete"] else 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("lab acceptance interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        raise SystemExit(run(args.output.resolve()))
    except (OSError, subprocess.SubprocessError) as error:
        parser.exit(2, f"error: {error}\n")
