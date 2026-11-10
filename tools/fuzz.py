#!/usr/bin/env python3
"""Build pinned fuzz targets and record bounded runs without changing seed fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
NIGHTLY = "nightly-2026-11-09"
CARGO_FUZZ = "0.13.2"
TARGETS = {"framing": 8192, "control_messages": 4096}


def completion(log, seconds):
    """Require libFuzzer's completion line, not merely a successful process exit."""
    matches = re.findall(r"Done (\d+) runs in (\d+) second", log)
    if not matches:
        raise RuntimeError("fuzzer did not record normal completion")
    executions, elapsed = map(int, matches[-1])
    if elapsed < seconds:
        raise RuntimeError("fuzzer stopped before the requested time budget")
    return {"executions": executions, "fuzzer_seconds": elapsed}


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {"schema_version": 1, "seed": args.seed, "seconds_per_target": args.seconds,
              "nightly": NIGHTLY, "cargo_fuzz": CARGO_FUZZ, "targets": [],
              "complete": False}
    summary = output / "summary.json"
    summary.write_text(json.dumps(result, indent=2) + "\n")
    env = dict(os.environ, RUSTUP_TOOLCHAIN=NIGHTLY)
    version = subprocess.check_output(["cargo", "fuzz", "--version"], env=env, text=True).strip()
    if version.split()[-1] != CARGO_FUZZ:
        raise RuntimeError(f"expected cargo-fuzz {CARGO_FUZZ}, got {version}")
    result["rustc"] = subprocess.check_output(["rustc", "-Vv"], env=env, text=True)
    fixture_path = ROOT / "crates/core/tests/fixtures/control-messages.json"
    fixtures = fixture_path.read_bytes()
    result["fixture_catalog_sha256"] = hashlib.sha256(fixtures).hexdigest()
    cases = json.loads(fixtures)
    names = [args.target] if args.target else list(TARGETS)
    lock = ROOT / "fuzz/Cargo.lock"
    lock_before = lock.read_bytes()
    result["lock_sha256"] = hashlib.sha256(lock_before).hexdigest()
    subprocess.run(["cargo", "metadata", "--manifest-path", str(ROOT / "fuzz/Cargo.toml"),
                    "--format-version", "1", "--locked"], cwd=ROOT, env=env,
                   stdout=subprocess.DEVNULL, check=True)
    subprocess.run(["cargo", "fuzz", "build", "--fuzz-dir", str(ROOT / "fuzz")],
                   cwd=ROOT, env=env, check=True)
    if lock.read_bytes() != lock_before:
        raise RuntimeError("fuzz build changed the dependency lockfile")
    for name in names:
        corpus = output / name / "corpus"
        artifacts = output / name / "failures"
        corpus.mkdir(parents=True)
        artifacts.mkdir()
        seed_hashes = {}
        for case in cases:
            data = bytes.fromhex(case["hex"])
            (corpus / case["name"]).write_bytes(data)
            seed_hashes[case["name"]] = hashlib.sha256(data).hexdigest()
        command = ["cargo", "fuzz", "run", "--fuzz-dir", str(ROOT / "fuzz"), name,
                   str(corpus), "--", f"-max_total_time={args.seconds}", f"-max_len={TARGETS[name]}",
                   "-timeout=2", "-rss_limit_mb=1024", f"-seed={args.seed}",
                   f"-artifact_prefix={artifacts}/"]
        start = time.monotonic()
        print(f"Running {name} for {args.seconds}s; log: {output / name / 'fuzz.log'}", flush=True)
        with (output / name / "fuzz.log").open("w") as log:
            completed = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        entry = {"name": name, "command": command, "seed_sha256": seed_hashes,
                 "elapsed_seconds": round(time.monotonic() - start, 3), "exit_code": completed.returncode,
                 "failure_artifacts": sorted(p.name for p in artifacts.iterdir())}
        result["targets"].append(entry)
        summary.write_text(json.dumps(result, indent=2) + "\n")
        if lock.read_bytes() != lock_before:
            raise RuntimeError("fuzz run changed the dependency lockfile")
        if completed.returncode:
            raise RuntimeError(f"{name} failed; preserved log and reproducers in {output / name}")
        entry.update(completion((output / name / "fuzz.log").read_text(), args.seconds))
        summary.write_text(json.dumps(result, indent=2) + "\n")
    result["complete"] = True
    summary.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Fuzz runs complete: {summary}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", choices=TARGETS)
    parser.add_argument("--seconds", type=int, default=600)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    if args.seconds <= 0 or args.seed <= 0:
        parser.error("seconds and seed must be positive")
    try:
        run(args)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(2, f"error: {error}\n")
