#!/usr/bin/env python3
"""Crash a disposable native journal process; never dispatch a real action."""
import datetime
import json
import os
from pathlib import Path
import platform
import select
import shutil
import sqlite3
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "experiments/authority-journal"


def command(argv):
    return subprocess.run(argv, check=True, text=True, capture_output=True, timeout=120).stdout.strip()


def measure():
    if platform.system() != "Darwin" or platform.machine() != "arm64" or os.getuid() == 0:
        raise RuntimeError("Requires an unprivileged Apple Silicon Mac")
    build = ["swift", "build", "--package-path", str(PACKAGE), "--triple", "arm64-apple-macosx26.0"]
    command(build)
    binary = Path(command(build + ["--show-bin-path"])) / "authority-journal-experiment"
    observations = []

    def invoke(operation, directory, *args, expected=0):
        result = subprocess.run([str(binary), operation, str(directory), *args], capture_output=True,
                                text=True, timeout=20, env={"PATH": "/usr/bin:/bin"})
        if result.returncode != expected:
            raise AssertionError(f"{operation}: expected {expected}, got {result.returncode}: {result.stderr}")
        return result

    def inspect(directory):
        return json.loads(invoke("inspect", directory).stdout)

    def new(root, name):
        directory = root / name
        invoke("init", directory)
        return directory

    def pause(directory, request, phone):
        process = subprocess.Popen([str(binary), "consume", str(directory), request, phone, "--pause", "before-intent"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env={"PATH": "/usr/bin:/bin"})
        try:
            if not select.select([process.stdout], [], [], 20)[0] or process.stdout.readline().strip() != "paused:before-intent":
                raise AssertionError("Writer did not reach the pause")
        except BaseException:
            process.kill()
            process.communicate(timeout=10)
            raise
        return process

    with tempfile.TemporaryDirectory(prefix="remozio-journal-") as temporary:
        root = Path(temporary).resolve()
        request, phone, other_phone = (str(uuid.uuid4()) for _ in range(3))
        cases = {
            "before-intent": None, "after-intent": None, "after-audit-insert": None,
            "before-database-commit": None, "after-database-commit": "noDispatch",
            "after-checkpoint": "unknown", "before-simulated-dispatch": "unknown",
        }
        for boundary, expected in cases.items():
            directory = new(root, boundary)
            crashed = invoke("consume", directory, request, phone, "--crash", boundary, expected=86)
            assert "simulated-permit" not in crashed.stdout
            report = inspect(directory)
            outcomes = [row["outcome"] for row in report["records"]]
            assert outcomes == ([] if expected is None else [expected]), (boundary, report)
            assert report["sequence"] == (0 if expected is None else 2)
            assert inspect(directory) == report, "Recovery must be idempotent"
            if expected is not None:
                rejected = invoke("consume", directory, request, other_phone, expected=1)
                assert rejected.stderr.strip() == "duplicate"
                assert "simulated-permit" not in rejected.stdout
            observations.append({"case": "crash-" + boundary, "outcomes": outcomes, "sequence": report["sequence"]})

        for boundary in ["before-intent", "after-intent", "after-audit-insert", "before-database-commit", "after-database-commit", "after-checkpoint"]:
            directory = new(root, "recovery-" + boundary)
            invoke("consume", directory, request, phone, "--crash", "after-database-commit", expected=86)
            invoke("inspect", directory, "--crash", boundary, expected=86)
            report = inspect(directory)
            assert [row["outcome"] for row in report["records"]] == ["noDispatch"], (boundary, report)
            assert report["sequence"] == 2
            assert inspect(directory) == report
            observations.append({"case": "recovery-crash-" + boundary, "outcome": "noDispatch"})

        directory = new(root, "exclusive-writer")
        process = pause(directory, request, phone)
        try:
            competitor = invoke("consume", directory, request, other_phone, expected=1)
            assert competitor.stderr.strip() == "busy"
            output, error = process.communicate("x", timeout=20)
            assert process.returncode == 0, error
            assert output.count("simulated-permit") == 1
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
        report = inspect(directory)
        assert len(report["records"]) == 1 and report["records"][0]["phone"].lower() == phone
        assert report["records"][0]["outcome"] == "unknown"
        assert invoke("consume", directory, request, other_phone, expected=1).stderr.strip() == "duplicate"
        observations.append({"case": "competing-writers-and-replay", "winners": 1})

        for filename in ["writer.lock", "journal.sqlite"]:
            directory = new(root, "replace-" + filename)
            process = pause(directory, request, phone)
            try:
                path = directory / filename
                path.rename(directory / (filename + ".old"))
                if filename.endswith("sqlite"):
                    shutil.copyfile(directory / (filename + ".old"), path)
                else:
                    path.write_bytes(b"")
                path.chmod(0o600)
                output, error = process.communicate("x", timeout=20)
                assert process.returncode == 1 and error.strip() == "identityChanged", (output, error)
                assert "simulated-permit" not in output
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=10)
            observations.append({"case": "live-replacement-" + filename, "admission": "closed"})

        directory = new(root, "live-content-replacement")
        invoke("consume", directory, request, phone)
        process = pause(directory, str(uuid.uuid4()), phone)
        try:
            with sqlite3.connect(directory / "journal.sqlite") as db:
                db.execute("DELETE FROM consumptions")
                db.execute("DELETE FROM events")
            output, error = process.communicate("x", timeout=20)
            assert process.returncode == 1 and error.strip() == "inconsistent", (output, error)
            assert "simulated-permit" not in output
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
        observations.append({"case": "live-content-replacement", "admission": "closed"})

        for tamper in ["ledger-row", "audit-row", "old-checkpoint", "malformed-checkpoint", "missing-checkpoint"]:
            directory = new(root, tamper)
            original = (directory / "checkpoint.json").read_bytes()
            invoke("consume", directory, request, phone)
            if tamper in ("ledger-row", "audit-row"):
                with sqlite3.connect(directory / "journal.sqlite") as db:
                    db.execute("DELETE FROM " + ("consumptions" if tamper == "ledger-row" else "events"))
            elif tamper == "old-checkpoint":
                (directory / "checkpoint.json").write_bytes(original)
            elif tamper == "malformed-checkpoint":
                (directory / "checkpoint.json").write_text("{}")
            else:
                (directory / "checkpoint.json").unlink()
            result = invoke("inspect", directory, expected=1)
            assert "simulated-permit" not in result.stdout
            observations.append({"case": tamper, "admission": "closed"})

        # A complete consistent snapshot is deliberately indistinguishable without an external witness.
        directory = new(root, "whole-backup")
        saved = root / "saved"
        shutil.copytree(directory, saved)
        invoke("consume", directory, request, phone)
        for filename in ["journal.sqlite", "checkpoint.json"]:
            shutil.copyfile(saved / filename, directory / filename)
        report = inspect(directory)
        assert report["records"] == []
        observations.append({"case": "whole-backup-rollback", "detected": False, "securityBoundary": "whole-mac-backup-restore-excluded"})

    return {
        "experiment": "authority-journal-process-crash-v1", "measuredAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": {"os": command(["sw_vers", "-productVersion"]), "build": command(["sw_vers", "-buildVersion"]),
                 "architecture": platform.machine(), "sdk": command(["xcrun", "--sdk", "macosx", "--show-sdk-version"]),
                 "sqlite": report["sqlite"], "deploymentTarget": "26.0"},
        "observations": observations,
        "limitations": ["Synthetic metadata only; no real dispatch", "Process exits are not physical power loss",
                        "No protected root installation or independent rollback witness", "No production admission or target validation"],
    }


if __name__ == "__main__":
    print(json.dumps(measure(), indent=2))
