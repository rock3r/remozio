#!/usr/bin/env python3
"""Build the actual child and inspect fixed frames. Never request elevation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "experiments/production-child"
NATIVE = ROOT / "macos/core/Sources/RemozioMach"
SOURCES = {
    "probe": [EXPERIMENT / "probe.c", NATIVE / "CommandAccountCredentials.c", NATIVE / "CommandMonitor.c", NATIVE / "CommandChildSpecification.c", NATIVE / "CommandMonitorProtocol.c"],
    "monitor": [ROOT / "macos/app/CommandMonitor/MonitorMain.c", NATIVE / "CommandProcess.c", NATIVE / "CommandChildSpecification.c", NATIVE / "CommandMonitorProtocol.c"],
    "child": [ROOT / "macos/app/CommandChild/ChildMain.c", NATIVE / "CommandAccountCredentials.c", NATIVE / "CommandChildSpecification.c"],
    "target": [EXPERIMENT / "target.c"],
}


def source_hashes():
    paths = {Path(__file__).resolve(), EXPERIMENT / "result.h", EXPERIMENT / "owner-controls.c"}
    paths.update(path for group in SOURCES.values() for path in group)
    paths.update((NATIVE / "include").glob("*.h"))
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(paths)}


def administrator_command(directory, binaries, uid):
    """Freeze the protected copies before execution. Failure retains the directory."""
    if type(uid) is not int or not 0 < uid < 2**32 - 1 or set(binaries) != set(SOURCES):
        raise ValueError("Invalid fixed experiment inputs")
    lines = ["set -eu", 'work=$(/usr/bin/mktemp -d /private/var/tmp/remozio-production-child.XXXXXXXX)',
             '/usr/sbin/chown 0:0 "$work"', '/bin/chmod 0755 "$work"',
             'echo "Disposable experiment directory: $work" >&2']
    for name, evidence in sorted(binaries.items()):
        digest = evidence["sha256"]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Invalid executable hash")
        source = shlex.quote(str(directory / name))
        lines.extend([f'/bin/cp {source} "$work/{name}"', f'/usr/sbin/chown 0:0 "$work/{name}"',
                      f'/bin/chmod 0555 "$work/{name}"',
                      f'actual=$(/usr/bin/shasum -a 256 "$work/{name}")',
                      f'[ "$actual" = "{digest}  $work/{name}" ]'])
    lines.extend([f'"$work/probe" --privileged-controls {uid}',
                  '/bin/rm "$work/probe" "$work/monitor" "$work/child" "$work/target"', '/bin/rmdir "$work"'])
    return "\n".join(lines) + "\n"


def prepare(directory):
    before = source_hashes()
    for name, sources in SOURCES.items():
        subprocess.run(["xcrun", "clang", "-target", "arm64-apple-macos26.0", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-I", str(NATIVE / "include"), "-I", str(EXPERIMENT), *(str(p) for p in sources),
                        "-o", str(directory / name)], check=True, timeout=120)
    controls = directory / "owner-controls"
    subprocess.run(["xcrun", "clang", "-target", "arm64-apple-macos26.0", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-DREMOZIO_PRODUCTION_CHILD_OWNER_FIXTURE=1", "-I", str(NATIVE / "include"), "-I", str(EXPERIMENT),
                    str(EXPERIMENT / "owner-controls.c"), str(NATIVE / "CommandAccountCredentials.c"),
                    str(NATIVE / "CommandChildSpecification.c"), "-o", str(controls)], check=True, timeout=120)
    owner = subprocess.run([str(controls)], check=True, capture_output=True, text=True, timeout=30)
    expected_owner = {"schemaVersion": 1, "ownerControls": 20, "privilegedControlsRun": False, "realProcessesSpawned": 0}
    if json.loads(owner.stdout) != expected_owner:
        raise RuntimeError("Unexpected owner control result")
    controls.unlink()
    if before != source_hashes():
        raise RuntimeError("Experiment sources changed during compilation")
    uid = os.getuid()
    inspect = subprocess.run([str(directory / "probe"), "--inspect", str(uid)], check=True,
                             capture_output=True, text=True, timeout=30)
    expected = {"schemaVersion": 1, "codecControls": 6, "privilegedControlsRun": False}
    if json.loads(inspect.stdout) != expected:
        raise RuntimeError("Unexpected ordinary frame inspection")
    for name in SOURCES:
        result = subprocess.run([str(directory / name)], capture_output=True, timeout=15)
        if result.returncode != 64 or result.stdout:
            raise RuntimeError(f"The {name} usage guard failed")
    refusal = subprocess.run([str(directory / "probe"), "--privileged-controls", str(uid)], capture_output=True, timeout=15)
    if refusal.returncode != 77 or refusal.stdout:
        raise RuntimeError("Ordinary account could invoke privileged controls")
    invalid = subprocess.run([str(directory / "probe"), "--inspect", str(2**32-1)], capture_output=True, timeout=15)
    if invalid.returncode != 64 or invalid.stdout:
        raise RuntimeError("Invalid account was accepted")
    binaries = {name: {"sha256": hashlib.sha256((directory / name).read_bytes()).hexdigest(),
                       "bytes": (directory / name).stat().st_size} for name in SOURCES}
    command = administrator_command(directory, binaries, uid)
    (directory / "administrator-command.txt").write_text(command)
    manifest = {"schemaVersion": 1, "hostMacOS": platform.mac_ver()[0], "hostArchitecture": platform.machine(),
                "sourceHashes": before, "executables": binaries, "ordinaryControls": expected,
                "ordinaryPrivilegedModeRefused": True, "invalidUIDRefused": True, "ownerControls": expected_owner,
                "privilegedControlsRun": False, "productionExecutionTested": False, "installedRemozio": False,
                "administratorCommandSHA256": hashlib.sha256(command.encode()).hexdigest()}
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-new-directory", type=Path)
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64" or os.getuid() == 0 or os.geteuid() == 0:
        raise RuntimeError("Run preparation as an ordinary account on an Apple Silicon Mac")
    if args.prepare_new_directory:
        directory = args.prepare_new_directory.absolute()
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        result = prepare(directory)
        print(json.dumps({"directory": str(directory), "manifest": str(directory / "manifest.json"),
                          "privilegedControlsRun": False, "productionExecutionTested": False,
                          "sourceCount": len(result["sourceHashes"])}, sort_keys=True))
    else:
        with tempfile.TemporaryDirectory(prefix="remozio-production-child-build-") as temporary:
            result = prepare(Path(temporary))
            print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
