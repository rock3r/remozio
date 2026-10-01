#!/usr/bin/env python3
"""Measure execution binding with disposable, unprivileged fixtures on Apple Silicon."""
import datetime
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile


FIXTURE = r'''#include <stdio.h>
#include <mach-o/dyld.h>
#ifndef MARKER
#define MARKER "original"
#endif
int main(int argc, char **argv) {
    char path[4096]; uint32_t size = sizeof(path);
    printf("marker=%s\nargv0=%s\n", MARKER, argv[0]);
    if (_NSGetExecutablePath(path, &size) == 0) printf("executable=%s\n", path);
    return 0;
}
'''
API_PROBE = '''#include <unistd.h>
int main(void) {
    char *args[] = {"fixture", 0};
    char *env[] = {0};
    return fexecve(3, args, env);
}
'''


def command(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=60).stdout.strip()


def run_fixture(label, executable, argv, root, descriptor=None):
    try:
        result = subprocess.run(
            argv, executable=str(executable), pass_fds=() if descriptor is None else (descriptor,),
            capture_output=True, text=True, timeout=5, env={"PATH": "/usr/bin:/bin"},
        )
    except OSError as error:
        return {"case": label, "launchErrno": error.errno}
    return {
        "case": label, "exit": result.returncode,
        "stdout": result.stdout.replace(str(root), "<fixture>"),
        "stderr": result.stderr.replace(str(root), "<fixture>"),
    }


def measure():
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("This experiment requires an Apple Silicon Mac")
    host = {
        "os": command(["sw_vers", "-productVersion"]),
        "build": command(["sw_vers", "-buildVersion"]),
        "architecture": platform.machine(),
        "xcode": command(["xcodebuild", "-version"]),
        "sdk": command(["xcrun", "--sdk", "macosx", "--show-sdk-version"]),
        "deploymentTarget": "26.0",
    }
    with tempfile.TemporaryDirectory(prefix="remozio-execution-") as directory:
        root = Path(directory)
        source = root / "fixture.c"
        source.write_text(FIXTURE)
        original = root / "program"
        replacement = root / "replacement"
        for path, marker in [(original, "original"), (replacement, "replacement")]:
            command(["xcrun", "clang", "-arch", "arm64", "-mmacosx-version-min=26.0",
                     f'-DMARKER="{marker}"', str(source), "-o", str(path)])
        observations = []
        with original.open("rb") as retained:
            descriptor = retained.fileno()
            alias = f"/dev/fd/{descriptor}"
            observations.append(run_fixture("path-before", original, [str(original)], root))
            observations.append(run_fixture("descriptor-before", alias, [str(original)], root, descriptor))
            expected, actual = os.fstat(descriptor), original.stat()
            same_identity = (expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino)
            if not same_identity:
                raise RuntimeError("Fixture identity did not match before replacement")
            original.rename(root / "held-original")
            replacement.rename(original)
            observations.append(run_fixture("path-after-replacement", original, [str(original)], root))
            observations.append(run_fixture("descriptor-after-replacement", alias, [str(original)], root, descriptor))
        if observations[0].get("exit") != 0 or "marker=original\n" not in observations[0].get("stdout", ""):
            raise RuntimeError("Original fixture did not execute correctly")
        if observations[2].get("exit") != 0 or "marker=replacement\n" not in observations[2].get("stdout", ""):
            raise RuntimeError("Replacement fixture did not execute correctly")

        script = root / "script"
        script.write_text('#!/bin/sh\nprintf "original-script:%s\\n" "$0"\n')
        script.chmod(0o700)
        with script.open("rb") as retained:
            descriptor = retained.fileno()
            alias = f"/dev/fd/{descriptor}"
            observations.append(run_fixture("script-descriptor-before", alias, [str(script)], root, descriptor))
            observations.append(run_fixture("explicit-interpreter-before", "/bin/sh", ["/bin/sh", alias], root, descriptor))
            script.write_text('#!/bin/sh\nprintf "changed-script:%s\\n" "$0"\n')
            observations.append(run_fixture("script-descriptor-after-inplace-write", alias, [str(script)], root, descriptor))
            observations.append(run_fixture("explicit-interpreter-after-inplace-write", "/bin/sh", ["/bin/sh", alias], root, descriptor))
            for row in observations:
                for key in ("stdout", "stderr"):
                    if key in row:
                        row[key] = row[key].replace(alias, "/dev/fd/<retained>")

        source.write_text(API_PROBE)
        probe = subprocess.run(
            ["xcrun", "clang", "-arch", "arm64", "-mmacosx-version-min=26.0",
             "-Werror=implicit-function-declaration", "-fsyntax-only", str(source)],
            capture_output=True, text=True, timeout=60,
        )
        if probe.returncode == 0:
            declared = True
        elif "undeclared function 'fexecve'" in probe.stderr:
            declared = False
        else:
            raise RuntimeError("Public API probe failed for an unexpected reason")
        return {
            "experiment": "execution-binding-v1", "host": host,
            "measuredAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "sameIdentityAtFinalCheck": same_identity, "publicHeaderDeclaresFexecve": declared,
            "observations": observations,
        }


if __name__ == "__main__":
    print(json.dumps(measure(), indent=2))
