#!/usr/bin/env python3
"""Exercise production dynamic validation with disposable, ad-hoc signed executables."""
import json
import os
from pathlib import Path
import plistlib
import re
import select
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
IDENTIFIER = "dev.remozio.self-probe"


def run(arguments, **kwargs):
    return subprocess.run(arguments, capture_output=True, text=True, timeout=120,
                          check=True, **kwargs)


def build(directory, generation):
    info = directory / f"Info-{generation}.plist"
    info.write_bytes(plistlib.dumps({"RemozioSecurityGeneration": str(generation)}))
    binary = directory / f"probe-{generation}"
    run(["xcrun", "swiftc", "-swift-version", "6", "-target",
         "arm64-apple-macosx26.0", str(ROOT / "macos/core/Sources/RemozioCore/DynamicCodeValidation.swift"),
         str(ROOT / "experiments/macos-self-code/main.swift"),
         "-Xlinker", "-sectcreate", "-Xlinker", "__TEXT", "-Xlinker", "__info_plist",
         "-Xlinker", str(info), "-o", str(binary)])
    run(["codesign", "--force", "--sign", "-", "--options", "runtime",
         "--identifier", IDENTIFIER, str(binary)])
    description = run(["codesign", "-d", "--verbose=4", str(binary)])
    match = re.search(r"^CDHash=([0-9a-f]{40})$", description.stderr, re.MULTILINE)
    if not match:
        raise RuntimeError("No CodeDirectory hash in the signed fixture")
    return binary, match.group(1)


def requirement(code_hash, generation, identifier=IDENTIFIER):
    return (f'identifier "{identifier}" and cdhash H"{code_hash}" '
            f'and info["RemozioSecurityGeneration"] = "{generation}"')


def check(binary, expression, accepted):
    result = subprocess.run([str(binary), expression], capture_output=True, text=True, timeout=15)
    expected = (0, "accepted") if accepted else (1, "rejected")
    if (result.returncode, result.stdout.strip()) != expected:
        raise RuntimeError(f"Unexpected probe result: {result.returncode}: {result.stdout!r} {result.stderr!r}")


def main():
    with tempfile.TemporaryDirectory(prefix="remozio-self-code-") as temporary:
        directory = Path(temporary)
        first, first_hash = build(directory, 4)
        replacement, replacement_hash = build(directory, 5)
        cases = [
            ("matching_identity", requirement(first_hash, 4), True),
            ("wrong_identifier", requirement(first_hash, 4, "dev.remozio.other"), False),
            ("wrong_hash", requirement("0" * 40, 4), False),
            ("wrong_generation", requirement(first_hash, 5), False),
            ("ad_hoc_is_not_apple_trusted", "anchor apple generic and " + requirement(first_hash, 4), False),
        ]
        for _, expression, accepted in cases:
            check(first, expression, accepted)
        process = subprocess.Popen([str(first), requirement(replacement_hash, 5), "wait"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            if not select.select([process.stdout], [], [], 15)[0] or process.stdout.readline() != b"ready\n":
                raise RuntimeError("The original process did not reach its validation barrier")
            os.rename(first, directory / "original-running")
            os.rename(replacement, first)
            output, errors = process.communicate(b"x", timeout=15)
            if process.returncode != 1 or output.strip() != b"rejected":
                raise RuntimeError(f"Replacement accepted or probe failed: {process.returncode}: {output!r} {errors!r}")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        print(json.dumps({"experiment": "dynamic_self_code", "passed":
                          [name for name, _, _ in cases] + ["path_replacement_rejected"]}))


if __name__ == "__main__":
    main()
