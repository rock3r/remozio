#!/usr/bin/env python3
"""Build and inspect the Mac app without launching it or registering services."""
from pathlib import Path
import plistlib
import os
import subprocess

from macos_build_checks import require, run, verify_executable

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / '.build' / 'macos-app'


def check(configuration):
    result = run('xcodebuild', '-project', str(ROOT / 'macos/app/Remozio.xcodeproj'),
                 '-scheme', 'Remozio', '-configuration', configuration,
                 '-destination', 'generic/platform=macOS', '-derivedDataPath', str(BUILD / 'DerivedData'),
                 'build', check=False)
    log = BUILD / f'xcodebuild-{configuration.lower()}.log'
    log.write_text(result.stdout + result.stderr)
    require(result.returncode == 0, f'Mac app build failed; see {log}')
    app = BUILD / f'DerivedData/Build/Products/{configuration}/Remozio.app'
    identity = 'dev.remozio.mac.debug' if configuration == 'Debug' else 'dev.remozio.mac'
    run('codesign', '--verify', '--deep', '--strict', str(app))
    verify_executable(app / 'Contents/MacOS/Remozio', identity)
    authority = app / 'Contents/Library/LaunchServices/RemozioAuthority'
    authority_identity = 'dev.remozio.authority.debug' if configuration == 'Debug' else 'dev.remozio.authority'
    require(authority.is_file(), 'Missing embedded authority executable')
    verify_executable(authority, authority_identity)
    run('codesign', '--verify', '--strict', '-R', '=info[RemozioSecurityGeneration] = "1"', str(authority))
    original = BUILD / f'DerivedData/Build/Products/{configuration}/RemozioAuthority'
    require(authority.read_bytes() == original.read_bytes(), 'Embedding changed the signed authority executable')
    usage = subprocess.run([str(authority)], text=True, capture_output=True, timeout=5)
    require(usage.returncode == 64 and 'Usage:' in usage.stderr, 'Authority must reject missing configuration')
    if os.geteuid() != 0:
        denied = subprocess.run([str(authority), '--configuration', '/nonexistent/remozio.cbor'],
                                text=True, capture_output=True, timeout=5)
        require(denied.returncode == 77, 'Authority must reject non-root startup before reading configuration')
    child = app / 'Contents/Helpers/RemozioCommandChild'
    child_identity = 'dev.remozio.command-child.debug' if configuration == 'Debug' else 'dev.remozio.command-child'
    require(child.is_file(), 'Missing embedded command child')
    verify_executable(child, child_identity)
    run('codesign', '--verify', '--strict', '-R', '=info[RemozioSecurityGeneration] = "1"', str(child))
    child_original = BUILD / f'DerivedData/Build/Products/{configuration}/RemozioCommandChild'
    require(child.read_bytes() == child_original.read_bytes(), 'Embedding changed the signed command child')
    require(subprocess.run([str(child)], timeout=5).returncode == 64, 'Command child must reject public command arguments')
    if os.geteuid() != 0:
        read_descriptor, write_descriptor = os.pipe()
        try:
            os.write(write_descriptor, b'unread command input'); os.close(write_descriptor); write_descriptor = -1
            denied_child = subprocess.run([str(child), '--execute'], stdin=read_descriptor, capture_output=True, timeout=5)
            require(denied_child.returncode == 77, 'Command child must require root before reading private data')
            require(os.read(read_descriptor, 64) == b'unread command input', 'Refused command child consumed stdin')
            require(not denied_child.stdout and not denied_child.stderr, 'Command child wrote to the command streams')
        finally:
            os.close(read_descriptor)
            if write_descriptor >= 0: os.close(write_descriptor)
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    require(info['CFBundleIdentifier'] == identity, 'Unexpected bundle identity')
    require(info['LSMinimumSystemVersion'] == '26.0', 'Unexpected deployment target')
    require(not info.get('LSUIElement', False), 'The app must remain reachable after hiding its menu item')
    strings = app / 'Contents/Resources/en.lproj/Localizable.strings'
    resources = plistlib.loads(run('plutil', '-convert', 'xml1', '-o', '-', str(strings)).stdout.encode())
    require(resources.get('This Mac is not configured') == 'This Mac is not configured', 'Missing application strings')
    require(not (app / 'Contents/Library/LaunchDaemons').exists(), 'Unexpected service manifests in the app scaffold')
    require(not (app / 'Contents/Library/LaunchAgents').exists(), 'Unexpected service manifests in the app scaffold')
    print(f'Mac app {configuration}: arm64, macOS 26, signature, runtime, resources, and bundle checks passed.')


if __name__ == '__main__':
    BUILD.mkdir(parents=True, exist_ok=True)
    for configuration in ('Debug', 'Release'):
        check(configuration)
