#!/usr/bin/env python3
"""Build and inspect the Mac app without launching it or registering services."""
from pathlib import Path
import plistlib

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
