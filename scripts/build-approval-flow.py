#!/usr/bin/env python3
"""Build the synthetic authority peer. This does not start it or install anything."""
from pathlib import Path
import shutil

from macos_build_checks import require, run

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / '.build' / 'approval-flow'
BUILD.mkdir(parents=True, exist_ok=True)
arguments = ('swift', 'build', '--package-path', str(ROOT / 'experiments/approval-flow'),
             '--triple', 'arm64-apple-macosx26.0')
result = run(*arguments, check=False)
log = BUILD / 'swift-build.log'
log.write_text(result.stdout + result.stderr)
require(result.returncode == 0, f'Approval peer build failed; see {log}')
binary_directory = Path(run(*arguments, '--show-bin-path').stdout.strip())
shutil.copy2(binary_directory / 'ApprovalFlowPeer', BUILD / 'ApprovalFlowPeer')
print('Synthetic approval peer built. No requests executed.')
