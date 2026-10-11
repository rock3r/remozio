#!/usr/bin/env python3
"""Run the anonymous presence wire fixture; never install or activate a service."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile

from macos_fixture_cleanup import retire_owned_tree

ROOT = Path(__file__).resolve().parents[1]


def run_fixture(arguments, environment, output):
    process = subprocess.Popen(arguments, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                               stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        return process.wait(timeout=300)
    finally:
        if process.poll() is None:
            retire_owned_tree(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True, help='Sanitized result file')
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64' or int(platform.mac_ver()[0].split('.')[0]) < 26:
        raise SystemExit('Requires Apple Silicon and macOS 26 or later.')
    with tempfile.TemporaryDirectory(prefix='remozio-presence-wire-') as directory:
        evidence = Path(directory) / 'evidence.json'
        log = Path(directory) / 'test.log'
        environment = os.environ.copy()
        environment['REMOZIO_PRESENCE_XPC_EVIDENCE'] = str(evidence)
        failure = None
        try:
            with log.open('w') as output:
                result = run_fixture(['swift', 'test', '--package-path', str(ROOT / 'macos/core'), '--triple', 'arm64-apple-macosx26.0',
                    '--filter', 'AuthorityPresenceXPCTests.testLiveAnonymousPresenceWireCommitsAndReconnectsInGuiSession'], environment, output)
            if result or not evidence.is_file():
                failure = 'failed or lacked a supported GUI session'
        except subprocess.TimeoutExpired:
            failure = 'timed out'
        except KeyboardInterrupt:
            failure = 'was interrupted'
        except Exception as error:
            failure = 'failed to run or clean up'
            with log.open('a') as output:
                output.write(f'Runner failure: {type(error).__name__}: {error}\n')
        if failure:
            # A headless-session skip does not provide live evidence. Keep failed diagnostics outside the temporary directory.
            with tempfile.NamedTemporaryFile(prefix='remozio-presence-wire-failure-', suffix='.log', delete=False) as retained:
                retained.write(log.read_bytes())
                diagnostic = retained.name
            raise SystemExit(f'Native presence fixture {failure}. Diagnostics: {diagnostic}')
        report = json.loads(evidence.read_text())
        required = ['guiSessionAvailable', 'testCodeHashRequirementApplied', 'kernelPeerCredentialsChecked',
            'invocationConnectionChecked', 'conflictReturnedCurrentState', 'lostReplyCommittedModeRecovered',
            'freshConnectionBinding', 'crossedConnectionMutationRejected', 'observerWithdrawnOnClose',
            'discardedPublicationRejected', 'freshPublicationAfterRejectionAccepted']
        if report.get('status') != 'passed' or not all(report.get(key) is True for key in required):
            raise SystemExit('Native presence fixture did not prove its required wire checks.')
        if any(report.get(key) is not False for key in ['installedRootAccountsTested', 'developerIDPolicyTested',
                'physicalPresenceSignalsTested', 'serviceInstalled', 'realApprovalIssued']):
            raise SystemExit('Unexpected installed or real-action claim in fixture evidence.')
        report['sourceCommit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        report['sourceWorktreeModified'] = bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=ROOT, text=True).strip())
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'status': 'passed', 'experiment': report['experiment'], 'evidence': str(args.evidence),
            'installedRootAccountsTested': False, 'developerIDPolicyTested': False}, sort_keys=True))


if __name__ == '__main__':
    main()
