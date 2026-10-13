import copy
import importlib.util
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('bootstrap_experiment', ROOT / 'scripts/run-native-bootstrap-file-experiment.py')
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class NativeBootstrapEvidenceTests(unittest.TestCase):
    def report(self):
        rows = []
        for index, name in enumerate(('replace-existing-file', 'replace-missing-file', 'replace-existing-directory', 'replace-missing-directory')):
            mode = (0o600, 0o640, 0o700, 0o750)[index]
            rows.append({'case': name, 'operationReturnedSuccess': True, 'replacementBytesPresent': True,
                         'sourceRemains': False, 'returnedDestination': True,
                         'before': {'mode': mode} if index in (0, 2) else None,
                         'after': {'ownerUID': os.getuid(), 'mode': mode, 'directory': index >= 2}})
        rows.append({'case': 'replace-under-missing-parent', 'operationReturnedSuccess': False,
                     'sourceRemains': True, 'after': None, 'replacementBytesPresent': False})
        return {'schemaVersion': 1, 'administratorAuthorizationRequested': False, 'privilegedFileManagerTested': False,
                'productionProtectedInstallationTested': False, 'fixtureRootRemoved': True, 'results': rows}

    def test_complete_ordinary_evidence_is_accepted(self):
        PROBE.check_report(self.report())

    def test_privileged_claims_and_unverified_cleanup_are_rejected(self):
        for field in ('administratorAuthorizationRequested', 'privilegedFileManagerTested', 'productionProtectedInstallationTested'):
            report = self.report(); report[field] = True
            with self.assertRaises(RuntimeError): PROBE.check_report(report)
        report = self.report(); report['fixtureRootRemoved'] = False
        with self.assertRaises(RuntimeError): PROBE.check_report(report)

    def test_scope_modes_and_returned_bytes_must_match(self):
        original = self.report()
        for key, value in (('ownerUID', os.getuid() + 1), ('mode', 0o666), ('directory', True)):
            report = copy.deepcopy(original); report['results'][0]['after'][key] = value
            with self.assertRaises(RuntimeError): PROBE.check_report(report)
        for key in ('operationReturnedSuccess', 'replacementBytesPresent', 'returnedDestination'):
            report = self.report(); report['results'][0][key] = False
            with self.assertRaises(RuntimeError): PROBE.check_report(report)

    def test_missing_parent_is_a_refusal_with_the_source_retained(self):
        for key, value in (('operationReturnedSuccess', True), ('sourceRemains', False), ('after', {}), ('replacementBytesPresent', True)):
            report = self.report(); report['results'][-1][key] = value
            with self.assertRaises(RuntimeError): PROBE.check_report(report)

    def test_incomplete_or_reordered_cases_cannot_claim_a_complete_probe(self):
        for rows in (self.report()['results'][:-1], list(reversed(self.report()['results']))):
            report = self.report(); report['results'] = rows
            with self.assertRaises(RuntimeError): PROBE.check_report(report)
