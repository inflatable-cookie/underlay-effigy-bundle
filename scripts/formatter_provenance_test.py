"""No backend effects: finite version capture and private selection controls."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import formatter_provenance as probe


class FormatterTests(unittest.TestCase):
    def fixture(self, root):
        fixture = root / 'fixture'
        fixture.mkdir(mode=0o700)
        for child in ('home', 'colima'):
            (fixture / child).mkdir(mode=0o700)
        executable = root / 'colima'
        executable.write_text('#!/bin/sh\nexit 93\n')
        executable.chmod(0o700)
        env = dict(os.environ, HOME=str(fixture / 'home'), COLIMA_HOME=str(fixture / 'colima'), PATH=str(root))
        for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'COLIMA_PROFILE'):
            env.pop(key, None)
        probe.bind_host(env)
        return fixture, env, executable

    def test_exact_argv_and_private_identity_refusals(self):
        with tempfile.TemporaryDirectory(prefix='ur.005-storage.', dir=Path.home()) as temporary:
            root = Path(temporary)
            fixture, env, executable = self.fixture(root)
            self.assertEqual(probe.version_arguments(env, fixture), [str(executable), 'nerdctl', '--profile', 'effigy', '--', 'version', '--format', probe.VERSION_TEMPLATE])
            for key, value in (('COLIMA_HOME', str(root)), ('HOME', str(root)), ('COLIMA_PROFILE', ''), ('DOCKER_HOST', '')):
                with self.assertRaises(ValueError):
                    probe.version_arguments({**env, key: value}, fixture)
            (fixture / 'colima').chmod(0o755)
            with self.assertRaises(ValueError): probe.version_arguments(env, fixture)
            (fixture / 'colima').chmod(0o700)
            executable.write_text('#!/bin/sh\nexit 94\n')
            with self.assertRaises(ValueError): probe.version_arguments(env, fixture)
            with self.assertRaises(ValueError): probe.version_arguments({**env, 'PATH': '/missing'}, fixture)

    def test_explicit_profile_fixture_scope_is_exact(self):
        with tempfile.TemporaryDirectory(prefix='ur.') as temporary:
            parent=Path(temporary).resolve()
            fixture=parent/'ur.A1b2C3';fixture.mkdir(mode=0o700)
            for name in ('home','colima-home'):(fixture/name).mkdir(mode=0o700)
            executable=parent/'colima';executable.write_text('#!/bin/sh\nexit 93\n');executable.chmod(0o700)
            env=dict(os.environ,PATH=str(parent),HOME=str(fixture/'home'),COLIMA_HOME=str(fixture/'colima-home'),UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT=str(fixture))
            for key in ('DOCKER_HOST','DOCKER_CONTEXT','COLIMA_PROFILE'):env.pop(key,None)
            probe.bind_host(env)
            self.assertEqual(probe.version_arguments(env,fixture)[0],str(executable))
            for key in ('UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT','HOME','COLIMA_HOME'):
                with self.assertRaises(ValueError):probe.version_arguments({**env,key:str(parent)},fixture)

    def test_metadata_source_and_unknown_secret_refusals(self):
        valid = (probe.QUALIFIED_VERSION + '|' + probe.QUALIFIED_COMMIT + '|linux|arm64\n').encode()
        self.assertEqual(probe.version_projection(valid)['git_commit'], probe.QUALIFIED_COMMIT)
        for value in (valid * 2, b'seeded-secret', valid.replace(b'linux', b'darwin'), valid.replace(b'arm64', b'unknown'), valid.replace(b'arm64', b'amd64'), valid.replace(b'v2.3.1',b'v2.1.6'), valid.replace(probe.QUALIFIED_COMMIT.encode(),b'0'*40), b'x' * 513):
            with self.assertRaises(ValueError): probe.version_projection(value)
        self.assertFalse(probe.formatter_projection((Path(__file__).parent/'qualification/fixtures/nerdctl-231-formatter.go').read_bytes())['binary_source_attestation'])
        for value in (b'seeded-secret', b'changed-source', b'x' * 262145):
            with self.assertRaises(ValueError): probe.formatter_projection(value)

    def test_complete_capture_and_secret_failure_projection(self):
        with tempfile.TemporaryDirectory(prefix='ur.005-storage.', dir=Path.home()) as temporary:
            fixture, env, executable = self.fixture(Path(temporary))
            valid = (probe.QUALIFIED_VERSION + '|' + probe.QUALIFIED_COMMIT + '|linux|arm64\n').encode()
            journal = Mock()
            response = Mock()
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            response.read.return_value = (Path(__file__).parent/'qualification/fixtures/nerdctl-231-formatter.go').read_bytes()
            capture = dict(stdout=valid, stderr=b'', stdout_bytes=len(valid), stderr_bytes=0, exit=0, outcome='complete')
            with patch.object(probe, 'bounded_run', return_value=capture) as run, patch.object(probe.urllib.request, 'urlopen', return_value=response):
                self.assertEqual(probe.observe(env, fixture, journal)['version'], probe.QUALIFIED_VERSION)
                self.assertEqual(run.call_args.kwargs['timeout'], 15)
                self.assertEqual(run.call_args.kwargs['cap'], 16384)
            for outcome in ('timeout', 'truncated', 'complete'):
                journal.reset_mock()
                failed = {**capture, 'stdout': b'seeded-secret', 'stdout_bytes': 13, 'outcome': outcome}
                with patch.object(probe, 'bounded_run', return_value=failed), patch.object(probe.urllib.request, 'urlopen') as fetch:
                    with self.assertRaises(ValueError): probe.observe(env, fixture, journal)
                    fetch.assert_not_called()
                self.assertNotIn('seeded-secret', str(journal.mock_calls))
                self.assertEqual(journal.mock_calls[0].args[0], 'formatter_version_input')

    def test_actual_private_process_capture_no_backend_fallback(self):
        with tempfile.TemporaryDirectory(prefix='ur.005-storage.', dir=Path.home()) as temporary:
            fixture, env, executable = self.fixture(Path(temporary))
            # The exact selected private executable refuses. A real backend is
            # never reachable; source download and services cannot be reached.
            journal = Mock()
            with patch.object(probe.urllib.request, 'urlopen') as fetch:
                with self.assertRaisesRegex(ValueError, 'formatter_capture_refused'):
                    probe.observe(env, fixture, journal)
                fetch.assert_not_called()
            self.assertEqual(journal.mock_calls[0].kwargs['exit'], 93)


if __name__ == '__main__':
    unittest.main()
