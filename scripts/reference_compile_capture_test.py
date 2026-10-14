import json
import os
import signal
import sys
import unittest

from reference_compile_capture import capture, diagnostic_summary, LIMIT


class CompileCaptureTests(unittest.TestCase):
    def test_closed_diagnostics_exclude_payload(self):
        secret = b'https://user:PRIVATE@invalid.test/token PRIVATE SSH_AUTH_SOCK=/secret'
        receipt = diagnostic_summary(b'', secret + b'\nerror[E0308]: PRIVATE\n --> crates/api/src/main.rs:42:9\nPermission denied (publickey)')
        self.assertNotIn('PRIVATE', json.dumps(receipt))
        self.assertEqual(receipt['rust_codes'], ['E0308'])
        self.assertEqual(receipt['locations'], [{'path': 'crates/api/src/main.rs', 'line': 42, 'column': 9}])
        self.assertIn('ssh_authentication', receipt['categories'])
        self.assertEqual(diagnostic_summary(b'', b' --> crates/../secret.rs:2:1')['locations'], [])
        self.assertEqual(diagnostic_summary(b'', b' --> crates/secretPRIVATE.rs:2:1')['locations'], [])

    def test_nonzero_complete_capture(self):
        result = capture([sys.executable, '-c', 'import sys; print("error[E0308]: private",file=sys.stderr);sys.exit(3)'], cwd=os.getcwd(), env=dict(os.environ), timeout=5)
        self.assertEqual(result['exit'], 3)
        self.assertTrue(result['leader_reaped'])
        self.assertTrue(result['identity_admitted'])
        self.assertTrue(result['stdout']['eof'] and result['stderr']['eof'])
        self.assertIsNone(result['refusal'])
        self.assertEqual(result['diagnostics']['rust_codes'], ['E0308'])

    def test_overflow_withholds_complete_output(self):
        result = capture([sys.executable, '-c', 'import os;os.write(2,b"x"*300000)'], cwd=os.getcwd(), env=dict(os.environ), timeout=5)
        self.assertEqual(result['refusal'], 'stderr_overflow')
        self.assertGreater(result['stderr']['read_bytes'], LIMIT)
        self.assertEqual(result['stderr']['retained_bytes'], LIMIT)
        self.assertTrue(result['leader_reaped'])
        self.assertEqual(result['group_absence'], 'unverified')

    def test_deadline_on_exact_owned_child(self):
        result = capture([sys.executable, '-c', 'import time;time.sleep(2)'], cwd=os.getcwd(), env=dict(os.environ), timeout=.1)
        self.assertEqual(result['refusal'], 'deadline')
        self.assertTrue(result['leader_reaped'])
        self.assertFalse(result['stdout']['eof'])

    def test_unknown_identity_grants_no_compile_credit(self):
        from unittest.mock import patch
        with patch('reference_compile_capture.kernel_identity', return_value=None):
            result = capture([sys.executable, '-c', 'pass'], cwd=os.getcwd(), env=dict(os.environ), timeout=5)
        self.assertEqual(result['exit'], 0)
        self.assertFalse(result['identity_admitted'])
        self.assertTrue(result['leader_reaped'])

    def test_actual_caller_records_before_refusal(self):
        import importlib.util
        from pathlib import Path
        from unittest.mock import patch
        path = Path(__file__).with_name('qualify-reference-optin.py')
        spec = importlib.util.spec_from_file_location('compile_capture_caller_test', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = {'exit': 1, 'refusal': None, 'identity_admitted': True,
                  'leader_reaped': True, 'stdout': {'eof': True}, 'stderr': {'eof': True}}
        inputs = {'reference_source_commit': 'source', 'patch_sha256': 'patch', 'cargo_lock_sha256': 'lock'}
        with patch.object(module, 'capture_compile', return_value=result) as producer, \
             patch.object(module, 'append_diagnostic_best_effort') as journal:
            with self.assertRaisesRegex(RuntimeError, 'compile failed'):
                module.capture_reference_compile('/qualified/effigy', Path('/new/check'), {'HOME': '/private'}, inputs, None)
            self.assertEqual(producer.call_args.kwargs['env'], {'HOME': '/private'})
            self.assertEqual(journal.call_args.kwargs['capture'], result)
            self.assertEqual(journal.call_args.kwargs['patch_sha256'], 'patch')
        result['exit'] = 0
        result['stderr']['eof'] = False
        with patch.object(module, 'capture_compile', return_value=result), patch.object(module, 'append_diagnostic_best_effort'):
            with self.assertRaisesRegex(RuntimeError, 'compile failed'):
                module.capture_reference_compile('/qualified/effigy', Path('/new/check'), {}, inputs, None)


if __name__ == '__main__':
    signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
    signal.alarm(60)
    unittest.main()
