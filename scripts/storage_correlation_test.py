"""Hermetic production correlation controls; no container or network effects."""
import json
import unittest
from unittest.mock import Mock
import storage_correlation as probe


class CorrelationTests(unittest.TestCase):
    def test_inner_pipeline_exit_survives_outer_error_without_output_leak(self):
        import subprocess
        result = subprocess.run(['/bin/sh', '-c', probe.shell_command('printf seeded-secret >/dev/null; exit 57')], capture_output=True, text=True, timeout=2)
        self.assertEqual(result.returncode, 57)
        self.assertEqual(probe.nested_exit(result.stdout), {'inner_exit':57, 'inner_exit_evidence':'shell_marker'})
        for value in ('seeded-secret', 'UNDERLAY_STORAGE_EXIT=999', 'UNDERLAY_STORAGE_EXIT=0\nUNDERLAY_STORAGE_EXIT=1'):
            self.assertEqual(probe.nested_exit(value)['inner_exit_evidence'], 'unknown')

    def test_exact_gateway_invocation_and_rejected_repo_have_no_effect(self):
        import os
        import subprocess
        import tempfile
        from pathlib import Path
        self.assertEqual(probe.invocation('/qualified', '/owned', ['gateway','status','--private-state-root','/private','--json']), ['/qualified','--json','gateway','status','--private-state-root','/private'])
        self.assertEqual(probe.invocation('/qualified', '/owned', ['container','hybrid_services','status','--json'])[:4], ['/qualified','--json','--repo','/owned'])
        with self.assertRaises(ValueError): probe.invocation('/qualified', '/owned', ['gateway','status'])
        binary = os.environ.get('UNDERLAY_PROFILE_EFFIGY_BIN')
        if not binary:
            raise RuntimeError('exact-source gateway parser control requires the qualified binary')
        from qualification_runtime import require_effigy_binary
        self.assertEqual(binary, require_effigy_binary())
        with tempfile.TemporaryDirectory(prefix='underlay-storage-cli-') as directory:
            root = Path(directory)
            import ast
            tree = ast.parse(Path(__file__).with_name('qualify-storage-correlation.py').read_text())
            calls = []
            for node in ast.walk(tree):
                if not isinstance(node, ast.List) or not node.elts or not isinstance(node.elts[0], ast.Constant) or node.elts[0].value != 'gateway':
                    continue
                values = []
                for item in node.elts:
                    if isinstance(item, ast.Constant) and isinstance(item.value, str):
                        values.append(item.value)
                    elif isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and item.func.id == 'str' and len(item.args) == 1 and isinstance(item.args[0], ast.Name) and item.args[0].id == 'gateway':
                        values.append(directory)
                    else:
                        self.fail('unclassified gateway argument in actual selector')
                calls.append(values)
            self.assertEqual(sorted(call[1] for call in calls), ['down','setup-tls','status','up'])
            for arguments in calls:
                actual = probe.invocation(binary, root, arguments)
                self.assertNotIn('--repo', actual)
                self.assertEqual(actual[actual.index('--private-state-root') + 1], directory)
                # All actual arguments must parse successfully before the
                # deliberate global --repo rejection. No command is executed.
                refused = [binary, '--repo', directory, *actual[1:]]
                process = subprocess.run(refused, capture_output=True, text=True, timeout=10)
                self.assertEqual(process.returncode, 2)
                envelope = json.loads(process.stdout)
                self.assertEqual(envelope['error']['kind'], 'CliParseError')
                self.assertEqual(envelope['error']['message'], 'unknown argument: --repo')
                self.assertEqual(list(root.iterdir()), [])

    def test_secret_free_error_projection_and_unknowns(self):
        body = b'<Error><Code>NoSuchKey</Code><RequestId>ABC-123</RequestId><Message>seeded-secret</Message><Key>secret</Key></Error>'
        result = probe.s3_error(body)
        self.assertEqual(result['error_code'], 'NoSuchKey')
        self.assertEqual(len(result['request_id_sha256']), 64)
        self.assertNotIn('seeded-secret', json.dumps(result))
        for body in (b'bad', b'<!DOCTYPE a><Error/>', b'<Error><Code>seeded-secret</Code></Error>', b'x' * 16385):
            self.assertEqual(probe.s3_error(body), {'error_code': 'unknown'})

    def test_alias_stat_and_headers_never_dump_secrets(self):
        record = {'status': 'success', 'alias': 'local', 'URL': 'http://user:seeded-secret@silo:9000?secret', 'accessKey': 'seeded-secret'}
        self.assertNotIn('secret', json.dumps(probe.alias_projection(json.dumps(record))))
        for change in ({'URL': 'http://foreign:9000'}, {'status': 'error'}, {'alias': 'foreign'}):
            with self.assertRaises(ValueError):
                probe.alias_projection(json.dumps({**record, **change}))
        self.assertEqual(probe.stat_projection('{"status":"success","size":39,"secret":"seeded-secret"}'), {'status': 'success', 'size': 39})
        for value in ('{"status":"error","message":"secret"}', '{"status":"success","size":true}', 'bad'):
            with self.assertRaises(ValueError):
                probe.stat_projection(value)
        response = Mock()
        response.getheader.side_effect = lambda name: {'Content-Length': '39', 'Content-Type': 'seeded-secret', 'Connection': 'close'}.get(name)
        self.assertEqual(probe.safe_framing(response), {'content-length': '39', 'content-type': 'unclassified', 'connection': 'close'})

    def test_actual_operation_order_and_404_stops_host_write(self):
        calls = []
        def shell(label, command, **kwargs):
            calls.append(label)
            if label == 'alias': return '{"status":"success","alias":"local","URL":"http://silo:9000"}'
            if label in ('dns', 'server-address'): return '10.0.0.2 silo'
            if label in ('stat', 'host-stat'): return '{"status":"success","size":39}'
            return ''
        journal = Mock()
        request = Mock(return_value=(404, {}, b'<Error><Code>NoSuchKey</Code></Error>'))
        with self.assertRaisesRegex(RuntimeError, 'disagree'):
            probe.correlate(shell, request, journal, 8540, 'first-known.txt')
        self.assertEqual(calls, ['alias', 'dns', 'server-address', 'bucket', 'pipe', 'stat'])
        self.assertEqual(request.call_count, 1)
        self.assertIn('NoSuchKey', str(journal.append.call_args_list))

    def test_success_and_pipeline_failure_propagate(self):
        def shell(label, command, **kwargs):
            if label == 'alias': return '{"status":"success","alias":"local","URL":"http://silo:9000"}'
            if label in ('dns', 'server-address'): return '10.0.0.2'
            if label in ('stat', 'host-stat'): return '{"status":"success","size":39}'
            return ''
        request = Mock(side_effect=[(200, {}, b'owned-storage-correlation:main-known.txt'), (200, {}, b'')])
        self.assertEqual(probe.correlate(shell, request, Mock(), 8440, 'main-known.txt')['port'], 8440)
        def failed(label, command, **kwargs):
            if label == 'pipe': raise RuntimeError('pipeline exit 1')
            return shell(label, command, **kwargs)
        request = Mock()
        with self.assertRaisesRegex(RuntimeError, 'pipeline exit 1'):
            probe.correlate(failed, request, Mock(), 8440, 'main-known.txt')
        request.assert_not_called()

    def test_minimal_policy_has_no_apps_dns_or_other_services(self):
        policy = dict(driver='colima', profile='effigy', startup='detached', project_name='owned', working_dir='/', host={'publish_address':'127.0.0.1'}, host_processes=[{'secret':'x'}], dns={'routes':['secret']}, services={'silo':{'catalog':'silo'}, 'silo_client':{'catalog':'silo-mc'}, 'postgres':{}})
        result = probe.minimal_policy(policy)
        self.assertEqual(list(result['services']), ['silo', 'silo_client'])
        self.assertEqual(result['host_processes'], [])
        self.assertNotIn('dns', result)
        self.assertTrue(probe.minimal_manifest(result).startswith('[sources]\nsiblings = false\n'))
        with self.assertRaises(ValueError): probe.minimal_policy({**policy, 'driver':'foreign'})
        for changed in ({'host':{'publish_address':'0.0.0.0'}}, {'project_name':'seeded-secret?'}, {'working_dir':'/foreign'}, {'startup':'attached'}):
            with self.assertRaises(ValueError): probe.minimal_policy({**policy, **changed})

    def test_actual_signed_request_retains_safe_framing_and_error(self):
        import importlib.util
        from pathlib import Path
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location('correlation_request_runtime', Path(__file__).with_name('qualify-reference-runtime.py'))
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        response = Mock(status=404)
        response.getheader.side_effect = lambda name: {'Content-Length':'99', 'Content-Type':'application/xml'}.get(name)
        response.getheaders.return_value = []
        response.read.return_value = b'<Error><Code>NoSuchKey</Code><Message>seeded-secret</Message></Error>'
        connection = Mock()
        connection.getresponse.return_value = response
        journal = Mock()
        journal.begin.return_value = 'storage-01'
        with patch.object(runtime.http.client, 'HTTPConnection', return_value=connection):
            status, _, _ = runtime._s3_request(8540, 'GET', '/bucket/key', diagnostics=journal, diagnostic_operation='known_get', diagnostic_path_template='/<bucket>/<object>')
        self.assertEqual(status, 404)
        phases = [call.args[4] for call in journal.phase.call_args_list]
        self.assertEqual(phases, ['request_sent', 'before_response_headers', 'response_headers_received', 'before_response_body', 'response_body_received'])
        self.assertNotIn('seeded-secret', str(journal.mock_calls))
        self.assertEqual(journal.append.call_args.kwargs['error_code'], 'NoSuchKey')
        connection.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
