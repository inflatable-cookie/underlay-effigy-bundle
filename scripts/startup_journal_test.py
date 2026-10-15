"""Private startup budget and closed refusal producer controls; no live backend."""
import ast
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import unittest
from unittest.mock import patch
from dev import startup_evidence as native
from native_startup_test import NativeControls, DRIVER

OLD=Path('/Users/tom/ur.005-b69-product.Z6yuDWKL/startup-55bd6b9652a20056325849007512792d-f0094e6dfc96fec5e0632c52e20ab7ea.jsonl')

class JournalVolumeControls(unittest.TestCase):
    setUpClass=classmethod(NativeControls.setUpClass.__func__)
    setUp=NativeControls.setUp
    pipeline=NativeControls.pipeline
    retained=NativeControls.retained

    def session(self,action='start'):
        return native.Session(dict(self.env,UNDERLAY_PROFILE_COMMAND_NONCE='b'*32),self.root,action,'hybrid')

    def replay(self,session,rows):
        for row in rows:
            token=native.SERVICE.set(row['service'])
            try:session.emit(row['stage'],row['state'],row['observation'],row['role'],row['original_host_identity'],row['elapsed_ms'])
            finally:native.SERVICE.reset(token)

    def test_closed_204_roundtrip_old_counterexample_and_full_topology(self):
        original=[json.loads(line) for line in native.Session.read(OLD,131072).splitlines()]
        self.assertEqual(len(original),204)
        measurements=[]
        # Three checkout starts are separate launcher calls, with the same
        # supported per-call topology. Actual closed pre-bootstrap events include
        # all three roles, managed state/report and original host identities.
        for checkout_role in range(3):
            session=self.session()
            try:
                self.replay(session,original[1:])
                restored=[json.loads(x) for x in native.Session.read(session.path,native.STARTUP_FILE_CAP).splitlines()]
                for before,after in zip(original,restored):
                    for key in before:
                        if key not in ('binding','nonce','call_id'):self.assertEqual(before[key],after[key])
                used=session.bytes
                # Same serialization/source metadata, without a native capture,
                # is already too large for the old remaining ordinary budget.
                minimal=dict(restored[-1],sequence=205,stage='bootstrap_bucket',state='completed',service='silo_client')
                requested=len((json.dumps(minimal,separators=(',',':'))+'\n').encode())
                self.assertGreater(requested,395)
                with self.assertRaises(native.JournalRefusal) as caught:native.preflight(106101,requested,106496)
                self.assertEqual(caught.exception.observation['reason'],'startup_journal_capacity')
                # Source-derived remaining calls: bucket completion, anonymous
                # policy, CORS, bootstrap/return. Each native operation retains
                # its observed source verification topology, not a neutral loop.
                shell_source=(Path(__file__).parent/'dev/profile_launcher.py').read_text()
                tree=ast.parse(shell_source)
                bootstrap=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_bootstrap_silo')
                labels=[n.args[0].value for n in ast.walk(bootstrap) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='shell' and n.args and isinstance(n.args[0],ast.Constant)]
                self.assertTrue({'bucket','anonymous','cors'}<=set(labels))
                native_rows=[r for r in original if r['observation'] is not None]
                gates=[r for r in original[196:] if r['stage']=='source_gate']
                for label in ('bucket','anonymous','cors'):
                    if label!='bucket':session.emit('bootstrap_native','entered')
                    self.replay(session,gates)
                    for role in ('api','front','admin'):
                        # Current role-bound readiness/report shape from the
                        # maintained producer; no new listener or socket exists.
                        session.emit('managed_state','entered',role=role)
                        session.emit('managed_state','completed',role=role)
                    self.replay(session,native_rows[-1:])
                    session.emit('bootstrap_bucket' if label=='bucket' else 'bootstrap_native','completed')
                for stage in ('bootstrap','start','return'):
                    session.emit(stage,'completed')
                # Status/idempotent-start/test-plan/action/down/cleanup seams
                # have distinct event topology and retain all native facts.
                for action in ('status','start','test','down'):
                    session.emit(action,'entered')
                    for stage in ('service_status','gateway_status','managed_report','readiness'):
                        session.emit(stage,'entered');self.replay(session,native_rows[-1:]);session.emit(stage,'completed')
                    if action=='test':
                        for stage in ('test_plan','test_action'):
                            session.emit(stage,'entered');self.replay(session,native_rows[-1:]);session.emit(stage,'completed')
                    session.emit(action,'completed')
                session.emit('cleanup','entered');session.emit('cleanup','completed')
                output=native.Session.read(session.path,native.STARTUP_FILE_CAP)
                rows=[json.loads(line) for line in output.splitlines()]
                self.assertEqual(len(rows),session.sequence)
                self.assertLess(session.bytes,native.STARTUP_ORDINARY_LIMIT)
                measurements.append({'records':len(rows),'bytes':session.bytes,'old_minimum_append':requested,'stages':dict(Counter(r['stage'] for r in rows))})
            finally:session.close()
        print('VOLUME '+json.dumps(measurements),flush=True)

    def test_new_hard_cap_preflight_sticky_and_cleanup_reserve(self):
        session=self.session()
        try:
            while True:
                before=session.bytes
                try:session.emit('source_gate','entered')
                except native.JournalRefusal as failure:
                    error=failure;break
            self.assertEqual(session.path.stat().st_size,before)
            self.assertEqual(error.observation['reason'],'startup_journal_capacity')
            self.assertEqual(error.observation['limit'],499712)
            self.assertGreater(error.observation['bytes_used']+error.observation['bytes_requested'],499712)
            primary=native.journal_failure(error)
            with self.assertRaises(native.JournalRefusal) as late:session.emit('cleanup','entered')
            secondary=native.journal_failure(late.exception,primary.record)
            self.assertEqual(secondary.record['source_reason'],'startup_journal_capacity')
            self.assertIn('startup_journal_sticky',secondary.record['journal_failure']['secondary_reasons'])
            self.assertLessEqual(session.bytes,499712)
        finally:session.close()
        # Cleanup has access to the reserve before any sticky refusal; it does
        # not restore a failed journal or grant any dispatcher authority.
        session=self.session('down')
        try:
            while session.bytes<500000:session.emit('cleanup','entered')
            self.assertGreater(session.bytes,499712)
            while True:
                before=session.bytes
                try:session.emit('cleanup','completed')
                except native.JournalRefusal as failure:
                    error=failure;break
            self.assertEqual(error.observation['limit'],524288)
            self.assertEqual(session.path.stat().st_size,before)
        finally:session.close()

    def test_identity_mode_link_intent_record_shortwrite_and_error_provenance(self):
        cases=('mode','link','replacement','symlink','intent','content','record','sequence','deadline','shortwrite','writeerror')
        for mode in cases:
            with self.subTest(mode=mode):
                session=self.session();restore=None
                try:
                    if mode=='mode':session.path.chmod(0o644)
                    if mode=='link':os.link(session.path,self.root/('link-'+session.call_id))
                    if mode in ('replacement','symlink'):
                        moved=self.root/('moved-'+session.call_id);session.path.rename(moved)
                        if mode=='replacement':session.path.write_text('');session.path.chmod(0o600)
                        else:session.path.symlink_to(moved)
                    if mode=='intent':
                        restore=session.intent_path.read_bytes();session.intent_path.write_bytes(restore+b' ')
                    if mode=='content':
                        raw=session.path.read_bytes();session.path.write_bytes(b' '+raw[1:])
                    if mode=='sequence':session.sequence=-1
                    if mode=='deadline':session.deadline=0
                    actual_write=native.os.write
                    write_fault=(patch.object(native.os,'write',side_effect=lambda fd,data:actual_write(fd,data[:1]))
                                 if mode=='shortwrite' else patch.object(native.os,'write',side_effect=PermissionError('PRIVATE'))
                                 if mode=='writeerror' else patch.dict(os.environ,{}))
                    with write_fault:
                        with self.assertRaises(native.JournalRefusal) as caught:session.emit('start','entered',{'PRIVATE':'https://secret.invalid/?token=PRIVATE'} if mode=='record' else None)
                    record=native.journal_failure(caught.exception).record
                    expected={'mode':'startup_journal_permissions','link':'startup_journal_link','replacement':'startup_journal_identity','symlink':'startup_journal_identity','intent':'startup_intent_changed','content':'startup_journal_content','record':'startup_record_refused','sequence':'startup_journal_sequence','deadline':'startup_journal_deadline','shortwrite':'startup_journal_write','writeerror':'startup_journal_write'}[mode]
                    self.assertEqual(record['source_reason'],expected)
                    self.assertNotIn('PRIVATE',json.dumps(record));self.assertNotIn('secret.invalid',json.dumps(record))
                    self.assertTrue(session.sticky)
                    if mode=='writeerror':self.assertEqual(record['error_class'],'PermissionError')
                    if mode=='shortwrite':
                        with self.assertRaises(ValueError):native.read_stages(session.path,binding=session.binding,nonce=session.nonce,call_id=session.call_id)
                finally:
                    session.close()
                    if restore is not None:session.intent_path.write_bytes(restore)
        error=ValueError('startup_journal_capacity')
        self.assertEqual(native.failure(error).record['reason'],'unknown')
        # Method code objects are registered, arbitrary identical strings aren't.
        self.assertIn(native.Session._emit.__code__,native.OWNING_CODES)

    def test_other_journal_methods_keep_closed_reason_without_budget_change(self):
        import sys
        sys.path.insert(0,str(Path(__file__).parent/'dev'))
        import profile_launcher as launcher
        repo=self.root/'journal-repo';repo.mkdir(mode=0o700)
        journal=launcher._silo_journal(repo,'hybrid_services')
        # Actual private journal producer and its source-qualified boundary.
        # The fixed bootstrap cap stays 131072; no startup limit is borrowed.
        journal.append('bootstrap_input',known=True)
        from reference_storage_probe import StorageDiagnosticJournal
        evidence=self.root/'main-evidence';evidence.mkdir(mode=0o700)
        fixture=self.root/'unrelated-fixture';fixture.mkdir(mode=0o700)
        main=StorageDiagnosticJournal(evidence/'storage-diagnostics.jsonl',fixture)
        try:
            main._capacity_refused=True
            try:main.append('native')
            except RuntimeError as error:record=native.journal_failure(error).record
            else:self.fail('main journal capacity refusal missing')
            self.assertEqual(record['source_reason'],'main_journal_capacity')
            self.assertEqual(record['error_class'],'RuntimeError')
            self.assertFalse(record['journal_failure']['counts_available'])
        finally:main.close()
        self.assertIsNone(native.owned_journal_reason(RuntimeError('diagnostic_capacity_refused')))

    def test_bounded_reader_duplicate_unknown_truncated_foreign_and_budget_marker(self):
        session=self.session()
        try:
            original=session.path.read_bytes()
            args=dict(binding=session.binding,nonce=session.nonce,call_id=session.call_id)
            self.assertEqual(len(native.read_stages(session.path,**args)),1)
            row=json.loads(original)
            variants=[original[:-1],original.replace(b'"stage":',b'"stage":"start","stage":'),
                json.dumps(dict(row,PRIVATE='secret')).encode()+b'\n',
                json.dumps(dict(row,sequence=2)).encode()+b'\n',
                json.dumps(dict(row,original_host_identity={'PRIVATE':'secret'})).encode()+b'\n',
                json.dumps(dict(row,elapsed_ms='PRIVATE')).encode()+b'\n']
            for raw in variants:
                session.path.write_bytes(raw)
                with self.assertRaises(ValueError):native.read_stages(session.path,**args)
            session.path.write_bytes(original)
            with self.assertRaises(ValueError):native.read_stages(session.path,**dict(args,binding='f'*64))
            with self.assertRaises(ValueError):native.Session.read(session.path,524289)
            with self.assertRaises(native.JournalRefusal) as caught:native.preflight(499700,438,499712)
            record=native.journal_failure(caught.exception).record
            record.update(binding=session.binding,nonce=session.nonce,call_id=session.call_id)
            line=native.MARKER+json.dumps(record)
            decoded,bad=native.marker_record(line,binding=session.binding,nonce=session.nonce)
            self.assertFalse(bad);self.assertEqual(decoded,record)
            self.assertEqual(native.marker_record(line+'\n'+line,binding=session.binding,nonce=session.nonce),(None,True))
            record['journal_failure']['PRIVATE']='secret'
            self.assertIsNone(native.validate(record))
        finally:session.close()

    def test_native_exit_zero_capacity_exported_launcher_parent_outer(self):
        injection="""
if os.environ.get('CONTROL_MODE')=='journalcapacity':
    original_emit=native.Session.emit
    def overflowing(self,name,state,*args,**kwargs):
        if name=='bootstrap_bucket' and state=='completed':
            while True:original_emit(self,'source_gate','entered')
        return original_emit(self,name,state,*args,**kwargs)
    native.Session.emit=overflowing
"""
        path=self.root/'driver.py';text=DRIVER.replace('try:\n    result=launcher.main',injection+'\ntry:\n    result=launcher.main');path.write_text(text)
        with self.assertRaises(native.NativeFailure) as caught:self.pipeline(mode='journalcapacity')
        record=self.retained(caught.exception)
        self.assertEqual(record['reason'],'journal_refused');self.assertEqual(record['source_reason'],'startup_journal_capacity')
        self.assertEqual(record['stage'],'bootstrap_bucket');self.assertEqual(record['exit'],0)
        self.assertEqual(record['journal_failure']['limit'],499712)
        self.assertTrue(record['journal_failure']['counts_available'])
        self.assertEqual(record['effect_state'],'unknown')
        self.assertIn('startup_journal_sticky',record['journal_failure']['secondary_reasons'])

if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(60)
    unittest.main()
