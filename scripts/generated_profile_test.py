import json,os,signal,unittest
from pathlib import Path
from unittest.mock import patch
from original_container_route_test import RouteControls
from generated_profile import private_mount,containerd_profile
from qualification_refusal import project,publish
from container_identity_observer import Refusal


def producer(root):
    # Neutral complete producer-shaped fixture; no retained config or secrets copied.
    return ("arch: aarch64\ncpus: 2\nlabel: owner's neutral field\n"
            'message: "neutral\\tvalue # scalar" # comment\n'
            '# harmless\tcomment\nprovision:\n- mode: system\n  script: |\n    printf "neutral\tvalue"\n'
            'mounts:\n    - location: '+json.dumps(str(root)+'/')+'\n      writable: true\n'
            'containerd:\n  system: true\n').encode()



class GeneratedControls(RouteControls):
    def test_full_bind_and_original_route_generated_form(self):
        self.start();config=self.root/'lima-home/colima-effigy/lima.yaml';config.write_bytes(producer(self.root))
        colima=self.root/'colima-home/effigy/colima.yaml';colima.write_text('runtime: "containerd" # producer\nmounts:\n  - location: '+str(self.root)+'/\n    writable: true\ncomment: "neutral\tvalue"\n')
        events=[];self.backend.refusal_emit=lambda event,**kw:events.append(kw)
        result=self.backend.admit_original_route(self.env)
        self.assertEqual(result['namespace'],'default');self.assertEqual(events,[])
        self.assertFalse(result['vm_signal_authority'])
        for representation in (str(self.root),json.dumps(str(self.root)),"'"+str(self.root)+"/'"):
            raw=('mounts:\n    - location: '+representation+'\n      mountPoint: '+json.dumps(str(self.root)+'/')+'\n      writable: true\n').encode()
            self.assertTrue(private_mount(raw,self.root)['original_root_matched'])

    def test_complete_binding_negative_forms_never_transport(self):
        self.start();config=self.root/'lima-home/colima-effigy/lima.yaml'
        base=producer(self.root)
        variants=[base.replace(b'      writable: true',b'\twritable: true'),base.replace(b'writable: true',b'writable: false'),base+b'mounts:\n',base.replace(b'      writable: true',b'      writable: true\n      writable: true'),base.replace(b'      writable: true',b'      unknown: true'),base.replace(b'mounts:\n',b'mounts: &anchor\n'),base.replace(b'      writable: true',b'      writable: true\n    - location: /foreign\n      writable: true'),base.replace(b'mounts:',b'notmounts:'),base.replace(b'- location:',b' - location:'),base[:-1],b'\xff\n',base.replace(str(self.root).encode(),(str(self.root)+'-prefix').encode()),base.replace(str(self.root).encode(),(str(self.root)+'/../foreign').encode())]
        for raw in variants:
            with self.subTest(kind=len(raw)):
                config.write_bytes(raw);events=[];self.backend.refusal_emit=lambda event,**kw:events.append(kw['projection'])
                with self.assertRaises(Refusal):self.backend.admit_original_route(self.env)
                self.assertIsNone(self.backend.profile_binding)
                self.assertTrue(events);self.assertNotEqual(events[0]['reason_id'],'unknown')
                self.assertFalse((self.root/'calls').exists())

    def test_original_inode_owner_symlink_and_rewrite_guards(self):
        self.start();config=self.root/'lima-home/colima-effigy/lima.yaml';config.write_bytes(producer(self.root));self.backend.admit_original_route(self.env)
        original=config.read_bytes()
        with patch('container_identity_observer.os.geteuid',return_value=os.geteuid()+1):
            with self.assertRaises(Refusal):self.backend.guard()
        replacement=config.parent/'replacement.yaml';replacement.write_bytes(original);replacement.chmod(0o600);replacement.replace(config)
        with self.assertRaisesRegex(Refusal,'profile_config_changed'):self.backend.guard()
        config.write_bytes(original+b'# rewrite\n')
        with self.assertRaisesRegex(Refusal,'profile_config_changed'):self.backend.guard()
        config.unlink();config.symlink_to(self.root/'backend-intent.json')
        with self.assertRaises(Refusal):self.backend.guard()

    def test_closed_refusal_privacy_primary_settlement_and_failed_publication(self):
        error=Refusal('capture_deadline');error.evidence={'stdout_observed':17,'stderr_observed':8,'stdout_eof':False,'leader_reaped':False,'payload':'SEEDED_SECRET','stdout_sha256':'SECRET'};error.settlement_observation='unknown'
        record=publish(error,'route_transport',lambda *_args,**_kwargs:(_ for _ in ()).throw(RuntimeError('SEEDED_SECRET')))
        self.assertEqual(record['reason_id'],'capture_deadline');self.assertEqual(record['settlement'],'unknown');self.assertEqual(record['publication'],'unavailable')
        self.assertNotIn('SECRET',json.dumps(record));self.assertNotIn('stdout_sha256',record['capture'])
        self.assertEqual(project(Refusal('SEEDED_SECRET'),'profile_binding')['reason_id'],'unknown')
        self.assertEqual(project(RuntimeError('SEEDED_SECRET'),'route_admission')['reason_id'],'unknown')
        self.assertEqual(project(Refusal('capture_deadline'),'route_transport')['capture'],{})

    def test_production_capture_preserves_primary_when_reap_unknown(self):
        from types import SimpleNamespace
        import subprocess,time
        import container_identity_observer as observer
        class Stream:
            def fileno(self):return 3
            def close(self):pass
        class Child:
            stdout=Stream();stderr=Stream();returncode=None
            def kill(self):pass
            def wait(self,**kw):raise subprocess.TimeoutExpired('SEEDED_SECRET',1)
        class Selector:
            def register(self,*args):pass
            def get_map(self):return {'pending':True}
            def select(self,*args):return [(SimpleNamespace(fd=3,data='stdout'),None)]
            def close(self):pass
        with patch.object(observer.subprocess,'Popen',return_value=Child()),patch.object(observer.selectors,'DefaultSelector',Selector),patch.object(observer.os,'set_blocking'),patch.object(observer.os,'read',side_effect=OSError('SEEDED_SECRET')):
            with self.assertRaises(Refusal) as caught:observer.host_capture(['private'],{},str(self.root),time.monotonic()+1)
        record=project(caught.exception,'route_transport')
        self.assertEqual(record['reason_id'],'capture_read');self.assertEqual(record['settlement'],'unknown')
        self.assertFalse(record['capture']['leader_reaped']);self.assertNotIn('SECRET',json.dumps(record))

    def test_actual_private_journal_identity_refusal_preserves_reason(self):
        import tempfile
        from reference_storage_probe import StorageDiagnosticJournal
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);fixture=root/'fixture';fixture.mkdir(mode=0o700)
            journal=StorageDiagnosticJournal(root/'storage-diagnostics.jsonl',fixture)
            error=Refusal('profile_structural_tab')
            record=publish(error,'profile_binding',journal.append)
            self.assertEqual(record['publication'],'recorded')
            journal.path.write_bytes(journal.path.read_bytes()+b'{}\n')
            record=publish(error,'profile_binding',journal.append)
            self.assertEqual(record['publication'],'unavailable')
            self.assertEqual(record['reason_id'],'profile_structural_tab')
            journal.close()

    def test_actual_retained_producer_read_only_projection(self):
        # Retained configuration may be inspected in memory only. It is never a fixture.
        retained=Path('/Users/tom/ur.XVq2GJ')
        raw=(retained/'lima-home/colima-effigy/lima.yaml').read_bytes()
        self.assertTrue(private_mount(raw,retained)['original_root_matched'])
        self.assertTrue(containerd_profile((retained/'colima-home/effigy/colima.yaml').read_bytes()))

if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(60)
    unittest.main()
