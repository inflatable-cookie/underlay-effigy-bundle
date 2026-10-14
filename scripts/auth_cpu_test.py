import sys
sys.dont_write_bytecode=True
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import time
import unittest
from unittest import mock
import auth_cpu_inputs as inputs

spec=importlib.util.spec_from_file_location('cpu',Path(__file__).with_name('qualify-auth-cpu.py'))
cpu=importlib.util.module_from_spec(spec);spec.loader.exec_module(cpu)


class Controls(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='auth-cpu-control.')
        self.root=Path(self.temporary.name).resolve()
        (self.root/'probe').mkdir()

    def tearDown(self): self.temporary.cleanup()

    def fixture(self,members):
        path=self.root/'fixture.crate'
        with tarfile.open(path,'w:gz') as stream:
            for name,kind,data in members:
                item=tarfile.TarInfo(name);item.type=kind;item.size=len(data);item.mode=0o644
                stream.addfile(item,io.BytesIO(data) if kind==tarfile.REGTYPE else None)
        return path,hashlib.sha256(path.read_bytes()).hexdigest()

    def test_real_archives_and_generated_source_marker(self):
        lock=cpu.packages(cpu.RETAINED/'reference/main/apps/acme-api/Cargo.lock')
        for name,version in [('argon2','0.5.3'),('password-hash','0.5.0'),('tokio','1.53.1')]:
            path=inputs.unique_archive(cpu.RETAINED/'.cargo/registry/cache',name,version)
            _,files,_=inputs.archive(path,name,version,lock[name,version][1])
            directories=list((cpu.RETAINED/'.cargo/registry/src').glob('*/'+name+'-'+version))
            self.assertEqual(len(directories),1)
            inputs.source_agrees(directories[0],files)
            self.assertFalse((directories[0]/'.cargo-checksum.json').exists())

    def test_whole_available_locked_cache_materialization(self):
        lock=cpu.packages(cpu.RETAINED/'reference/main/apps/acme-api/Cargo.lock')
        admitted=inputs.admit_cache(cpu.RETAINED/'.cargo/registry/cache',lock,self.root/'private-cache')
        self.assertTrue(all(key in admitted for key in ('argon2-0.5.3','password-hash-0.5.0','tokio-1.53.1')))
        for key,(_,evidence) in admitted.items():
            self.assertGreater(evidence['files'],0)
            self.assertLessEqual(evidence['compressed_bytes'],inputs.COMPRESSED)

    def test_member_mutations(self):
        good=[('test-1/Cargo.toml',tarfile.REGTYPE,b'[package]')]
        for member in [('test-1/../escape',tarfile.REGTYPE,b'x'),('/test-1/a',tarfile.REGTYPE,b'x'),('other/a',tarfile.REGTYPE,b'x'),('test-1/Cargo.toml',tarfile.REGTYPE,b'x'),('test-1/link',tarfile.SYMTYPE,b''),('test-1/link',tarfile.LNKTYPE,b''),('test-1/device',tarfile.CHRTYPE,b'')]:
            path,checksum=self.fixture(good+[member])
            with self.assertRaises(inputs.Refusal): inputs.archive(path,'test','1',checksum)

    def test_archive_identity_and_limits(self):
        path,checksum=self.fixture([('test-1/Cargo.toml',tarfile.REGTYPE,b'x'*4096)])
        with self.assertRaises(inputs.Refusal): inputs.archive(path,'test','1','0'*64)
        original=inputs.EXPANDED;inputs.EXPANDED=10
        try:
            with self.assertRaises(inputs.Refusal): inputs.archive(path,'test','1',checksum)
        finally: inputs.EXPANDED=original
        for field,limit in [('COMPRESSED',1),('MEMBERS',0),('FILE',1)]:
            original=getattr(inputs,field);setattr(inputs,field,limit)
            try:
                with self.assertRaises(inputs.Refusal):inputs.archive(path,'test','1',checksum)
            finally:setattr(inputs,field,original)
        path.write_bytes(b'broken')
        with self.assertRaises(inputs.Refusal): inputs.archive(path,'test','1',hashlib.sha256(b'broken').hexdigest())

    def test_missing_duplicate_and_link_archives(self):
        cache=self.root/'cache';cache.mkdir()
        with self.assertRaises(inputs.Refusal): inputs.unique_archive(cache,'test','1')
        for folder in ('a','b'):
            (cache/folder).mkdir();(cache/folder/'test-1.crate').write_bytes(b'x')
        with self.assertRaises(inputs.Refusal): inputs.unique_archive(cache,'test','1')
        path=cache/'a/test-1.crate';os.link(path,self.root/'linked')
        with self.assertRaises(inputs.Refusal): inputs.read_file(path,100)
        link=self.root/'symlink';link.symlink_to(path)
        with self.assertRaises(inputs.Refusal): inputs.read_file(link,100)

    def test_changed_and_extra_source(self):
        source=self.root/'source';source.mkdir();(source/'a.rs').write_bytes(b'original')
        expected={'a.rs':(hashlib.sha256(b'original').hexdigest(),False)}
        inputs.source_agrees(source,expected)
        (source/'a.rs').write_bytes(b'changed')
        with self.assertRaises(inputs.Refusal): inputs.source_agrees(source,expected)
        (source/'a.rs').write_bytes(b'original');(source/'extra.rs').write_bytes(b'x')
        with self.assertRaises(inputs.Refusal): inputs.source_agrees(source,expected)

    def test_lock_and_phase_schema_refusal(self):
        lock=self.root/'lock';lock.write_text('[[package]]\nname = "test"\nversion = "1"\nsource = "a"\nsource = "b"\n')
        with self.assertRaises(ValueError): cpu.packages(lock)
        for data in [b'{"phase":"join","phase":"total","elapsed_us":1,"outcome":"valid"}',b'{"phase":"join","elapsed_us":true,"outcome":"valid"}',b'{"phase":"unknown","elapsed_us":1,"outcome":"valid"}',b'{']:
            with self.assertRaises(ValueError):cpu.phase_rows(data)

    def test_actual_layout_and_fingerprint_classes(self):
        source=cpu.RETAINED/'.cargo/git/checkouts/underlay-d2d5ac68e32e8122/72d6fd9'
        self.assertTrue((source/'Cargo.toml').is_file())
        self.assertFalse((source/'rust/Cargo.toml').exists())
        prior=[json.loads(f.read_text()) for f in (cpu.RETAINED/'.cargo-target/debug/.fingerprint').glob('argon2-*/lib-argon2.json')]
        cpu.profile_admitted(prior,prior)
        for values in [[],[dict(prior[0],profile=-1)],[{k:v for k,v in prior[0].items() if k!='features'}]]:
            with self.assertRaises(ValueError):cpu.profile_admitted(values,prior)

    def test_local_noncrypto_capture(self):
        env={'PATH':os.environ['PATH']}
        receipt,output=cpu.bounded(self.root,'success',[sys.executable,'-c','print("closed")'],env,time.monotonic()+5)
        self.assertEqual((receipt['exit'],receipt['reason']),(0,'complete'))
        self.assertEqual(output['stdout'],b'closed\n')
        for kind,code,reason in [('overflow','import sys;sys.stdout.write("x"*20000)','stdout_overflow'),('deadline','import time;time.sleep(5)','deadline'),('nonzero','import sys;sys.exit(3)','complete')]:
            receipt,_=cpu.bounded(self.root,kind,[sys.executable,'-c',code],env,time.monotonic()+(.2 if kind=='deadline' else 5))
            self.assertEqual(receipt['reason'],reason);self.assertTrue(receipt['reaped'])
            self.assertLessEqual(receipt['bytes']['stdout'],cpu.CAP+4096)

    def test_read_failure_reaps_only_new_child(self):
        original=os.read
        def fail_output(fd,size):
            if size==4096:raise OSError('controlled')
            return original(fd,size)
        with mock.patch.object(cpu.os,'read',fail_output):
            receipt,_=cpu.bounded(self.root,'read_failure',[sys.executable,'-c','print("closed")'],{'PATH':os.environ['PATH']},time.monotonic()+5)
        self.assertEqual(receipt['reason'],'read_failure')
        self.assertTrue(receipt['reaped'])


if __name__=='__main__':unittest.main()
