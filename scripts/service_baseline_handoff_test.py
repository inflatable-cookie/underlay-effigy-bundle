"""Actual factory/ready wrapper/private fake transport sequence, no backend."""
import copy
import json
import os
from pathlib import Path
import signal
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from original_container_route_test import RouteControls
import service_baseline_handoff as handoff
import qualification_cleanup_action as wrapper
from qualification_cleanup_test import World
import qualification_cleanup as host
from container_identity_observer import Refusal


class HandoffControls(RouteControls):
    def ready(self):
        other=self.backend.paths['HOME']/'other';other.mkdir(mode=0o700)
        (other/'effigy.toml').write_text('independent foreign config\n');(other/'effigy.toml').chmod(0o600)
        import subprocess
        subprocess.run(['git','init','-q',str(other)],check=True,capture_output=True)
        scope=dict(self.scope,checkout=str(other));config=copy.deepcopy(self.config)
        config['result']['selected_path']='containers.hybrid_services'
        config['result']['selected_value']={'path':'containers.hybrid_services','value':dict(self.policy,project_name='foreign')}
        self.backend.original_policy(other,'hybrid_services',json.dumps(config).encode(),json.dumps({'ok':True,'result':scope}).encode())
        def row(token,project,checkout,service):
            return dict(id=token*64,created='2026-10-14T01:02:03Z',project=project,checkout=str(checkout),service=service,oneoff='false',running=True,status='running')
        rows=[row('c','foreign',other,'api'),row('d','foreign',other,'portless')]
        self.model['records']={r['id']:r for r in rows};self.write();self.start()
        reader=self.backend.observer_for(self.checkout,self.env,'default',[(str(other),'hybrid_services')])
        self.receipts=self.checkout/'ready-proof';self.receipts.mkdir(mode=0o700)
        self.manifest=self.checkout/'effigy.toml';self.original=self.manifest.read_bytes()
        self.changed=self.original+b'# exact predeclared ready action\n'
        stamp=handoff.prepare(reader,self.receipts,self.manifest,self.changed)
        self.manifest.write_bytes(self.changed)
        rows += [row('a','fixture',self.checkout,'api'),row('b','fixture',self.checkout,'portless')]
        self.model['records']={r['id']:r for r in rows};self.write()
        return reader,stamp

    def test_actual_wrapper_captures_live_services_before_test_and_parent_postabsence(self):
        parent,stamp=self.ready();world=World();events=[]
        class HostObserver:
            def __init__(self,*args):pass
            def capture(self):return host.capture(world.states,world)
        def action(argv,**kw):
            record,_=handoff.read(self.receipts/'services.json',self.receipts)
            self.assertEqual(len(record['baseline']['owned']),2)
            self.assertEqual(host.read_private(self.receipts/'pending.json',self.receipts)['action'],'pending')
            self.assertEqual(argv[-1],'acme-api/test');self.assertEqual(kw['timeout'],900)
            events.append('test');return SimpleNamespace(returncode=0)
        fake=SimpleNamespace(require_effigy_binary=lambda:'/qualified/effigy',RUNTIME=SimpleNamespace(run=action))
        with patch.object(wrapper,'load_qualifier',return_value=fake),patch.object(wrapper,'ListenerObserver',HostObserver),patch.dict(os.environ,self.env,clear=True),patch.object(sys,'argv',['wrapper',str(self.checkout),str(self.receipts)]):
            self.assertEqual(wrapper.main(),0)
        events.append('launcher-down')
        self.model['records']={k:r for k,r in self.model['records'].items() if r['project']=='foreign'};self.write()
        self.manifest.write_bytes(self.original)
        proof=handoff.accept(parent,self.receipts,stamp)
        self.assertEqual(events,['test','launcher-down']);self.assertTrue(proof['container_cleanup_verified'])
        self.assertTrue(proof['foreign_preservation_verified']);self.assertFalse(proof['vm_signal_authority'])

    def test_missing_handoff_and_wrong_root_source_manifest_refuse_before_inventory(self):
        parent,stamp=self.ready();record,_=handoff.read(self.receipts/'association.json',self.receipts)
        for field in ('root','source','manifest'):
            bad=copy.deepcopy(record)
            if field=='root':bad['directories'][str(self.root)][1]+=1
            if field=='source':bad['sources'][next(iter(bad['sources']))]='0'*64
            if field=='manifest':bad['ready_manifest']['sha256']='0'*64
            with self.assertRaises(Refusal):handoff.Association(bad,self.root)
        with self.assertRaises(Refusal):handoff.accept(parent,self.receipts,stamp)
        self.assertIsNone(parent._baseline)

    def test_changed_private_input_full_id_foreign_and_replacement_refuse(self):
        parent,stamp=self.ready();child,baseline=handoff.capture_ready(self.receipts,self.root,self.env)
        self.manifest.write_bytes(self.original)
        self.model['records']={k:r for k,r in self.model['records'].items() if r['project']=='foreign'}
        self.model['records']['c'*64]['created']='2026-10-14T01:02:04Z';self.write()
        with self.assertRaises(Refusal):handoff.accept(parent,self.receipts,stamp)
        self.assertTrue(parent._post_attempted)
        with self.assertRaises(Refusal):handoff.accept(parent,self.receipts,stamp)
        path=self.receipts/'association.json';path.write_text('{"secret":"SEEDED_SECRET"}')
        with self.assertRaises(Refusal) as caught:handoff.read(path,self.receipts,stamp)
        self.assertNotIn('SEEDED',str(caught.exception))

    def test_private_permissions_truncation_duplicate_and_live_baseline_required(self):
        parent,stamp=self.ready()
        self.model['records']={k:r for k,r in self.model['records'].items() if r['project']=='foreign'};self.write()
        with self.assertRaises(Refusal):handoff.capture_ready(self.receipts,self.root,self.env)
        self.assertFalse((self.receipts/'services.json').exists())
        path=self.receipts/'association.json';path.chmod(0o644)
        with self.assertRaises(Refusal):handoff.read(path,self.receipts)
        path.chmod(0o600)
        for raw in ('{','{"schema":1,"schema":1}'):
            path.write_text(raw)
            with self.assertRaises(Refusal):handoff.read(path,self.receipts)

if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *unused:os._exit(124));signal.alarm(60)
    unittest.main()
