"""Closed retained producer replay is a control, never runtime/cleanup credit."""
import copy,hashlib,json,os,signal,tempfile,unittest
from pathlib import Path
from reference_storage_probe import StorageDiagnosticJournal,decode_journal_rows

class JournalControls(unittest.TestCase):
    def fixture(self):
        root=Path(tempfile.mkdtemp(prefix='ur.005-journal64.')).resolve();root.chmod(0o700)
        (root/'fixture').mkdir(mode=0o700);(root/'evidence').mkdir(mode=0o700)
        return root,StorageDiagnosticJournal(root/'evidence/storage-diagnostics.jsonl',root/'fixture')

    def test_actual_closed_producer_roundtrip_reserve_and_changed_facts(self):
        path=Path('/Users/tom/ur.005-b63-product.nqv7Z4XQ/runtime-diagnostics/storage-diagnostics.jsonl')
        raw=path.read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),'eca3f6bdeccb592e0e5ab7ac6aeb53830882b485448012e5228382906dbee072')
        originals=[json.loads(x) for x in raw.splitlines() if json.loads(x)['event']!='diagnostic_capacity_refused']
        root,journal=self.fixture()
        for row in originals:
            try:journal.append(row['event'],**{k:v for k,v in row.items() if k not in ('schema','sequence','utc','monotonic_ns','event')})
            except RuntimeError:
                print('Closed control refusal event:',row['event'],'bytes:',journal._bytes,'root:',root)
                raise
        journal.enter_cleanup();journal.append('cleanup_completed',exit=0,proof='controlled_not_runtime')
        journal.close();text=(root/'evidence/storage-diagnostics.jsonl').read_text()
        decoded=decode_journal_rows(text)
        captured=[x for x in decoded if x['event'] in ('listener_probe_snapshot','managed_transition_snapshot')]
        expected=[x for x in originals if x['event'] in ('listener_probe_snapshot','managed_transition_snapshot')]
        self.assertEqual([(x['event'],x['snapshot']) for x in captured],[(x['event'],x['snapshot']) for x in expected])
        self.assertLess(len(text.encode()),106496)
        print('Closed producer control bytes:',len(text.encode()),'root:',root)
        self.assertTrue(any(x['event']=='cleanup_evidence_phase' and not x['budget_reset'] for x in decoded))
        # Changed owner/generation/causal/foreign facts never reuse an old node.
        root,journal=self.fixture()
        snapshots=[{'checkout':'/neutral/first','state':{'generation':'a'*32,'owner':{'generation':'a'*32},'foreign':'same'},'old':{'generation':'b'*32}},
                   {'checkout':'/neutral/first','state':{'generation':'c'*32,'owner':{'generation':'a'*32},'foreign':'changed'},'old':{'generation':'b'*32}}]
        for x in snapshots:journal.append('listener_probe_snapshot',snapshot=x,outcome='before_validation')
        journal.close();decoded=decode_journal_rows((root/'evidence/storage-diagnostics.jsonl').read_text())
        self.assertEqual([x['snapshot'] for x in decoded],snapshots)

    def test_sticky_identity_capacity_decoder_and_cleanup_no_reset(self):
        root,journal=self.fixture()
        with self.assertRaisesRegex(RuntimeError,'diagnostic_capacity_refused'):
            for i in range(1000):journal.append('closed_control',count=i,typed_static='x'*4096)
        with self.assertRaisesRegex(RuntimeError,'diagnostic_capacity_refused'):journal.enter_cleanup()
        with self.assertRaisesRegex(RuntimeError,'diagnostic_capacity_refused'):journal.append('cleanup_completed',exit=0)
        journal.close();self.assertLessEqual((root/'evidence/storage-diagnostics.jsonl').stat().st_size,131072)
        root,journal=self.fixture();journal.append('listener_probe_snapshot',snapshot={'state':{'generation':'a'*32,'typed_static':'x'*900}},outcome='before_validation');journal.close()
        path=root/'evidence/storage-diagnostics.jsonl';rows=[json.loads(x) for x in path.read_text().splitlines()]
        for kind in ('unknown','truncated','size','trailing','version','partial'):
            bad=copy.deepcopy(rows)
            if kind=='unknown':bad[0]['typed_record']='!'
            if kind=='truncated':bad[0]['typed_record']=bad[0]['typed_record'][:-4]
            if kind=='size':bad[0]['typed_record_bytes']+=1
            if kind=='trailing':bad[0]['typed_record']+='AAAA'
            if kind=='version':bad[0]['typed_record_encoding']='unknown'
            text=''.join(json.dumps(x)+'\n' for x in bad)
            if kind=='partial':text=text[:-1]
            with self.assertRaises((ValueError,RuntimeError)):decode_journal_rows(text)
        root,journal=self.fixture();path=root/'evidence/storage-diagnostics.jsonl'
        with path.open('ab') as f:f.write(b'changed')
        with self.assertRaisesRegex(RuntimeError,'diagnostic_journal_identity_refused'):journal.append('closed_control')
        with self.assertRaisesRegex(RuntimeError,'diagnostic_journal_identity_refused'):journal.enter_cleanup()
        journal.close()

if __name__=='__main__':
    signal.alarm(60);unittest.main()
