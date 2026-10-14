"""Finite private intent, immutable input and no replay controls; no runtime."""
import hashlib
import json
import os
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest.mock import patch
import qualification_batch as batch
from qualification_runtime import SUPPORTED_EFFIGY_SOURCE,SUPPORTED_EFFIGY_SHA256
from container_identity_observer import Refusal

class BatchControls(unittest.TestCase):
    def test_finite_cap_tighter_deadline_no_zero_or_renewal(self):
        previous=batch.INTENT
        try:
            batch.INTENT={'deadline_at':time.time()+2}
            self.assertLess(batch.cap(8),2);self.assertEqual(batch.cap(0.01),0.01)
            batch.INTENT={'deadline_at':time.time()-1}
            with self.assertRaises(Refusal):batch.cap(8)
        finally:batch.INTENT=previous
    def test_original_exact_inputs_and_exclusive_stage_no_retry(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve();root.chmod(0o700)
            controls=root/'controls.json';controls.write_text('{}');controls.chmod(0o600)
            now=time.time()
            value={'schema':'underlay.product-batch-intent.v1','head':'a'*40,
                'source':SUPPORTED_EFFIGY_SOURCE,'binary_sha256':SUPPORTED_EFFIGY_SHA256,
                'started_at':now,'deadline_at':now+14400,'stages':['runtime','container'],
                'controls_sha256':hashlib.sha256(controls.read_bytes()).hexdigest()}
            path=root/'intent.json';path.write_text(json.dumps(value));path.chmod(0o600)
            env={'UNDERLAY_PROFILE_BATCH_INTENT':str(path),'UNDERLAY_PROFILE_BATCH_INTENT_SHA256':hashlib.sha256(path.read_bytes()).hexdigest()}
            def git(args,**kw):
                from types import SimpleNamespace
                return SimpleNamespace(stdout='a'*40 if args[-1]=='HEAD' else '')
            previous=batch.INTENT
            try:
                with patch.dict(os.environ,env),patch.object(batch.subprocess,'run',git):
                    with self.assertRaises(Refusal):batch.enter('container')
                    self.assertEqual(batch.enter('runtime'),value)
                    with self.assertRaises(FileExistsError):batch.enter('runtime')
                    controls.write_text('{"unknown":true}')
                    with self.assertRaises(Refusal):batch.enter('container')
                    path.write_text('{}')
                    with self.assertRaises(Refusal):batch.enter('runtime')
            finally:batch.INTENT=previous

if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *unused:os._exit(124));signal.alarm(60)
    unittest.main()
