"""Actual locked formatter renderer: offline, private, no application/auth CPU."""
import hashlib,json,os,signal,subprocess,sys,tempfile,time,unittest,selectors
from pathlib import Path
sys.dont_write_bytecode=True
import auth_operation as auth
from private_caller_environment import construct
from private_cargo_cache import initialize
from container_identity_observer import host_capture

class ProducerControl(unittest.TestCase):
    def test_locked_pretty_formatter_both_styles_current_capture_and_sanitizer(self):
        root=Path(tempfile.mkdtemp(prefix='ur.005-b63-renderer.')).resolve();root.chmod(0o700)
        lock=Path('/Users/tom/ur.3AVM3Z/home/reference/main/apps/acme-api/Cargo.lock').read_bytes()
        self.assertEqual(hashlib.sha256(lock).hexdigest(),'cb602efabc528bc05c40432c7196c507fb16f2e2b4e3d9eca74271a4a7683b7f')
        api=root/'apps/acme-api';api.mkdir(parents=True);(api/'Cargo.lock').write_bytes(lock)
        env,_=construct(os.environ);env.update(HOME=str(root/'home'),UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT=str(root))
        (root/'home').mkdir(mode=0o700)
        env,receipt=initialize(root,root/'cargo',root/'target',env)
        renderer=root/'renderer';(renderer/'src').mkdir(parents=True)
        (renderer/'Cargo.lock').write_bytes(lock)
        (renderer/'Cargo.toml').write_text('[package]\nname="auth-formatter-control"\nversion="0.0.0"\nedition="2021"\n[dependencies]\ntracing="=0.1.44"\ntracing-subscriber="=0.3.23"\n')
        (renderer/'effigy.toml').write_text('[tasks.render]\nrun="cargo run --offline --quiet"\nrun_in="host"\n')
        (renderer/'src/main.rs').write_text(r'''fn main() {
 for ansi in [true, false] {
  let subscriber=tracing_subscriber::fmt().pretty().with_target(true).with_ansi(ansi).with_writer(std::io::stdout).finish();
  tracing::subscriber::with_default(subscriber, || {
   for (phase,outcome) in [("auth_verify_worker","valid"),("auth_verify_join","ok"),("api_login_response","success")] {
    tracing::info!(target: "underlay_profile_auth_diagnostic", correlation="fixture-auth-login",phase=phase,elapsed_ms=1u64,outcome=outcome);
   }
  });
 }
}''')
        binary='/Users/tom/.local/share/northstar/release-audits/effigy/bounded-refusal-accounting/final-main-bd259769/private-bin/effigy'
        # Compile warnings are not a native read-channel contract. This tiny
        # source-only renderer has independent bounded streams and no raw log.
        started=time.monotonic();deadline=started+120
        process=subprocess.Popen([binary,'render'],cwd=renderer,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        from pending_start_identity import IdentityUnknown, kernel_identity
        original=kernel_identity(process.pid)
        streams=selectors.DefaultSelector();buffers={'stdout':bytearray(),'stderr':bytearray()}
        for name,pipe in [('stdout',process.stdout),('stderr',process.stderr)]:streams.register(pipe,selectors.EVENT_READ,name)
        while streams.get_map():
            if time.monotonic()>=deadline:
                if kernel_identity(process.pid)==original:process.kill()
                process.wait(timeout=3);raise AssertionError('renderer_deadline')
            for key,_ in streams.select(.05):
                data=os.read(key.fileobj.fileno(),4096)
                if not data:streams.unregister(key.fileobj);continue
                buffers[key.data].extend(data)
                if len(buffers[key.data])>65536:
                    if kernel_identity(process.pid)==original:process.kill()
                    process.wait(timeout=3);raise AssertionError('renderer_capture_cap')
        code=process.wait(timeout=max(.001,deadline-time.monotonic()))
        streams.close();process.stdout.close();process.stderr.close()
        output=bytes(buffers['stdout']);result={'exit_code':code,'stderr_observed':len(buffers['stderr'])}
        self.assertEqual(code,0,'renderer_compile_or_execution_failed')

        self.assertEqual(result['exit_code'],0)
        lines=[x for x in output.splitlines() if auth.TARGET.encode() in x]
        self.assertEqual(len(lines),6);self.assertTrue(all(b'\x1b[' in x for x in lines[:3]));self.assertTrue(all(b'\x1b' not in x for x in lines[3:]))
        from reference_storage_probe import sanitize_service_log_line
        for line in lines:
            self.assertIsNotNone(auth.decode_trace(line));self.assertTrue(sanitize_service_log_line(line.decode()).startswith('AUTH_DIAGNOSTIC'))
        for group in (lines[:3],lines[3:]):
            path=root/'window.log';path.write_bytes(b'prior unrelated\n')
            before,_=auth.capture(path,root,lambda *a,**k:None)
            with path.open('ab') as f:f.write(b'\n'.join(group)+b'\n')
            events=[];latest,complete=auth.capture(path,root,lambda e,**k:events.append((e,k)),post=True,baseline=before['baseline'])
            self.assertTrue(complete);self.assertEqual(latest['total_observations'],3)
            self.assertTrue(events[-1][1]['current_operation_bound'])
        (root/'producer-receipt.json').write_text(json.dumps({'schema':'underlay.auth-formatter-control.v1','locked_tracing_subscriber':'0.3.23','locked_tracing':'0.1.44','source_hash':hashlib.sha256((renderer/'src/main.rs').read_bytes()).hexdigest(),'styles':[True,False],'target_lines':len(lines),'current_operation_complete':True,'offline':True,'exit':0,'stdout_bytes':len(output),'stderr_bytes':result['stderr_observed'],'private_cache_receipt_sha256':hashlib.sha256(json.dumps(receipt,sort_keys=True).encode()).hexdigest()}))
        (root/'producer-receipt.json').chmod(0o600)
        print('Private formatter control receipt:',root/'producer-receipt.json')

if __name__=='__main__':
    signal.alarm(120)
    unittest.main()
