import hashlib,json,os,signal,tempfile,unittest
from pathlib import Path
from private_cargo_cache import *

class CacheTests(unittest.TestCase):
    def fixture(self, checksum=None, root=None):
        root=Path(root) if root is not None else Path(tempfile.mkdtemp(prefix='private-cargo-control.'))
        checkout=root/'reference';api=checkout/'apps/acme-api';api.mkdir(parents=True)
        host=root/'host';raw=b'authentic-test-archive';sha=hashlib.sha256(raw).hexdigest()
        (api/'Cargo.lock').write_text('version = 4\n\n[[package]]\nname = "tiny"\nversion = "1.0.0"\nsource = "'+REGISTRY+'"\nchecksum = "'+(checksum or sha)+'"\n')
        archive=host/'registry/cache'/INDEX/'tiny-1.0.0.crate';archive.parent.mkdir(parents=True);archive.write_bytes(raw)
        index=host/'registry/index'/INDEX/'.cache/ti/ny/tiny';index.parent.mkdir(parents=True)
        item=json.dumps({'name':'tiny','vers':'1.0.0','cksum':sha,'deps':[]}).encode()
        index.write_bytes(b'\x03\x02\x00\x00\x00etag: "fixture"\x001.0.0\x00'+item+b'\x00')
        return root,checkout,host,{'HOME':str(root),'UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT':str(root)}
    def test_actual_constructor_and_frozen_inputs(self):
        root,checkout,host,env=self.fixture();original=dict(env);ambient=dict(os.environ)
        child,receipt=initialize(checkout,root/'cargo',root/'target',env,host_cache=host)
        self.assertEqual(env,original);self.assertEqual(dict(os.environ),ambient)
        self.assertTrue(verify(child,receipt));self.assertEqual(child['CARGO_NET_OFFLINE'],'true')
        projected=summary(receipt)
        self.assertLess(len(json.dumps(projected)),4096)
        self.assertEqual(projected['admission_sha256'],hashlib.sha256((root/'cargo/admission.json').read_bytes()).hexdigest())
        self.assertEqual(receipt['registry'][0]['package'],'tiny')
        changed=dict(child,CARGO_TARGET_DIR=str(root/'foreign'))
        with self.assertRaises(CacheRefused): verify(changed,receipt)
        (root/'cargo/registry/cache'/INDEX/'tiny-1.0.0.crate').write_bytes(b'changed')
        with self.assertRaisesRegex(CacheRefused,'private_cache_input_changed'):verify(child,receipt)
    def test_wrong_checksum_and_missing_archive(self):
        root,checkout,host,env=self.fixture('0'*64)
        with self.assertRaisesRegex(CacheRefused,'registry_archive_checksum'):initialize(checkout,root/'cargo',root/'target',env,host_cache=host)
    def test_wrong_git_commit_duplicate_and_unsafe_names(self):
        for suffix in ('source = "git+ssh://git@github.com/inflatable-cookie/underlay.git?tag=v0.10.3#'+'0'*40+'"\n','name = "other"\n'):
            with self.assertRaises(CacheRefused):lock_packages(('version = 4\n[[package]]\nname = "tiny"\nversion = "1"\n'+suffix).encode())
        with self.assertRaises(CacheRefused):lock_packages(b'version = 4\n[[package]]\nname = "../tiny"\nversion = "1"\n')
    def test_escape_symlink_and_credentials_refuse(self):
        root,checkout,host,env=self.fixture()
        with self.assertRaisesRegex(CacheRefused,'private_cache_path_escape'):initialize(checkout,root.parent/'escape',root/'target',env,host_cache=host)
        (root/'cargo').symlink_to(host,target_is_directory=True)
        with self.assertRaises(CacheRefused):initialize(checkout,root/'cargo',root/'target',env,host_cache=host)
        env['SSH_AUTH_SOCK']='seeded-secret'
        with self.assertRaises(CacheRefused):initialize(checkout,root/'another',root/'target',env,host_cache=host)
    def test_config_hooks_alternates_refuse_after_admission(self):
        for name in ('config.toml','credentials','git/db/new/hooks','git/db/new/objects/info/alternates'):
            root,checkout,host,env=self.fixture();child,receipt=initialize(checkout,root/'cargo',root/'target',env,host_cache=host)
            path=root/'cargo'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('seeded-secret')
            with self.assertRaises(CacheRefused):verify(child,receipt)
    def test_both_actual_callers_share_initializer(self):
        for filename in ('qualify-reference-optin.py','qualify-reference-container.py'):
            source=Path(__file__).with_name(filename).read_text()
            self.assertIn('initialize_private_cargo(',source)
            self.assertIn('private_cargo_cache.py',source)

if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(60);unittest.main()
