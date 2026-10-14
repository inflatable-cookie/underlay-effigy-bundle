"""One genuine pinned Silo witness in a separate new project, no published ports.

The catalog recipe is unchanged except removal of host publication. Running
ID/state preservation does not certify service health or arbitrary foreign VMs.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from container_identity_observer import Refusal, identity, file_sha


class ForeignFixture:
    def __init__(self, backend):
        backend.guard()
        if backend.start_record is not None:raise Refusal('foreign_intent_after_start')
        self.backend=backend;self.checkout=backend.paths['HOME']/'foreign-witness'
        self.checkout.mkdir(mode=0o700)
        subprocess.run(['git','init','-q',str(self.checkout)],check=True,capture_output=True,timeout=8,
                       env={**os.environ,'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'})
        catalog=self.checkout/'infra/dev/catalog/silo'
        catalog.mkdir(parents=True,mode=0o700)
        source=Path(__file__).parent/'dev/catalog/silo'
        fragment=(source/'compose.fragment.yml').read_text()
        publication='    ports:\n      - "{{ api_port }}:9000"\n      - "{{ console_port }}:9001"\n'
        if fragment.count(publication)!=1:raise Refusal('foreign_recipe_source_changed')
        for name,raw in [('service.toml',(source/'service.toml').read_bytes()),
                         ('compose.fragment.yml',fragment.replace(publication,'').encode())]:
            path=catalog/name
            with path.open('xb') as stream:stream.write(raw)
            path.chmod(0o600)
        manifest='''[containers]
default = "witness"
[containers.witness]
driver = "colima"
profile = "effigy"
project_name = "qualified-foreign-silo"
primary_service = "silo"
startup = "detached"
working_dir = "/workspace"
[containers.witness.services.silo]
catalog = "silo"
'''
        path=self.checkout/'effigy.toml';path.write_text(manifest);path.chmod(0o600)
        self.files={str(p):{'identity':identity(p),'sha256':file_sha(p,1048576)} for p in [path,catalog/'service.toml',catalog/'compose.fragment.yml']}
        self.sources={str(source/name):hashlib.sha256((source/name).read_bytes()).hexdigest() for name in ('service.toml','compose.fragment.yml')}
        self.intent={'schema':'underlay.foreign-container-intent.v1','startup_intent_sha256':backend.intent_sha256,
                     'checkout':str(self.checkout),'project':'qualified-foreign-silo','service':'silo',
                     'oneoff':False,'published_ports':False,'files':self.files,'sources':self.sources}
        self.path=backend.root/'foreign-container-intent.json'
        fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:json.dump(self.intent,stream,sort_keys=True)
        self.sha=file_sha(self.path,1048576);self.up_attempted=False;self.baseline=None

    def guard(self):
        self.backend.guard()
        if file_sha(self.path,1048576)!=self.sha:raise Refusal('foreign_creation_intent_changed')
        for path,row in self.files.items():
            if identity(path)!=tuple(row['identity']) or file_sha(path,1048576)!=row['sha256']:raise Refusal('foreign_recipe_changed')
        for path,sha in self.sources.items():
            if hashlib.sha256(Path(path).read_bytes()).hexdigest()!=sha:raise Refusal('foreign_source_changed')

    def start(self, binary, env, dispatch):
        self.guard()
        if self.up_attempted:raise Refusal('foreign_fixture_reuse')
        self.up_attempted=True
        return dispatch(binary,self.checkout,env,'container','up','--detach','--json',timeout=600,private=True)

    def owns_scope(self, backend, key):
        self.guard()
        return self.backend is backend and self.up_attempted and key==(str(self.checkout),'default')
