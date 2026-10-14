"""Qualification-only original rootful nerdctl route observation; no backend control."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import time
from container_identity_observer import Refusal, Observer, host_capture, identity, file_sha

OWNER_RECEIPT='/tmp/005-nerdctl-original-route-source/owner-source-receipt.json'
OWNER_SHA='6558a39207c4b9b7a2fc9065e6fea1d98b62f7912af0ff59c6bf53f64e831dd1'
NERDCTL_SOURCE='04f63fe15f3f8d77fe41e56ab7ff1d1f3e312860'
# Source-derived constants are not effective guest facts. Help must report the route.
SOURCE_DEFAULTS={'namespace':'default','address':'/run/containerd/containerd.sock'}
CONFIG_PATH='/etc/nerdctl/nerdctl.toml'
# Fixed qualification projection, not a nerdctl/provider API. No environment values,
# command payloads, config bytes or filenames are emitted. Utility failure refuses.
METADATA_SCRIPT='''set -eu
[ "$(/usr/bin/id -u)" = 0 ] || exit 61
[ "${CONTAINERD_NAMESPACE+x}${CONTAINERD_ADDRESS+x}${NERDCTL_TOML+x}${ROOTLESSKIT_STATE_DIR+x}" = "" ] || exit 62
p=$(command -v nerdctl)
case "$p" in /*) ;; *) exit 63 ;; esac
[ -f "$p" ] && [ -x "$p" ] && [ ! -L "$p" ] || exit 64
h=$(/usr/bin/sha256sum "$p"); h=${h%% *}
printf 'underlay.nerdctl-route-metadata.v1\\nrootful\\n%s\\n' "$h"
p=/etc/nerdctl/nerdctl.toml
if [ -e "$p" ] || [ -L "$p" ]; then
 [ -f "$p" ] && [ ! -L "$p" ] || exit 65
 h=$(/usr/bin/sha256sum "$p"); h=${h%% *}
 printf 'present\\n%s\\n' "$h"
else
 printf 'absent\\n-\\n'
fi
'''


def read_small(path, limit=1048576):
    before=identity(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:raw=stream.read(limit+1)
    if len(raw)>limit:raise Refusal('original_input_cap')
    if identity(path)!=before:raise Refusal('original_input_changed')
    return raw


def admit_sources(receipt=None):
    if receipt is None:receipt=OWNER_RECEIPT
    try:
        path=Path(receipt).resolve(strict=True)
        raw=read_small(path)
        if hashlib.sha256(raw).hexdigest()!=OWNER_SHA:raise Refusal('route_source_receipt_mismatch')
        value=json.loads(raw);sources={}
        for row in value['files']:
            if 'file' not in row:continue # failed guessed URL remains metadata history
            source=Path(row['file']).resolve(strict=True)
            if source.stat().st_size!=row['bytes'] or file_sha(source,1048576)!=row['sha256']:
                raise Refusal('route_source_changed')
            sources[row['path']]=row['sha256']
        if value['nerdctlCommit']!=NERDCTL_SOURCE or len(sources)!=12:raise Refusal('route_source_identity')
        return {'owner_receipt_sha256':OWNER_SHA,'nerdctl_source':NERDCTL_SOURCE,
                'source_digests':sources,'source_defaults':copy.deepcopy(SOURCE_DEFAULTS),
                'binary_source_attested':False}
    except Refusal:raise
    except Exception:raise Refusal('route_source_unavailable') from None


def metadata(raw):
    if type(raw) is not bytes or len(raw)>256:raise Refusal('route_metadata_cap')
    try:lines=raw.decode('ascii').splitlines()
    except Exception:raise Refusal('route_metadata_encoding') from None
    if not raw.endswith(b'\n') or raw.count(b'\n')!=5 or b'\r' in raw or len(lines)!=5 or lines[:2]!=['underlay.nerdctl-route-metadata.v1','rootful']:
        raise Refusal('route_privilege_or_metadata')
    if not re.fullmatch('[a-f0-9]{64}',lines[2]):raise Refusal('route_binary_digest')
    if lines[3] not in ('present','absent') or (lines[3]=='present' and not re.fullmatch('[a-f0-9]{64}',lines[4])) or (lines[3]=='absent' and lines[4]!='-'):
        raise Refusal('route_config_identity')
    return dict(binary_sha256=lines[2],config_selection=CONFIG_PATH,config_state=lines[3],config_sha256=None if lines[4]=='-' else lines[4],rootful=True)


def help_route(raw):
    # main.go Long + custom usage, pflag1.0.10 FlagUsages/quoted string DefValue.
    # CLI values do NOT replace DefValue in help. Original invocation therefore
    # admits no route CLI flags at all; host/guest route overrides are refused.
    if type(raw) is not bytes or not raw or len(raw)>65536 or not raw.endswith(b'\n'):
        raise Refusal('route_help_framing')
    try:text=raw.decode('ascii')
    except Exception:raise Refusal('route_help_encoding') from None
    if any(ord(x)<32 and x!='\n' for x in text):raise Refusal('route_help_control')
    if text.count('Config file ($NERDCTL_TOML): ')!=1 or ('Config file ($NERDCTL_TOML): '+CONFIG_PATH+'\n') not in text:
        raise Refusal('route_config_selection')
    if text.count('Usage: nerdctl [command]\n')!=1 or text.count('\nFlags:\n')!=1 or not text.endswith("Run 'nerdctl COMMAND --help' for more information on a command.\n\n"):
        raise Refusal('route_help_producer')
    result={}
    descriptions={'namespace':'containerd namespace, such as "moby" for Docker, "k8s.io" for Kubernetes [$CONTAINERD_NAMESPACE]',
                  'address':'containerd address, optionally with "unix://" prefix [$CONTAINERD_ADDRESS]'}
    for key,description in descriptions.items():
        candidates=[line for line in text.splitlines() if re.match(r' *--'+key+r'(?: |$)',line)]
        if len(candidates)!=1:raise Refusal('route_help_duplicate_or_missing')
        match=re.fullmatch(r'      --'+key+r' string +'+re.escape(description)+r' \(default "([^"\\]+)"\)',candidates[0])
        if not match:raise Refusal('route_help_flag')
        result[key]=match[1]
    if not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}',result['namespace']) or not re.fullmatch(r'/[a-zA-Z0-9_./-]+\.sock',result['address']):
        raise Refusal('route_value_unqualified')
    result['help_sha256']=hashlib.sha256(raw).hexdigest()
    return result


class RouteReader:
    """Exact fresh-root caller transport; never discover/adopt an existing instance."""
    verify_cwd_correspondence=Observer.verify_cwd_correspondence
    _verify_cwd_correspondence=Observer._verify_cwd_correspondence
    def __init__(self, backend, env):
        backend.guard();backend.require_read_contract();backend.verify_environment(env)
        if not getattr(backend,'profile_binding',None):raise Refusal('original_profile_config_missing')
        self.backend=backend;self.context=backend.route_context();self.env=backend.reader_environment();self.cwd_evidence=[]
        self.source=copy.deepcopy(backend.route_source)
    def guard(self):
        self.backend.guard();self.backend.verify_tools()
        if self.context!=self.backend.route_context():raise Refusal('original_route_context_changed')
    def read(self, tail, deadline):
        allowed=[['sudo','nerdctl','--help'],['sudo','nerdctl','--version'],['sudo','/bin/sh','-c',METADATA_SCRIPT]]
        if tail not in allowed:raise Refusal('original_route_arguments')
        self.guard();c=self.context
        raw,capture=host_capture([c['limactl'],'shell','--workdir',c['cwd'],c['instance'],*tail],self.env,c['cwd'],min(deadline,time.monotonic()+8))
        self.guard();return raw,{k:v for k,v in capture.items() if k!='stdout_sha256'}
    def observe(self):
        deadline=time.monotonic()+30;self.verify_cwd_correspondence(deadline)
        first,c1=self.read(['sudo','/bin/sh','-c',METADATA_SCRIPT],deadline);before=metadata(first)
        version,c2=self.read(['sudo','nerdctl','--version'],deadline)
        if version!=b'nerdctl version 2.3.1\n':raise Refusal('route_reported_version')
        first_help,c3=self.read(['sudo','nerdctl','--help'],deadline);route=help_route(first_help)
        last,c4=self.read(['sudo','/bin/sh','-c',METADATA_SCRIPT],deadline)
        last_help,c5=self.read(['sudo','nerdctl','--help'],deadline)
        if metadata(last)!=before or help_route(last_help)!=route:raise Refusal('original_route_changed')
        if time.monotonic()>=deadline:raise Refusal('original_route_late')
        return {**route,**before,'source':copy.deepcopy(self.source),'reported_version':'2.3.1',
                'captures':[c1,c2,c3,c4,c5],'cwd_correspondence':copy.deepcopy(self.cwd_evidence),
                'atomic_config_route_snapshot':False,'backend_boot_verified':False,'vm_signal_authority':False,
                'remote_memory_bounded':False,'remote_cancellation_verified':False}
