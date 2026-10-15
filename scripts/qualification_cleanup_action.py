"""Private qualification action wrapper; no product selector or supervisor."""
import importlib.util
import os
from pathlib import Path
import sys
import qualification_cleanup as cleanup
import service_baseline_handoff as services


def load_qualifier():
    path=Path(__file__).with_name('qualify-reference-optin.py')
    spec=importlib.util.spec_from_file_location('cleanup_qualifier',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class ListenerObserver:
    def __init__(self, qualifier, checkout, env, container="disposable_test", profile="test"):
        self.q=qualifier;self.checkout=checkout;self.env=env;self.container=container;self.profile=profile
    def match_role(self,state,role):return self.q.pending_start_identity.match_role(state,role)
    def kernel_identity(self,pid):return self.q.pending_start_identity.kernel_identity(pid)
    def boot_identity(self):return self.q.pending_start_identity.boot_identity()
    def group_members(self,pid):return self.q.pending_start_identity.group_members(pid)
    def socket_pids(self,address):
        return sorted(x['pid'] for x in self.q.RUNTIME.socket_snapshot(address)['listening_pids'])
    def address_accepts(self,address):return self.q.RUNTIME.address_accepts_connection(address)
    def gateway(self):
        return self.q.RUNTIME.gateway_json(self.q.EFFIGY,self.env,self.q.profile_root(self.checkout,self.profile),'status')
    def routes(self):
        gateway=self.gateway()
        if type(gateway.get('routes')) is not list or type(gateway.get('running')) is not bool:
            raise cleanup.CleanupUnknown('gateway_observation_unknown')
        routes=gateway['routes']
        if any(type(x) is not dict or not isinstance(x.get('domain'),str) or not isinstance(x.get('target'),str) for x in routes):
            raise cleanup.CleanupUnknown('gateway_route_schema')
        if len({x['domain'] for x in routes})!=len(routes):
            raise cleanup.CleanupUnknown('gateway_route_duplicate')
        return routes
    def route_matches(self,state):
        routes=self.routes();matches=[x for x in routes if x.get('domain')==state['route_domain']]
        return len(matches)==1 and matches[0].get('target')==state['address']
    def route_absent(self,state):
        return not any(x.get('domain')==state['route_domain'] for x in self.routes())
    def capture(self):
        states={name:self.q.listener_state(self.checkout,name,self.env,container=self.container)[1]
                for name in ('api','front','admin')}
        return cleanup.capture(states,self)


def main():
    # Only a fixture-owned checkout and a new private receipt directory are admitted.
    if len(sys.argv)!=3:raise cleanup.CleanupUnknown('wrapper_arguments')
    checkout=Path(sys.argv[1]).resolve(strict=True);root=Path(sys.argv[2]).resolve(strict=True)
    if not (checkout/'.git').exists() or not root.is_relative_to(checkout):
        raise cleanup.CleanupUnknown('fixture_boundary')
    info=root.stat()
    if info.st_uid!=os.geteuid() or info.st_mode&0o777!=0o700:
        raise cleanup.CleanupUnknown('receipt_root')
    env=dict(os.environ)
    association,_=services.read(root/'association.json',root)
    from private_caller_environment import verify_context
    verify_context(env,association['context'])
    from private_cargo_cache import verify_environment
    cargo_admission = str(Path(env.get("CARGO_HOME", "")) / "admission.json")
    if cargo_admission not in association["files"]:
        raise cleanup.CleanupUnknown("ready_cargo_context_changed")
    verify_environment(env)
    q=load_qualifier();q.EFFIGY=q.require_effigy_binary(env=env)
    observer=ListenerObserver(q,checkout,env)
    fixture=Path(association['context']['cwd'])
    reader,service_baseline=services.capture_ready(root,fixture,env)
    first_capture=True
    def capture():
        nonlocal first_capture
        if first_capture:
            first_capture=False
            return observer.capture()
        current=reader.snapshot()['containers']
        if current!={**service_baseline['owned'],**service_baseline['foreign']}:
            raise cleanup.CleanupUnknown('ready_service_baseline_changed')
        return observer.capture()
    def save(record):
        name='pending.json' if record['action']=='pending' else 'completed.json'
        cleanup.write_private(root/name,root,record)
    def action():
        # The fixed original Reference selector is dispatched exactly once with inherited
        # profile environment and the original 900s configured qualification bound.
        return q.RUNTIME.run([q.EFFIGY,'--repo',str(checkout),'acme-api/test'],cwd=checkout,
                             env=env,timeout=900,expected=None,print_output=False).returncode
    return cleanup.action_once(capture,action,save)


if __name__=='__main__':
    try:sys.exit(main())
    except BaseException as error:
        from dev.startup_evidence import NativeFailure
        if type(error) is NativeFailure:
            import json
            from qualification_refusal import project
            sys.stderr.write(json.dumps(project(error,'runtime_profile'))+'\n');sys.exit(1)
        # Never publish exception, child output, arguments or environment.
        sys.stderr.write('qualification_cleanup_action_refused\n');sys.exit(1)
