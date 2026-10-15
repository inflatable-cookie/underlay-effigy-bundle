#!/usr/bin/env python3
"""Bundle-owned default/container Silo setup and bounded bootstrap."""
import argparse
import os
from pathlib import Path
import re
import profile_launcher as profiles


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('prepare','admit','reconcile'))
    parser.add_argument('--repo',required=True)
    parser.add_argument('--container',required=True)
    args=parser.parse_args()
    repo=Path(args.repo).resolve(strict=True)
    if not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_-]{0,63}',args.container):raise profiles.ProfileError('storage container refused')
    env=dict(os.environ)
    try:profiles.startup_evidence.configure(env,repo,'context' if args.action=='admit' else 'start','container')
    except Exception:profiles.startup_evidence.refuse('source_refused')
    if args.action=='prepare':
        profiles._prepare_silo_override(repo)
        return 0
    identity=profiles.verify_binary(env.get('UNDERLAY_PROFILE_EFFIGY_SOURCE'),env.get('UNDERLAY_PROFILE_EFFIGY_BIN'))
    root=env.get('EFFIGY_GATEWAY_PRIVATE_STATE_ROOT')
    if not root:raise profiles.ProfileError('default storage bootstrap requires explicit gateway state root')
    if args.action=='admit':return 0
    hosts=profiles._json_command(identity,repo,env,'container',args.container,'hosts')
    routes={}
    for name in ('front','admin'):
        declared=env.get('EFFIGY_PROFILE_'+name.upper()+'_DECLARED')
        matches=[r.get('effective') for r in hosts.get('routes',[]) if r.get('declared')==declared]
        if len(matches)!=1 or not isinstance(matches[0],str):raise profiles.ProfileError('default storage route unavailable')
        routes[name]=matches[0]
    gateway=profiles._gateway_json(identity,repo,env,'status','--private-state-root',root)
    context={'routes':routes,'https_port':profiles._gateway_https_port(gateway)}
    profiles._bootstrap_silo(identity,repo,env,args.container,context)
    return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        if profiles.startup_evidence.ACTIVE.get() is not None or type(error) is profiles.startup_evidence.NativeFailure:
            profiles.startup_evidence.cli_failure(error)
            raise SystemExit(1)
        print('STORAGE REFUSED: exact input, source or finite stage failed')
        raise SystemExit(1)
