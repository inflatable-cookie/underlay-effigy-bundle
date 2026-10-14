"""One private finite qualification intent; no implicit renewal or runtime retry."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from container_identity_observer import Refusal, identity
from original_container_route import read_small
from service_baseline_handoff import write

INTENT=None
ROOT=None


def enter(stage):
    global INTENT,ROOT
    path=Path(os.environ.get('UNDERLAY_PROFILE_BATCH_INTENT',''))
    raw=read_small(path)
    if hashlib.sha256(raw).hexdigest()!=os.environ.get('UNDERLAY_PROFILE_BATCH_INTENT_SHA256'):raise Refusal('batch_intent_changed')
    value=json.loads(raw)
    if set(value)!={'schema','head','source','binary_sha256','started_at','deadline_at','stages','controls_sha256'} or value['schema']!='underlay.product-batch-intent.v1':raise Refusal('batch_intent_schema')
    from qualification_runtime import SUPPORTED_EFFIGY_SOURCE,SUPPORTED_EFFIGY_SHA256
    if value['source']!=SUPPORTED_EFFIGY_SOURCE or value['binary_sha256']!=SUPPORTED_EFFIGY_SHA256 or value['stages']!=['runtime','container']:raise Refusal('batch_input_changed')
    if any(type(value[key]) not in (int,float) for key in ('started_at','deadline_at')) or value['deadline_at']-value['started_at']!=14400 or not value['started_at']<=time.time()<value['deadline_at']:raise Refusal('batch_wall_expired')
    repo=Path(__file__).resolve().parents[1]
    def git(*args):return subprocess.run(['git',*args],cwd=repo,check=True,capture_output=True,text=True,timeout=10).stdout.strip()
    if git('rev-parse','HEAD')!=value['head'] or git('status','--porcelain'):raise Refusal('batch_source_head_changed')
    ROOT=path.parent;identity(ROOT,True)
    if hashlib.sha256(read_small(ROOT/'controls.json')).hexdigest()!=value['controls_sha256']:raise Refusal('batch_controls_changed')
    if stage not in value['stages']:raise Refusal('batch_stage_unknown')
    if stage=='container' and not (ROOT/'runtime.passed.json').exists():raise Refusal('batch_previous_stage_unqualified')
    write(ROOT/(stage+'.started.json'),ROOT,{'schema':'underlay.product-stage-start.v1','stage':stage,'intent_sha256':hashlib.sha256(raw).hexdigest()})
    INTENT=value
    return value


def cap(seconds):
    if INTENT is None:
        path=os.environ.get('UNDERLAY_PROFILE_BATCH_INTENT')
        if not path:return seconds  # hermetic controls, without a runtime intent
        raw=read_small(Path(path))
        if hashlib.sha256(raw).hexdigest()!=os.environ.get('UNDERLAY_PROFILE_BATCH_INTENT_SHA256'):raise Refusal('batch_intent_changed')
        value=json.loads(raw)
        remaining=value['deadline_at']-time.time()
        if remaining<=0:raise Refusal('batch_wall_expired')
        return min(seconds,remaining)
    remaining=INTENT['deadline_at']-time.time()
    if remaining<=0:raise Refusal('batch_wall_expired')
    return min(seconds,remaining)


def passed(stage, receipt):
    if INTENT is None:raise Refusal('batch_not_entered')
    cap(1)
    write(ROOT/(stage+'.passed.json'),ROOT,{'schema':'underlay.product-stage-pass.v1','stage':stage,
                                         'receipt_sha256':hashlib.sha256(Path(receipt).read_bytes()).hexdigest()})
