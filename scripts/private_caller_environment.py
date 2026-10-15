"""Qualification-only child environment, constructed before ownership admission."""
import hashlib
import os
from pathlib import Path
from container_identity_observer import Refusal

CLASSES=('DOCKER_','CONTAINERD_','NERDCTL_','LIMA_','SSH','COLIMA_','XDG_')
# Explicit host tool/platform and current qualification invocation inputs only.
# Product secrets remain in the fixture vault and rendered declarations.
RETAIN=frozenset(('PATH','LANG','LC_ALL','LC_CTYPE','TMPDIR','TERM',
    'DEVELOPER_DIR','SDKROOT','MACOSX_DEPLOYMENT_TARGET','RUSTUP_HOME','RUSTUP_TOOLCHAIN',
    'UNDERLAY_PROFILE_EFFIGY_SOURCE','UNDERLAY_PROFILE_EFFIGY_BIN','UNDERLAY_REFERENCE_SOURCE',
    'UNDERLAY_PROFILE_STORAGE_DIAGNOSTICS_DIR','UNDERLAY_PROFILE_STORAGE_ONLY',
    'UNDERLAY_PROFILE_REMAINING_LIFECYCLE','UNDERLAY_PROFILE_PRIOR_DIAGNOSTICS_DIR',
    'UNDERLAY_PROFILE_PRIOR_RESTART_DIR','UNDERLAY_PROFILE_BATCH_INTENT',
    'UNDERLAY_PROFILE_BATCH_INTENT_SHA256','UNDERLAY_PROFILE_RESUME_AUTHORIZATION','UNDERLAY_PROFILE_RESUME_CHECKPOINT','UNDERLAY_PROFILE_COMMAND_NONCE','PYTHONDONTWRITEBYTECODE'))


def construct(ambient):
    original=dict(ambient)
    if any(type(k) is not str or type(v) is not str for k,v in original.items()):raise Refusal('private_environment_input_type')
    env={k:v for k,v in original.items() if k in RETAIN}
    env.update(GIT_CONFIG_GLOBAL='/dev/null',GIT_CONFIG_NOSYSTEM='1')
    # Rustup is a declared host tool/cache input, not a guest HOME fallback.
    if 'RUSTUP_HOME' not in env and original.get('HOME'):
        home=Path(original['HOME'])
        if not home.is_absolute():raise Refusal('private_tool_home_input')
        env['RUSTUP_HOME']=str(home/'.rustup')
    receipt={'schema':'underlay.private-caller-environment.v1',
             'excluded_class_counts':{p:sum(k.startswith(p) for k in original) for p in CLASSES},
             'routing_classes_excluded':True,'owned_roots_assigned_after_exclusion':True,
             'ambient_unchanged':dict(ambient)==original,
             'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    if not receipt['ambient_unchanged']:raise Refusal('ambient_environment_changed')
    return env,receipt


def verify_context(env, context):
    # Used AFTER construction: explicit overrides refuse; never strip/rebase here.
    allowed={'COLIMA_HOME','LIMA_HOME'}
    if any(k not in allowed and any(k.startswith(p) for p in CLASSES) for k in env):
        raise Refusal('private_environment_late_override')
    for key,field in (('HOME','private_home'),('COLIMA_HOME','colima_home'),('LIMA_HOME','lima_home')):
        if env.get(key)!=context[field]:raise Refusal('private_environment_root_changed')
    return True
