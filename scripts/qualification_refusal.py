"""Closed owning refusal evidence; never native payload or cleanup authority."""
import ast
from container_identity_observer import Refusal
from pathlib import Path

STAGES=frozenset(('profile_binding','route_admission','route_transport','route_correspondence',
                  'route_metadata','route_help','runtime_profile','default_profile'))
# Derive the closed literal constructors from these exact owning source modules.
# No exception message, dynamic argument or external repository text is admitted.
def reasons():
    values=set()
    for name in ('generated_profile.py','fresh_backend_admission.py','original_container_route.py','container_identity_observer.py'):
        tree=ast.parse(Path(__file__).with_name(name).read_text())
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='Refusal' and node.args and isinstance(node.args[0],ast.Constant) and type(node.args[0].value) is str:
                values.add(node.args[0].value)
    return frozenset(values)

REASONS=reasons()
COUNTS=('stdout_observed','stderr_observed')
BOOLEANS=('stdout_eof','stderr_eof','leader_reaped','remote_cancellation_verified')


def project(error,stage):
    if stage not in STAGES:raise ValueError('refusal_stage_unqualified')
    args=getattr(error,'args',())
    reason=args[0] if type(error) is Refusal and len(args)==1 and type(args[0]) is str and args[0] in REASONS else 'unknown'
    evidence=getattr(error,'evidence',None);fields={}
    if type(evidence) is dict:
        for key in COUNTS:
            value=evidence.get(key)
            if type(value) is int and 0<=value<=2**64-1:fields[key]=value
        for key in BOOLEANS:
            if type(evidence.get(key)) is bool:fields[key]=evidence[key]
        code=evidence.get('exit_code')
        if type(code) is int and -128<=code<=255:fields['exit_code']=code
    return {'schema':'underlay.qualification.refusal.v1','stage':stage,'reason_id':reason,
            'exception_type':type(error).__name__[:64],'capture_available':type(evidence) is dict,
            'capture':fields,'settlement':getattr(error,'settlement_observation','unknown') if getattr(error,'settlement_observation','unknown') in ('unknown','leader_reaped') else 'unknown',
            'nonce_cleanup':getattr(error,'nonce_cleanup_observation','unknown') if getattr(error,'nonce_cleanup_observation','unknown') in ('unknown','verified') else 'unknown',
            'signal_authority':False,'remote_cancellation_verified':False}


def publish(error,stage,emit=None):
    record=project(error,stage)
    record['publication']='unavailable'
    if emit is not None:
        try:
            emit('qualification_refusal',projection={**record,'publication':'recorded'})
            record['publication']='recorded'
        except BaseException:record['publication']='unavailable'
    existing=getattr(error,'qualification_refusals',[])
    error.qualification_refusals=(existing+[record])[-8:]
    return record
