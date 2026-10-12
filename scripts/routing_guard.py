"""Finite readonly predicate evidence, with refusal enforced after decoding."""
import re
import secrets

from storage_correlation import (ROUTING_OVERRIDES, bounded_arguments, bounded_payload,
                                 shell_command, shell_region)


# This private capability names the shared command binding, not native/image
# HOME provenance. Baselines cannot authorize arbitrary supplied HOME values.
OWNER_CLIENT_COMMAND_INPUT = object()


def client_command_input(command, marker):
    return ('if test "${HOME+present}" != present; then underlay_home_state=absent; '
            'elif test -z "$HOME"; then underlay_home_state=empty; else underlay_home_state=present; fi; '
            'if test "${HOME-}" = /root; then underlay_home_agreement=1; else underlay_home_agreement=0; fi; '
            'HOME=/root; export HOME; '
            'if test "$HOME" = /root; then underlay_home_bound=1; else underlay_home_bound=0; fi; '
            "printf '"+marker+"_HOME|%s|%s|%s\\n' "+
            '"$underlay_home_state" "$underlay_home_agreement" "$underlay_home_bound"; '
            'test "$underlay_home_bound" = 1 || exit 1; '+command)


def client_input_projection(region, marker):
    line, separator, remainder = region.partition('\n')
    match = re.fullmatch(re.escape(marker)+r'_HOME\|(absent|empty|present)\|([01])\|1', line)
    if not separator or not match or (match[1]!='present' and match[2]!='0'):
        raise ValueError('client_command_input_refused')
    return remainder, {'inherited_presence':match[1], 'inherited_expected_agreement':match[2]=='1',
                       'input_presence':'present', 'input_expected_agreement':True,
                       'provenance':'owner_command_input', 'default_home_qualified':False}


def predicates(service):
    if service not in ('silo','silo_client'):
        raise ValueError('guard_service_refused')
    result=[(name,'expected_server_configdir' if service=='silo' and name=='MC_CONFIG_DIR' else 'absent') for name in ROUTING_OVERRIDES]
    result.append(('MC_HOST_local','expected_loopback_alias' if service=='silo' else 'absent'))
    if service=='silo_client':result.append(('HOME','expected_home'))
    return result


def guard_command(service):
    commands=['set -u']
    for name,rule in predicates(service):
        commands.append('if test "${'+name+'+present}" != present; then underlay_guard_state=absent; '
                        'elif test -z "$'+name+'"; then underlay_guard_state=empty; else underlay_guard_state=present; fi')
        condition=('test "${'+name+'+present}" != present' if rule=='absent' else
                   'test "${'+name+'+present}" = present && test "$'+name+'" = "'+
                   ('http://minioadmin:minioadmin@127.0.0.1:9000' if rule=='expected_loopback_alias' else '/tmp/.mc' if rule=='expected_server_configdir' else '/root')+'"')
        commands.append('if '+condition+'; then underlay_guard_match=1; else underlay_guard_match=0; fi')
        commands.append("printf 'GUARD|"+name+"|%s|%s\\n' \"$underlay_guard_state\" \"$underlay_guard_match\"")
    # This finite diagnostic transport succeeds only to preserve all predicate
    # records in native bounded-exec success. Python still refuses any mismatch.
    return '; '.join(commands)


def guard_projection(region,service):
    expected=predicates(service)
    if len(region.encode())>4096:raise ValueError('guard_framing_refused')
    lines=region.splitlines()
    if len(lines)!=len(expected):raise ValueError('guard_framing_refused')
    result=[]
    for line,(name,rule) in zip(lines,expected):
        match=re.fullmatch('GUARD\\|'+re.escape(name)+r'\|(absent|empty|present)\|([01])',line)
        if not match:raise ValueError('guard_framing_refused')
        state,agreement=match.groups();passed=agreement=='1'
        if (rule=='absent' and passed!=(state=='absent')) or (rule!='absent' and passed and state!='present'):
            raise ValueError('guard_record_refused')
        result.append({'predicate':name,'rule':rule,'presence':state,'agreement':passed})
    return {'service':service,'predicates':result,'guard_passed':all(r['agreement'] for r in result),
            'evidence':'readonly_predicate_evaluation_not_environment_dump'}


def finite_shell(call,journal,label,command,service='silo_client'):
    marker='UNDERLAY_'+secrets.token_hex(16).upper()
    if service not in ('silo','silo_client'):raise ValueError('guard_service_refused')
    if service=='silo_client':command=client_command_input(command,marker)
    try:
        output,outer=call(label,None,bounded_arguments(service,shell_command(command,marker)),timeout=10)
    except Exception as error:
        classification=('timeout' if isinstance(error,TimeoutError) else 'spawn_refused' if isinstance(error,OSError)
                        else {'command_spawn_refused':'spawn_refused','command_capture_timeout':'timeout','command_capture_truncated':'truncated'}.get(str(error),'dispatch_refused'))
        journal.append('shell_dispatch',operation=label,service=service,classification=classification,
                       guard_evidence='not_reached')
        raise ValueError('guard_dispatch_refused') from None
    try:
        output,projection=bounded_payload(output,outer,service)
    except (ValueError,TypeError,KeyError):
        journal.append('shell_dispatch',operation=label,service=service,classification='native_envelope_refused',
                       outer_exit=outer if type(outer) is int and -255<=outer<=255 else None,guard_evidence='not_reached')
        raise ValueError('bounded_envelope_refused') from None
    journal.append('native_bounded_completion',operation=label,service=service,**projection)
    if output is None:
        journal.append('shell_dispatch',operation=label,service=service,classification=projection['failure'],
                       guard_evidence='unavailable_native_failure_omits_command_bytes')
        raise ValueError('native_bounded_refusal')
    try:region,inner=shell_region(output,marker)
    except ValueError:
        journal.append('shell_dispatch',operation=label,service=service,classification='marker_refused',guard_evidence='not_reached')
        raise ValueError('guard_framing_refused') from None
    journal.append('shell_completion',operation=label,service=service,inner_exit=inner,outer_exit=outer,
                   region_bytes=len(region.encode()),framing='unique_marker')
    if outer!=0 or inner!=0:raise ValueError('shell_operation_refused')
    if service=='silo_client':
        try:region,input_record=client_input_projection(region,marker)
        except ValueError:
            journal.append('client_command_input',operation=label,classification='input_framing_refused')
            raise
        journal.append('client_command_input',operation=label,service=service,**input_record)
    return region


def evaluate_guard(shell,journal,service):
    region=shell('routing_environment_guard',guard_command(service),service=service)
    try:projection=guard_projection(region,service)
    except ValueError:
        journal.append('routing_guard',service=service,classification='malformed_predicate_evidence')
        raise
    journal.append('routing_guard',classification='predicates_complete',**projection)
    if not projection['guard_passed']:raise ValueError('routing_guard_refused')
    return projection
