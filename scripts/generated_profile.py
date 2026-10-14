"""Closed generated Colima/Lima mapping projection; never a general YAML loader."""
import json
import re
from container_identity_observer import Refusal


def uncomment(line):
    quote = None; escaped = False; i = 0
    match = re.search(r': +',line)
    value_start = match.end() if match else -1
    while i < len(line):
        c = line[i]
        if quote == '"':
            if escaped: escaped = False
            elif c == '\\': escaped = True
            elif c == quote: quote = None
        elif quote == "'":
            if c == "'":
                if i+1 < len(line) and line[i+1] == "'": i += 1
                else: quote = None
        elif c in ('"', "'") and i == value_start: quote = c
        elif c == '#' and (i == 0 or line[i-1].isspace()): return line[:i].rstrip()
        i += 1
    if quote: raise Refusal('profile_scalar_shape')
    return line.rstrip()


def document(raw):
    if type(raw) is not bytes or len(raw) > 1048576 or not raw.endswith(b'\n'):
        raise Refusal('mount_config_shape')
    try: text = raw.decode('utf8')
    except UnicodeError: raise Refusal('mount_config_encoding') from None
    if any(ord(c) < 32 and c not in '\n\t' for c in text): raise Refusal('mount_config_shape')
    tokens = []; keys = set(); block_base = None; block_indent = None
    for original in text.splitlines():
        if not original.strip(): continue
        spaces = len(original)-len(original.lstrip(' '))
        if block_base is not None:
            if spaces > block_base:
                if block_indent is None: block_indent = spaces
                if spaces < block_indent: raise Refusal('profile_block_indent')
                continue  # literal producer scalar, not keys or mount grammar
            block_base = block_indent = None
        if original.lstrip(' \t').startswith('#'): continue
        if '\t' in original[:len(original)-len(original.lstrip())]:
            raise Refusal('profile_structural_tab')
        line = uncomment(original)
        if not line.strip(): continue
        content = line[spaces:]
        if spaces == 0 and not content.startswith('- '):
            match = re.fullmatch(r'([A-Za-z][A-Za-z0-9_]*):(?: (.*))?',content)
            if not match: raise Refusal('profile_top_shape')
            if match[1] in keys: raise Refusal('mount_config_duplicate')
            keys.add(match[1])
        tokens.append((spaces,content))
        # Only producer literal/folded blocks; indentation indicators unsupported.
        if re.search(r': [|>][-+]?$',content): block_base = spaces
    return tokens


def scalar(value):
    if not value or value[0] in '&*!' or value.startswith(('[','{')):
        raise Refusal('mount_scalar')
    if value.startswith('"'):
        try: parsed = json.loads(value)
        except ValueError: raise Refusal('mount_scalar') from None
        if type(parsed) is not str: raise Refusal('mount_scalar')
        return parsed
    if value.startswith("'"):
        if not value.endswith("'"): raise Refusal('mount_scalar')
        return value[1:-1].replace("''", "'")
    if any(c.isspace() for c in value): raise Refusal('mount_scalar')
    return value


def sections(raw):
    result = {}; selected = None
    for indent,content in document(raw):
        if indent == 0 and not content.startswith('- '):
            key,value = content.split(':',1);selected=key
            result[key] = {'value':value.strip(),'children':[]}
        else:
            if selected is None: raise Refusal('profile_top_shape')
            result[selected]['children'].append((indent,content))
    return result


def private_mount(raw, root, *, sequence_indent=4):
    fields = sections(raw)
    mount = fields.get('mounts')
    if mount is None: raise Refusal('sole_private_mount_missing')
    if mount['value'] or not mount['children']: raise Refusal('sole_private_mount_shape')
    values = {}; started = False
    for indent,content in mount['children']:
        if indent == sequence_indent and content.startswith('- '):
            if started: raise Refusal('sole_private_mount_extra')
            started = True;content=content[2:]
        elif indent != sequence_indent+2 or not started: raise Refusal('sole_private_mount_shape')
        match = re.fullmatch(r'(location|mountPoint|writable): (.+)',content)
        if not match or match[1] in values: raise Refusal('sole_private_mount_shape')
        values[match[1]] = match[2]
    if not started or not {'location','writable'} <= set(values): raise Refusal('sole_private_mount_missing')
    if values['writable'] != 'true': raise Refusal('sole_private_mount_mismatch')
    original = str(root)
    for key in ('location','mountPoint'):
        value = scalar(values[key]) if key in values else original
        # ONLY one terminal slash is equivalent. Never resolve an observed path.
        if value not in (original,original+'/') or any(part in ('.','..') for part in value.split('/')):
            raise Refusal('sole_private_mount_mismatch')
    return {'mount_count':1,'original_root_matched':True,'writable':True}


def containerd_profile(raw):
    value = sections(raw).get('runtime')
    if value is None or value['children'] or scalar(value['value']) != 'containerd':
        raise Refusal('original_profile_runtime')
    return True
