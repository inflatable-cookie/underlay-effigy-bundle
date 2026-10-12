"""Source-derived control model, not an executed Go/binary attestation.

The immutable Apache-2.0 nerdctl fixtures own FormatPorts/formatRange and tests.
This model is checked against those maintained input/output cases first, then
supplies cases to the actual native parser. No service/backend is contacted.
"""
import hashlib
from pathlib import Path
import re


def format_ports(mappings):
    groups={}
    for address,host,target,protocol in mappings:
        groups.setdefault((address,protocol),[]).append((host,target))
    displays=[]
    for (address,protocol),pairs in groups.items():
        pairs.sort()
        ranges=[];index=0
        while index<len(pairs):
            first=last=pairs[index]
            while index+1<len(pairs) and pairs[index+1]==(last[0]+1,last[1]+1):
                index+=1;last=pairs[index]
            ranges.append(f'{first[0]}->{first[1]}' if first==last else f'{first[0]}-{last[0]}->{first[1]}-{last[1]}')
            index+=1
        displays.append(address+':'+', '.join(ranges)+'/'+protocol)
    return ', '.join(sorted(displays))


def maintained_cases():
    root=Path(__file__).parent/'fixtures'
    source=(root/'nerdctl-231-formatter_test.go').read_bytes()
    if hashlib.sha256(source).hexdigest()!='1acd10f1155eb1d09b8661d1e00c44347532918242eb6130002c60d88c4745a2':
        raise ValueError('maintained formatter tests changed')
    text=source.decode().split('func TestFormatPorts(t *testing.T) {',1)[1]
    cases=[]
    for name,body,expected in re.findall(r'name: "([^"]+)",\s*input: \[\]cni.PortMapping\{(.*?)\n\t\t\texpected: "([^"]+)",',text,re.S):
        mappings=[]
        for host,target,protocol,address in re.findall(r'HostPort:\s*([0-9]+),\s*ContainerPort:\s*([0-9]+),\s*Protocol:\s*"([a-z]+)",\s*HostIP:\s*"([0-9.]+)",',body):
            mappings.append((address,int(host),int(target),protocol))
        if not mappings:raise ValueError('maintained mapping missing')
        cases.append((name,mappings,expected))
    if len(cases)!=5:raise ValueError('maintained cases incomplete')
    return cases
