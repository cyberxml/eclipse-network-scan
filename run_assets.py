#! /bin/python
from lxml import etree
import assets
import nmap
import os
import pickle

# start with blank document root if no document exists


# read the network config file(s)
cfgfile="inbox/network1.config"
n=assets.network()
ip0=None
ip1=None
ns=[]
dn=[]
a=assets.assets()
with open(cfgfile) as f:
    for line in f:
        if not line[0]=='#':
            s = line.strip().split(',')
            if s[0] == 'name':
                n.id=s[1]
            elif s[0] == 'site':
                a.id=s[1]
            elif s[0] == 'hosts':
                n.hosts=s[1]
            elif s[0] == 'ipstart':
                ip0=s[1]
            elif s[0] == 'ipend':
                ip1=s[1]
            elif s[0] == 'nameserver':
                 ns.append(s[1])
	elif s[0] == 'domainname':
                dn.append(s[1])
    if ip0 and ip1:
        n.iprange=[ip0,ip1]
    if len(ns) > 0:
        n.nameservers=ns
    if len(dn) > 0:
        n.domainames=dn

print(n.id)
print(n.hosts)
print(n.iprange)
print(n.nameservers)
print(n.domainnames)

a.add_network(n)
#print("--ONE---")
#print(a.toxml())

# -------------------------------------------------------------
# if no ping sweep file for this network, then run a new one
# -------------------------------------------------------------
pname="inbox/"+n.id+"-nmap-pingsweep.pkl"
if not os.path.isfile(pname):
    nm = nmap.PortScanner()
    nm.scan(hosts=n.hosts, arguments='-n -sP -PE')
    with open(pname,'w') as f:
        pickle.dump(nm, f, pickle.HIGHEST_PROTOCOL)
else:
    with open(pname) as f:
        nm = pickle.load(f)
    

# -------------------------------------------------------------
# parse the results into a list of nodes
# -------------------------------------------------------------
for h in nm.all_hosts():
    try:
        ipv4 = nm[h]['addresses']['ipv4']
    except:
        ipv4 = None
    try:
        mac = nm[h]['addresses']['mac']
    except:
        mac = "00:00:00:00:00:00"
    if ipv4 and mac:
        id2='-'.join([ipv4,mac])
        n.add_node(assets.node(id=id2,ipv4=ipv4,mac=mac))

#print("--TWO---")
#print(a.toxml())
# -------------------------------------------------------------
# using just the live hosts, do a top 100 scan (this is TCP only)
# -------------------------------------------------------------
pname="inbox/"+n.id+"-nmap-top100.pkl"
if not os.path.isfile(pname):
    ipv4s=(" ".join(n.get_node_ipv4s()))
    nm = nmap.PortScanner()
    nm.scan(hosts=ipv4s, arguments=' -sS -Pn --top-ports 100')
    with open(pname,'w') as f:
        pickle.dump(nm, f, pickle.HIGHEST_PROTOCOL)
else:
    with open(pname) as f:
        nm = pickle.load(f)

print(n.get_nodes().keys())

# -------------------------------------------------------------
# parse the results into a list of nodes
# -------------------------------------------------------------
for nn in n.nodes.values():
    try:
        for k in nm[nn.ipv4]['tcp'].keys():
            try:
                p=assets.port(id='/'.join([str(k),'tcp']))
                print nn.ipv4, nn.id,str(k) 
                nn.add_port(p)
            except:
               pass
    except:
        pass

#print("--THREE--")
#print(a.toxml())

# -------------------------------------------------------------
# using just the live ports, do a service version scan
# -------------------------------------------------------------
for nn in n.nodes.values():
    pname="inbox/"+nn.id+"-nmap-svcver.pkl"
    if not os.path.isfile(pname):
        portlist=[ i.split('/')[0] for i in nn.ports.keys()]
        if len(portlist)>0:
            portstr=','.join(portlist)
            nm = nmap.PortScanner()
            nm.scan(hosts=nn.ipv4, arguments='-sSV -Pn -p '+portstr)
        with open(pname,'w') as f:
            pickle.dump(nm, f, pickle.HIGHEST_PROTOCOL)
    else:
        with open(pname) as f:
            nm = pickle.load(f)
    try:
        for k in nm[nn.ipv4]['tcp'].keys():
            try:
                pid = '/'.join([str(k),'tcp'])
                print(nn.ipv4,pid)
                p = nn.get_ports()[pid]
                p.product = nm[nn.ipv4]['tcp'][k]['product']
                p.name = nm[nn.ipv4]['tcp'][k]['name']
                p.version = nm[nn.ipv4]['tcp'][k]['version']
                p.cpe = nm[nn.ipv4]['tcp'][k]['cpe']
                print(p.tostr(),'boo')
            except:
                pass
    except:
        pass
        
   
print("--FOUR--")
print(a.toxml())

exit()


