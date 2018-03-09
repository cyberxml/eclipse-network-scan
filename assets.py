from lxml import etree
from platform import node

servicetypes=[
    'web',
    'database',
    'nfs',
    'samba',
    'ldap',
    'smtp',
    'ftp',
    'rdp',
    'other',
    ]

protocols=[
    'tcp',
    'upd',
    ]

class assets:
    def __init__(self, id=None, root=None, doc=None, networks={}):
        if not root:
            #self.root = etree.XML('''<ai:assets xmlns:ai="http://scap.nist.gov/schema/asset-identification/1.1" xmlns:core="http://scap.nist.gov/schema/reporting-core/1.1" xmlns:cpe="http://cpe.mitre.org/naming/2.0" xmlns:p="urn:oasis:names:tc:ciq:xsdschema:xNL:2.0" xmlns:p1="urn:oasis:names:tc:ciq:xsdschema:xAL:2.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://scap.nist.gov/schema/asset-identification/1.1 asset-identification_1.1.0.xsd "></ai:assets>''')
            self.root = etree.XML('''<assets></assets>''')
        else:
            self.root = root
        self.id = id
        self.doc = etree.ElementTree(self.root)
        self.networks = networks

    
    def get_doc(self): return self.doc
    def tostring(self): return etree.tostring(self.doc,pretty_print=True)

    def get_networks(self): return self.networks
    def set_networks(self,networks): self.networks=networks
    def add_network(self,network): 
        if not network.id in self.networks.keys():
            self.networks[network.id] = network
        else:
            print("error: network already present")
    
    def toxml(self):
        self.root = etree.XML('''<assets></assets>''')
        self.doc = etree.ElementTree(self.root)
        xnetworks=etree.SubElement(self.root,'networks')
        xnetworks.set('id',self.id)
        try:
            for network in self.networks.keys():
                try:
                    xnetwork=etree.SubElement(xnetworks,'network')
                    xnetwork.set('id',self.networks[network].id)
                    try:
                        xnodes=etree.SubElement(xnetwork,'nodes')
                        for node in self.networks[network].nodes.values():
                            try:
                                xnode=etree.SubElement(xnodes,'node')
                                xnode.set('id',node.id)
                                for k in node.__dict__.keys():
                                    try:
                                        if ( not node.__dict__[k] is None 
                                          and len(node.__dict__[k])>0 
                                          and not isinstance(node.__dict__[k],list) 
                                          and not isinstance(node.__dict__[k],dict) ):
                                            xtmp=etree.SubElement(xnode,k)
                                            #xtmp.set('id',str(node.__dict__[k]))
                                            xtmp.text = str(node.__dict__[k])
                                    except:
                                        pass # no fields in port
                                if not node.ports is None and len(node.ports)>0:
                                    xports=etree.SubElement(xnode,'ports')
                                    for port in node.ports.values():
                                        try:
                                            xport=etree.SubElement(xports,'port')
                                            xport.set('id',port.id)
                                            for k in port.__dict__.keys():
                                                try:
                                                    if ( not port.__dict__[k] is None 
                                                      and len(port.__dict__[k])>0 
                                                      and not isinstance(port.__dict__[k],list) 
                                                      and not isinstance(port.__dict__[k],dict) ):
                                                        xtmp=etree.SubElement(xport,k)
                                                        #xtmp.set('id',str(port.__dict__[k]))
                                                        xtmp.text = str(port.__dict__[k])
                                                except:
                                                    pass # no fields in port
                                        except:
                                             pass # no port in ports
                            except:
                                 pass # no node in nodes
                    except:
                        pass # no nodes defined in network
                except:
                    pass # not network defined in networks
        except:
            pass # no network defined in networks
        return etree.tostring(self.doc,pretty_print=True)

class network:
    def __init__(self, id=None, hosts=None, iprange=[], nodes={}, domainnames=[], nameservers=[]):
        self.id = id
        self.hosts = hosts
        self.iprange = iprange
        self.nodes = nodes
        self.domainnames = domainnames
        self.nameservers= nameservers
    
    def get_hosts(self): return self.hosts
    def set_hosts(self,hosts): self.hosts=hosts

    def get_nodes(self): return self.nodes
    def set_nodes(self,nodes): self.nodes=nodes
    def get_node(self, id): return self.nodes[id]    
    def add_node(self,node): 
        try:
            self.nodes[node.id]=node
        except:
            print("error trying to add to nodes: "+node.id)

    def get_node_ipv4s(self):
        ips=[]
        for n in self.nodes.values():
            try:
                ips.append(n.ipv4)
            except:
                pass
        return ips

    def get_iprange(self): return self.iprange
    def set_iprange(self,ipstart,ipend): self.iprange=[ipstart,ipend]
    
    def get_domainnames(self): return self.domainnames
    def set_domainnames(self,dnames): self.domainnames=dnames
    def add_domainname(self,dname): self.domainnames.append(dname)
    
    def get_nameservers(self): return self.nameservers
    def set_nameservers(self,nsnames): self.nameservers=nsnames
    def add_nameserver(self,nsname): self.nameservers.append(nsname)

class node:
    def __init__(self, id=None, ipv4=None, mac=None, ports=None, hostname=None, fqdn=None, os=None, sw=None, users=None):
        self.ipv4 = ipv4
        self.mac = mac
        if id:
            self.id = id
        else:
            try:
                self.id = '-'.join([ipv4,mac])
            except:
                self.id = None
        if ports is None:
            self.ports = {}
        else:
            self.ports = ports
        self.os = os
        self.sw = sw
        self.hostname = hostname
        self.fqdn = fqdn
        self.users = users
    
    def get_ipv4(self):return self.ipv4
    def get_mac(self): return self.mac
    
    def get_ports(self): return self.ports
    def set_ports(self,ports): self.ports = ports
    def add_port(self,port): 
        if not port.id in self.ports.keys():
            self.ports[port.id] = port
        else:
            print("error: port already present")
    
    def get_hostname(self): return self.hostname
    def set_hostname(self,hostname): self.hostname = hostname
    
    def get_fqdn(self): return self.fqdn
    def set_fqdn(self,fqdn): self.fqdn = fqdn
    
    def get_users(self): return self.users
    def set_users(self,users): self.users = users
    
    def get_sw(self): return self.sw
    def set_sw(self,sw): self.sw = sw
    def add_sw(self,sw): self.sw.append(sw)
    

class port:
    def __init__(self, id=None, portnum=None, protocol=None, servicetype=None, product=None, name=None, version=None, cpe=None, conf=None):
        self.id = id
        try:
            self.portnum = int(portnum)
        except:
            self.portnum = 0
        if protocol in protocols:
            self.protocol = protocol
        else:
            self.protocol = 'other'
        if self.id is None:
            self.id = '/'.join([str(portnum),self.protocol])
        if servicetype in servicetypes:
            self.servicetype = servicetype
        else:
            self.servicetype = 'other'
        self.product = product
        self.name = name
        self.version = version
        self.cpe = cpe
        self.conf = str(conf)
        self.reset_servicetype()

    
    def get_portnum(self): return self._realPortNumber
    def get_protocol(self): return self.protocol

    def get_name(self): return self.name
    def set_name(self, name): 
        self.name = name
        self.reset_servicetype()

    def get_version(self): return self.version
    def set_version(self, version): self.version = version

    def get_cpe(self): return self.cpe
    def set_cpe(self, cpe): self.cpe = cpe

    def get_conf(self): return self.conf
    def set_conf(self, conf): self.conf = str(conf)
 
    def reset_servicetype(self):
        if self.name == 'http': self.servicetype = 'web'
 
    def tostr(self):
        strs=[self.id]
        if not self.portnum is None:
            strs.append(str(self.portnum))
        else:
            strs.append(' ')
        if not self.protocol is None:
            strs.append(self.protocol)
        else:
            strs.append(' ')
        if not self.servicetype is None:
            strs.append(self.servicetype)
        else:
            strs.append(' ')
        if not self.product is None:
            strs.append(self.product)
        else:
            strs.append(' ')
        if not self.name is None:
            strs.append(self.name)
        else:
            strs.append(' ')
        if not self.version is None:
            strs.append(self.version)
        else:
            strs.append(' ')
        if not self.cpe is None:
            strs.append(self.cpe)
        else:
            strs.append(' ')
        if not self.conf is None:
            strs.append(self.conf)
        else:
            strs.append(' ')
        return ','.join(strs)

