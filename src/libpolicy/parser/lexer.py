import yaml
import re
import json
import pyang
import os
import sys

# holds bindings for both variables(bindings) and policies(policies)
bindings = {}
policies = []

# some fixed data here
# convert protocol names to codes
proto2num = dict(
    icmp = 1,
    tcp = 6,
    udp = 17,
    )
    
# convert ip strings to codes
ip2dl = dict(
    ipv4 = 0x800,
    ipv6 = 0x86dd,
    )

# describes a single service consisting of one or more protocols
class Service:
    protocols = None
    name = None
    def add_protocol(self,prot):
        self.protocols.append(prot)
    def __init__(self,name):    
        self.name = name
        self.protocols = list()
    
# describes a single protocol and port, eg TCP 443        
class Protocol:
    name = None
    port = None
    
# describes a group of similar 'things'. eg we can classify both http and https as 'www'
class Group:
    name = None
    members = None
    def add_member(self,member):
        self.members.append(member)
    def __init__(self,name):    
        self.name = name
        self.members = list()
        
# describes a single entity on the network, such as a host or router
class Entity:
    attribs = None
    name = None
    def add_attrib(self,attrib):
        self.attribs.append(attrib)
    def __init__(self,name):    
        self.name = name
        self.attribs = list()
        
# allows us to rename anything we want
class Alias:
    name = None
    real_name = None
    def __init__(self,name,real_name):    
        self.name = name
        self.real_name = real_name

# an attribute that provides information such as ip version and address
class PacketAttrib:
    name = None
    attrib = None
    def __init__(self,name,attrib):    
        self.name = name
        self.attrib = attrib

# a single rule specifying how the network is allowed to behave
class Policy:
    name = None
    action = None
    sub = None
    obj = None
    app = None
    def __init__(self,name,action,sub,obj,app):    
        self.name = name
        self.action = action
        self.sub = sub
        self.obj = obj
        self.app = app
        
def start(filename):
    src_file = open(filename,"r")
    line  = src_file.readline()
    while line:
        line = line.strip()
        #print(line)
        if line == '' or line[0] == '#':
            # print "commnet"
            pass
        else :
            tokens = line.split()
            if tokens[0] == "service":
                parseService(tokens)
            elif tokens[0] == "group":
                parseGroup(tokens)
            elif tokens[0] == "entity":
                parseEntity(tokens)
            elif tokens[0] == "policy":
                parsePolicy(tokens)
            elif tokens[0] == "alias":
                parseAlias(tokens)
        line = src_file.readline()
    generate(filename)
    
def parseService(line):
    if line[0] != "service":
        #print(line)
        raise Exception("parseService called but line not a service")
    else:
        service_obj = Service(line[1])
        protocol_obj = Protocol()
        protocol_obj.name = line[2]
        protocol_obj.port = line[3] 
        service_obj.add_protocol(protocol_obj)
        bindings[line[1]] = service_obj
    
def parseGroup(line):
    if line[0] != "group":
        #print(line)
        raise Exception("parseGroup called but line not a service")
    else:
        group_obj = Group(line[2])
        group_type = line[1] # currently IGNORED, maybe redundant?
        cur_index = 3
        while cur_index < len(line):
            if line[cur_index]=="}":
                break
            else:
                group_obj.add_member(bindings[line[cur_index]])
            cur_index = cur_index+1
        bindings[line[2]] = group_obj
        
def parseEntity(line):
    if line[0] != "entity":
        #print(line)
        raise Exception("parseEntity called but line not a entity")
    else:
        entity_name = line[1]
        if entity_name in bindings:
            entity_obj = bindings[line[1]]
        else:
            entity_obj = Entity(line[1])
            bindings[line[1]] = entity_obj
        
        if line[2] == "group":
            entity_obj.add_attrib(bindings[line[3]])
        else:
            entity_attrib = parseEntityAttrib(line[2:])
            entity_obj.add_attrib(entity_attrib)
        
def parseEntityAttrib(subline):
    #print(subline)
    if subline[0] == "service":
        service_name = subline[1]
        service_obj = bindings[service_name]
        return service_obj
    else:
        packet_attrib = PacketAttrib(subline[0],subline[1])
        return packet_attrib
        
def parsePolicy(line):
    if line[0] != "policy":
        #print(line)
        raise Exception("parsePolicy called but line not a policy")
    else:
        policy_obj = Policy(line[1],line[2],bindings[line[3]],bindings[line[4]],line[5])
        bindings[line[1]]=policy_obj
        policies.append(policy_obj)
        
def parseAlias(line):
    if line[0] != "alias":
        #print(line)
        raise Exception("parseAlias called but line not a alias")
    else:
        new_name = line[1]
        real_name = line[2]
        alias_real_obj = bindings[real_name]
        bindings[new_name] = alias_real_obj
    
# validates bindings and policies against yang definitions
# used to ensure we are generating good acls
# todo finish after yang is complete
def validate(): 
    #with open('bindings.json', 'w') as bf:
    #    json.dump(bindings, bf)
    #with open('policies.json', 'w') as pf:
    #    json.dump(bindings, pf)
    # load callum pyang thing here
    # yang = open("")
    # validate it
    
    return True #placeholder
    
# generates faucet acls using defined policies
# the ordering is a little strange but appears to return valid results...
def generate(filename):
    # print nice message if everything ok and continue
    if validate():
        print("Generating acl")
    # otherwise return and do not generate. Should/could validation occur earlier?
    else :
        print("Invalid policy file, cannot proceed")
        return
    global policies 
    data = {}
    data["dps"] = {}
    data["acls"] = {}
    # 1 acl per policy
    for policy in policies:
        data["acls"][policy.name] = dict()
        # obtain policy details from policy object
        pol_sub = policy.sub
        pol_obj = policy.obj
        pol_app = bindings[policy.app]
        # declaring info for rule generation
        nw_srcs = set()          
        nw_dsts = set()
        dst_protos_tmp = set() # bunch of services
        dst_protos = [] # bunch of protocols
        allow = ""
    
        # compiling nw_srcs
        for subattrib in pol_sub.attribs:
            if subattrib.name == 'ipv4' or subattrib.name == 'ipv6':
                nw_srcs.add(subattrib)
        # compiling nw_dsts
        for objattrib in pol_obj.attribs:
            if objattrib.name == 'ipv4' or objattrib.name == 'ipv6':
                nw_dsts.add(objattrib)
        # compiling dst_protos    
        # first isolate services
        if isinstance(pol_app,Group):
            dst_protos_tmp = list(pol_app.members)
        else:
            dst_protos_tmp.append(pol_app)
        # then retrieve protocols
        for service in dst_protos_tmp:
            dst_protos.extend(service.protocols)
        # calculating allow/deny
        if policy.action == "allow":
            allow_val = 1
        else:
            allow_val = 0
            
        # space counter, used as a 'hack' to make rule 'names' unique since python dicts do not allow duplicate keys
        spaces = ''
        
        # we must structure rules such that any valid combination of nw_src/nw_dst/dst_proto results in a separate rule due to our language allowing more complex specifications of each item than faucet acls
        for nw_src_val in nw_srcs:
            for nw_dst_val in nw_dsts:
                for dst_proto_val in dst_protos:
                    # check for invalid matchings where src is ipv4, dst ipv6 or vice versa
                    if nw_src_val.name != nw_dst_val.name:
                        continue
                    rule_name = "ruleSPACING"+spaces
                    spaces = spaces + "@"
                    nw_src_ip = nw_src_val.attrib
                    nw_dst_ip = nw_dst_val.attrib
                    # calculating nw_proto and dst port
                    nw_proto_val = proto2num[dst_proto_val.name]
                    dst_port_name = dst_proto_val.name+"_dst"
                    dst_port_num = dst_proto_val.port
                    # generate rule
                    data["acls"][policy.name][rule_name] = dict(
                        nw_src = nw_src_ip,
                        nw_dst = nw_dst_ip,
                        nw_proto = nw_proto_val,
                        dl_type = ip2dl[nw_src_val.name],
                        actions = dict(
                                    allow = allow_val,
                                    ),            
                    )
                    # have to do this separately because python doesnt let you init dict keys with variable values
                    data["acls"][policy.name][rule_name][dst_port_name] = dst_port_num
        
        
    # this needs to be streamlined in the future. ie make the replacements happen before writing 
    # to file, not write, read, then write again SLOW
    # figure out actual name of file(minus extensions)
    realfilename = os.path.splitext(filename)[0]
    # first dump the yaml to tmp file
    with open(realfilename+'.tmp', 'w') as acltmp:
        yaml.dump(data, acltmp, default_flow_style=False)    
    # open the tmp file again...
    with open(realfilename+'.tmp','r') as acltmp:
        acltmpdata = acltmp.read()
        #print(acltmpdata)
        # replace the padding with actual rule keyword
        newdata = re.sub("ruleSPACING@?", "rule",acltmpdata)
        # now write to proper yaml
        f = open(realfilename+".yaml",'w')
        f.write(newdata)
        f.close()    
        

print(sys.argv)
if len(sys.argv) == 1:
    start("test.txt")
else :
    start(sys.argv[1])