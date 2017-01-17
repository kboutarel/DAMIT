#!/usr/bin/env python2

# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info, debug, output
from mininet.cli import CLI

from p4_mininet import P4Switch, P4Host

import sys
import argparse
import socket
import struct
import subprocess
import threading
import binascii
import networkx as nx
from time import sleep

_THRIFT_BASE_PORT = 9090
_ROUTER_ID = 0x78787800
MIRROR_ID = 250
APPLY_RATE = False

parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", required=True)
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)
#parser.add_argument('--num-hosts', help='Number of hosts to connect to switch',
                    #type=int, action="store", default=2)
parser.add_argument('--mode', choices=['l2', 'l3'], type=str, default='l3')
parser.add_argument('--json', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--pcap-dump', help='Dump packets on interfaces to pcap files',
                    type=str, action="store", required=False, default=False)
parser.add_argument('--cli', help='Command Line Argument for table updates',
                    type=str, action="store", required=True)
parser.add_argument('--topo', help='Topology file',
                    type=str, action="store", required=True)
parser.add_argument('--default', help='Default commands to execute on each switch',
                    type=str, action="store", default=None, required=False)

args = parser.parse_args()


class DAMITTopo(Topo):
    "Single switch connected to n (< 256) hosts."
    def __init__(self, sw_path, json_path, thrift_port, pcap_dump, switches, outer_hosts, inner_hosts, links, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        for s in xrange(switches):
            switch = self.addSwitch('s%d' % (s+1),
                                    sw_path = sw_path,
                                    json_path = json_path,
                                    thrift_port = _THRIFT_BASE_PORT + s,
                                    pcap_dump = True)

        for o in xrange(outer_hosts):
            outer = self.addHost('o%d' % (o+1),
                                 ip = "192.144.%d.10/24" % o,
                                 mac = "aa:df:bb:00:00:%02x" % o)

        for i in xrange(inner_hosts):
            inner = self.addHost('i%d' % (i+1),
                                 ip = "10.0.%d.10/24" % i,
                                 mac = "00:04:00:00:00:%02x" % i)

        for src,dst in links:
            self.addLink(src, dst)
            # If this is the link that is connected to an inner host
            if dst[0] == 'i':
                # Add the traceback tool to the switch
                tid = int(src[1:])
                trace = self.addHost('t%d' % tid,
                                     ip = "128.17.%d.10/24" % tid,
                                     mac = "00:04:00:11:11:%02x" % tid)
                self.addLink(src, 't%d' % tid)


def tconnect(self, switch_name):
    """
    Attach the traceback tool to a switch on the network.
    Example: tconnect s1
    This will create the host 'trace', if it does not exist, and connect it
    to the switch 's1'.
    """
    # Make sure the switch exists in the network
    output("Getting switch %s from the network... " % switch_name)
    switch = self.getLocals().get(switch_name, None)
    if switch is None or not isinstance(switch, P4Switch):
        output("ERROR\nSwitch %s does not exist\n" % switch_name)
        return
    output("Retrieved.\n")
    net = self.mn
    # Get the traceback host or create it if it does not exist
    output("Getting traceback tool trace from the network... ")
    trace = self.getLocals().get('trace', None)
    if trace is None:
        trace = net.addHost('trace', ip="128.0.0.4/24", mac="00:04:00:11:11:00")
        output("Created.\n")
    else:
        output("Retrieved.\n")
    # Make sure tool is not already connected
    output("Checking if traceback tool is not connected... ")
    if getattr(trace, 'connected', False) == True:
        output("ERROR.\nTraceback tool is already connected to %s\n" % trace.connectedTo)
        return
    else:
        output("Pass.\n")
    # Create the link between the tool and the switch
    output("Creating link to switch %s... " % switch_name)
    link = net.addLink(switch, trace)
    output("Created.\n")
    # Configure the tool
    output("Configuring traceback tool... ")
    trace.connected = True
    trace.connectedTo = switch
    trace.link = link
    trace.configDefault()
    trace.setARP(gateway_IP(trace.IP()), link.intf1.MAC())
    trace.setDefaultRoute("dev eth0 via %s" % gateway_IP(trace.IP()))
    output("Done.\n")
    # Add the port to the configuration of the switch
    output("Adding new port to switch configuration...\n")
    port = switch.ports[link.intf1]
    cmd = "port_add %s %s %s.pcap" % (link.intf1.name, port, link.intf1.name)
    #output("%s\n" % cmd)
    table_updates(switch, net.cli, [cmd])
    output("*** Done.\n")


def tdisconnect(self, delete):
    """
    Detach the traceback tool from the switch in the network and possibly delete
    the host.
    Example: tdisconnect [True/False]
    This will delete the link between the host 'trace' and the switch and delete
    the host 'trace' if the argument passed is True.
    """
    # Check the argument passed
    output("Checking argument... ")
    if delete != "True" and delete != "False":
        output("ERROR.\nWrong argument passed, need True or False\n")
        return
    output("Pass (%s)\n" % delete)
    net = self.mn
    # Get the traceback tool
    output("Getting traceback tool from the network... ")
    trace = self.getLocals().get('trace', None)
    if trace is None:
        output("ERROR.\nTraceback tool does not exist in the network\n")
        return
    output("Retrieved.\n")
    # if the tool is connected, delete the link
    output("Deleting link to switch... ")
    if trace.connected == True:
        port = trace.connectedTo.ports[trace.link.intf1]
        net.delLink(trace.link)
        output("Deleted.\n")
        output("Deleting port from switch configuration...\n")
        table_updates(trace.connectedTo, net.cli, ["port_remove %s" % port])
    else:
        output("ERROR.\nTraceback tool is not connected to any switches.\n")
    # Configure the tool
    trace.connected = False
    trace.connectedTo = None
    trace.link = None
    # Delete the host if needed
    if delete == "True":
        output("Deleting traceback tool... ")
        net.delHost(trace)
        output("Deleted.\n")
    output("*** Done.\n")


def parse_pkt(pkt):
    pktstring = binascii.hexlify(pkt)
    ethernet = pktstring[0:28]
    tag = None
    if pktstring[28] == '0':
        tag = pktstring[28:48]
        ip = pktstring[48:88]
    else:
        ip = pktstring[28:68]
    srcip = ip[24:32]
    dstip = ip[32:40]
    return ethernet, tag, srcip, dstip


def traceback(self, args, timeout=30):
    srcip, dstip = args.split()
    # Get the traceback tool from the network
    trace = self.getLocals().get('trace', None)
    if trace is None:
        print("Trace does not exist")
        return
    if trace.connected == False:
        print("Trace is not connected to any switch in the network")
        return
    port = trace.connectedTo.ports[trace.link.intf1]
    port_mirror = "mirroring_add %s %s" % (MIRROR_ID, port)
    set_clone = "table_set_default set_clone set_clone_bit 1"
    clone = "table_add clone set_dmac 1 => %s" % (trace.link.intf2.MAC())
    rewrite = "table_add send_frame rewrite_mac %s => %s" % (port, trace.link.intf1.MAC())
    table_updates(trace.connectedTo, self.mn.cli, [port_mirror, set_clone, clone, rewrite])


def read_topo(topo_file):
    "Read mininet topology"
    switches = 0
    outer_hosts = 0
    inner_hosts = 0
    links = []
    with open(topo_file, "r") as f:
        w, switches = f.readline().strip().split()
        assert(w == "switches")
        w, outer_hosts = f.readline().strip().split()
        assert(w == "outer_hosts")
        w, inner_hosts = f.readline().strip().split()
        assert(w == "inner_hosts")
        for line in f:
            src, dst = line.split()
            links.append((src,dst))
    return int(switches), int(outer_hosts), int(inner_hosts), links


def read_default(default_file):
    "Read default commands for the switches"
    default_cmds = []
    if default_file is None:
        return default_cmds
    with open(default_file, "r") as d:
        default_cmds = [line.strip() for line in d.readlines()]
    return default_cmds


def make_router_ids(switches):
    "Setup the router ids for the switches"
    info("*** Setting up router ids for the switches in the network\n")
    global _ROUTER_ID
    for i in xrange(len(switches)):
        ip_address = socket.inet_ntoa(struct.pack(">L", (_ROUTER_ID + 1)))
        info("%s.router_id: %s\n" % (switches[i].name, ip_address))
        switches[i].router_id = ip_address
        _ROUTER_ID += 1
    info("\n")


def gateway_IP(IP):
    "Return the gateway IP of the given IP address"
    # Assume /24
    return ".".join(IP.split('.')[:-1] + ["1"])


def setup_path(G, path):
    "Setup the interfaces of the nodes along the path"
    info("*** Setting up path from %s to %s\n" % (path[0], path[-1]))
    debug(path)

    # Setup the intfs of the hosts on both ends
    hsrc = G.node[path[0]]
    hdst = G.node[path[-1]]
    hsrc_ip = hsrc['node'].IP()
    hdst_ip = hdst['node'].IP()
    # Assume only one connection to the network from the hosts
    if hsrc['intfs'] == {}:
        connection = hsrc['node'].connectionsTo(G.node[path[1]]['node'])
        hintf = connection[0][0]
        sintf = connection[0][1]
        hsrc['intfs']= (gateway_IP(hsrc_ip), sintf.MAC())
    if hdst['intfs'] == {}:
        connection = hdst['node'].connectionsTo(G.node[path[-2]]['node'])
        hintf = connection[0][0]
        sintf = connection[0][1]
        hdst['intfs']= (gateway_IP(hdst_ip), sintf.MAC())

    # Setup the intfs of the switches along the path
    # <-- up  hsrc <---> s1 <---> s2 <---> ... <---> sn <---> hdst  down -->

    # This loop will setup the up and down intfs
    switch = G.node[path[1]]
    up = hsrc
    for i in xrange(1, len(path)-1):
        down = G.node[path[i+1]]

        # Find out if the switch is an up border switch
        switch['node'].border = True if up == hsrc else False

        # FInd out if the switch is connected to an inner host
        switch['node'].has_trace = True if down == hdst else False

        # switch_up_intf = [(IP(hsrc), sf_action, fwd_action, MAC(switch_up_intf), MAC(up_intf)), ...]
        up_link = up['node'].connectionsTo(switch['node'])
        up_intf = up_link[0][0]
        switch_up_intf = up_link[0][1]
        sf_action = 'remove_then_rewrite' if up == hsrc else 'rewrite_mac'
        entry = (hsrc_ip, sf_action, 'set', switch_up_intf.MAC(), up_intf.MAC())
        intf = switch['intfs'].get(switch_up_intf, [])
        if entry not in intf:
            intf.append(entry)
        switch['intfs'][switch_up_intf] = intf
        print "%s: %s" % (switch_up_intf, intf)
        #switch['intfs'][switch_up_intf] = (hsrc_ip, action, switch_up_intf.MAC(), up_intf.MAC())

        # switch_down_intf = [(IP(hdst), action, MAC(switch_down_intf), MAC(down_intf)), ...]
        down_link = switch['node'].connectionsTo(down['node'])
        switch_down_intf = down_link[0][0]
        down_intf = down_link[0][1]
        sf_action = 'remove_then_rewrite' if down == hdst else 'rewrite_mac'
        entry = (hdst_ip, sf_action, 'increase', switch_down_intf.MAC(), down_intf.MAC())
        intf = switch['intfs'].get(switch_down_intf, [])
        if entry not in intf:
            intf.append(entry)
        switch['intfs'][switch_down_intf] = intf
        print "%s: %s" % (switch_down_intf, intf)
        #switch['intfs'][switch_down_intf] = (hdst_ip, action, switch_down_intf.MAC(), down_intf.MAC())

        # Setup intf between switch and traceback host
        if switch['node'].has_trace:
            trace_name = 't%s' % switch['node'].name[1:]
            trace = G.node[trace_name]
            trace_link = switch['node'].connectionsTo(trace['node'])
            switch_intf = trace_link[0][0]
            trace_intf = trace_link[0][1]
            entry = (None, 'rewrite_mac', None, switch_intf.MAC(), trace_intf.MAC())
            intf = switch['intfs'].get(switch_intf, [])
            if entry not in intf:
                intf.append(entry)
            switch['intfs'][switch_intf] = intf
            print "%s: %s" % (switch_intf, intf)

        # Move the up and switch nodes
        up = switch
        switch = down


def make_commands(switch, intfs, default=[]):
    """
    Make the required commands for the table updates for the switch
    default: list of default commands that must appear on each switch
    """
    info("*** Making commands for %s\n" % switch.name)
    # Prototypes of commands
    send_frame = "table_add send_frame %s %s => %s"
    forward_set = "table_add forward set_dmac %s => %s"
    forward_increase = "table_add forward set_dmac_then_increase %s => %s %s"
    ipv4_lpm = "table_add ipv4_lpm set_nhop %s/32 => %s %s"
    add_tag = "table_add addition add_tag 0 => %s %s" % (switch.router_id, 1 if switch.border else 0)
    set_tag = "table_add addition set_tag 1 => %s %s" % (switch.router_id, 1 if switch.border else 0)
    add_mark = "table_add marking add_mark 0 => %s %s" % (switch.router_id, 1 if switch.border else 0)
    set_dst_tag = "table_add modification set_dst_tag 1 1 0 => %s" % (switch.router_id)
    configure = "table_set_default configure config_action %s" % (1 if switch.has_trace else 0)
    port_mirror = "mirroring_add %s %s"
    set_clone = "table_add set_clone set_dmac 1 => %s"

    cmds = [cmd for cmd in default]
    cmds.extend([add_tag, set_tag, add_mark, set_dst_tag, configure])
    reg_index = 0
    for intf, entries in intfs.items():
        port = switch.ports[intf]
        info("Intf: %s -- port: %s -- entries:%s\n" % (intf, port, entries))
        for entry in entries:
            ip, sf_action, fwd_action, smac, dmac = entry
            if ip is not None:
                if fwd_action == 'set':
                    cmds.append(forward_set % (ip, dmac))
                elif fwd_action == 'increase':
                    cmds.append(forward_increase % (ip, dmac, reg_index))
                    reg_index += 1
                cmds.extend([send_frame % (sf_action, port, smac),
                            ipv4_lpm % (ip, ip, port)])
            else: # Trace interface
                cmds.extend([send_frame % (sf_action, port, smac),
                            set_clone % (dmac),
                            port_mirror % (MIRROR_ID, port)])
    #info("\n".join(cmds) + "\n")
    return cmds


def table_updates(switch, cli, cmds):
    "Execute the table updates on the switch"
    info("*** Executing table updates for %s\n" % switch.name)
    updates = ["-c"] * (len(cmds) * 2)
    updates[1::2] = cmds
    table_update = [cli, "--thrift-port", str(switch.thrift_port)]
    table_update.extend(updates)
    info("\n".join(cmds) + "\n")
    #print table_update
    try:
        output = subprocess.check_output(table_update)
        #print output
    except subprocess.CalledProcessError as e:
        print e
        print e.output


def configure_network(net, links, default=[]):
    "Configure a mininet network topology for the traceback problem"
    info("*** Configuring the mininet network topology ***\n")

    G = nx.Graph()
    hosts = net.hosts
    switches = net.switches
    # Get the hosts and switches
    nodes = [(node.name, node) for node in hosts + switches]
    # Associate each name to its respective node in the graph
    [G.add_node(name, node=node, intfs={}) for name, node in nodes]
    # Add the edges to the graph
    G.add_edges_from(links)

    # Find the outer and inner hosts
    outer = []
    inner = []
    for host in hosts:
        if host.name[0] == 'o':
            outer.append(host.name)
        elif host.name[0] == 'i':
            inner.append(host.name)

    # Create mapping of intf->(IP address, sf_action, fwd_action, SMAC, DMAC) over paths between outer hosts to inner hosts
    # where sf_action = 'remove_then_rewrite' or 'rewrite_mac'
    # and fwd_action = 'increase' or 'set'
    shortest_paths = nx.shortest_path(G)
    for o in outer:
        for i in inner:
            shortest_path = shortest_paths[o][i]
            setup_path(G, shortest_path)

    # Create the commands to update the switches tables and set the arp table for the hosts
    for gnode in G.nodes(data=True):
        node = gnode[1]['node']
        intfs = gnode[1]['intfs']
        if gnode[0][0] == 'o' or gnode[0][0] == 'i':
            info("*** Setting up ARP table for %s\n" % gnode[0])
            info("%s <-> %s\n" % (intfs[0], intfs[1]))
            node.setARP(intfs[0], intfs[1])
            node.setDefaultRoute("dev eth0 via %s" % intfs[0])
        elif isinstance(node, P4Switch):
            updates = make_commands(node, intfs, default)
            table_updates(node, net.cli, updates)


def main():
    mode = args.mode

    # Read topology
    num_switches, outer_hosts, inner_hosts, links = read_topo(args.topo)

    # Read default commands
    default = read_default(args.default)

    topo = DAMITTopo(args.behavioral_exe,
                            args.json,
                            args.thrift_port,
                            args.pcap_dump,
                            num_switches,
                            outer_hosts,
                            inner_hosts,
                            links)

    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4Switch,
                  controller = None)
    net.start()

    # Set the cli to be the one passed to the program
    net.cli = args.cli

    # Set the router ids on the switches in the network
    make_router_ids(net.switches)

    sleep(1)

    # Configure the mininet network topology
    configure_network(net, links, default)

    sleep(1)

    if APPLY_RATE:
        for switch in net.switches:
            mitigation_cmd = "./register_reset.py %s %s fwd_register &" % (net.cli, switch.thrift_port)
            info("*** Setting mitigation on %s\n" % switch.name)
            try:
                switch.cmd(mitigation_cmd)
            except subprocess.CalledProcessError as e:
                print e
                print e.output

    '''for switch in net.switches:
        cmd = [net.cli, "--thrift-port", str(switch.thrift_port)]
        with open("mirror.txt", "r") as m:
            try:
                output = subprocess.check_output(cmd, stdin=m)
                print output
            except subprocess.CalledProcessError as e:
                print e
                print e.output'''

    #sw_mac = ["00:aa:bb:00:00:%02x" % n for n in xrange(num_hosts)]
    #sw_mac = ["00:aa:bb:00:00:00", "00:aa:bb:00:00:03"]
    #sw_addr = ["10.0.%d.1" % n for n in xrange(num_hosts)]


    """for n in xrange(num_hosts):
        h = net.get('h%d' % (n + 1))
        if mode == "l2":
            h.setDefaultRoute("dev eth0")
        else:
            h.setARP(sw_addr[n], sw_mac[n])
            h.setDefaultRoute("dev eth0 via %s" % sw_addr[n])"""

    #for n in xrange(num_hosts):
    #    h = net.get('h%d' % (n + 1))
    #    h.describe()

    sleep(1)

    CLI.do_tconnect = tconnect
    CLI.do_tdisconnect = tdisconnect
    CLI.do_traceback = traceback

    print "Ready !"

    CLI( net )
    if APPLY_RATE:
        # Kill the mitigation process, otherwise mininet won't stop
        stop_mitigation_cmd = "ps -ef | grep register_reset.py | awk '{print $2}' | xargs kill -9"
        info("*** Killing mitigation on switches\n")
        try:
            net.switches[0].cmd(stop_mitigation_cmd)
        except subprocess.CalledProcessError as e:
            print e
            print e.output
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    #setLogLevel('debug')
    main()
