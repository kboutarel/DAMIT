#!/usr/bin/env python2
import sys
import socket
import binascii
import subprocess
import networkx as nx

APPLY_MARK = 0

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


def parse_tag(tag):
    flags = int(tag[1])
    mark = flags & 4 == 4
    border = flags & 2 == 2
    srcid = tag[2:10]
    dstid = tag[10:18]
    dist = int(tag[18:20], 16)
    return mark, border, srcid, dstid, dist


class AttackPath(object):
    """ Represent the attack path taken in the network """

    def __init__(self, srcip, dstip, total_pkts=100):
        self.srcip = srcip
        self.dstip = dstip
        self.farthest_id = dstip
        self.border_found = False
        self.longest_dist = 0
        self.pkts_recv = 0
        self.pkts_tagged = 0
        self.total_pkts = total_pkts
        self.completed = False
        self.DG = nx.DiGraph()
        self.DG.add_nodes_from([srcip, dstip])
        self.connected = self.get_connected()

    def get_connected(self):
        G = self.DG.to_undirected()
        return len(list(nx.connected_components(G)))

    def print_connected(self):
        G = self.DG.to_undirected()
        connected_comps = map(list, list(nx.connected_components(G)))
        print("Connected components: %s" % connected_comps)

    def print_edges(self):
        edges = self.DG.edges(data=True)
        edges.sort(key=lambda e: e[2]['dist'], reverse=True)
        print("Edges (src <---> dst : dist): %d" % len(edges))
        #for edge in edges:
        #    print("%s <---> %s : %d" % (edge[0], edge[1], edge[2]['dist']))

    def add(self, pkt):
        ethernet, tag, srcip, dstip = parse_pkt(pkt)
        if srcip != self.srcip or dstip != self.dstip or self.completed:
            return

        if APPLY_MARK == 0:
            #print "PKTS: %d" % self.pkts_recv
            if self.pkts_recv == self.total_pkts:
                self.complete_path()
                return
            self.pkts_recv += 1

        if tag is None:
            return

        is_marked, is_border, edge_src, edge_dst, dist = parse_tag(tag)
        if APPLY_MARK == 1 and not is_marked:
            return

        if APPLY_MARK == 1:
            print "PKTS: %d" % self.pkts_recv
            if self.pkts_recv == self.total_pkts:
                self.complete_path()
                return
            self.pkts_recv += 1

        self.pkts_tagged += 1
        if not self.border_found and is_border:
            self.border_found = True
            self.farthest_id = edge_src
            #print("Adding edge: %s <---> %s" % (self.srcip, edge_src))
            self.DG.add_edge(self.srcip, edge_src, {'dist': dist+1})
        elif not self.border_found and dist > self.longest_dist:
            self.longest_dist = dist
            self.farthest_id = edge_src
        if dist == 0:
            #print("Adding edge: %s <---> %s" % (edge_src, self.dstip))
            self.DG.add_edge(edge_src, self.dstip, {'dist': dist})
        elif dist != 0:
            #print("Adding edge: %s <---> %s" % (edge_src, edge_dst))
            self.DG.add_edge(edge_src, edge_dst, {'dist': dist})
        self.connected = self.get_connected()
        if self.border_found and self.connected == 1:
            self.complete_path()

    def complete_path(self):
        self.completed = True
        print("-----------------------")
        print("Attack Path: %s <---> %s" % (self.srcip, self.dstip))
        print("Total packets received: %d" % self.pkts_recv)
        print("Total packets tagged: %d" % self.pkts_tagged)
        percentage = float(self.pkts_tagged) / self.pkts_recv
        print("Percentage packets tagged: %.2f\n" % percentage)
        if self.border_found and self.connected == 1:
            print("Complete path found:")
            print("Border router: %s" % self.farthest_id)
            print("Path: %s" % nx.shortest_path(self.DG, self.srcip, self.dstip))
        else:
            print("Uncomplete path:")
            print("Farthest router found: %s" % self.farthest_id)
            self.print_connected()
        self.print_edges()
        print("-----------------------")


if __name__ == "__main__":
    dstip_arg = sys.argv[1]
    # Create raw socket matching on 0x0800 protocol (IPv4)
    raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    # Set the timeout on the socket
    raw_socket.settimeout(30)
    attack_paths = {}
    while True:
        pkt = raw_socket.recv(100)
        ethernet, tag, srcip, dstip = parse_pkt(pkt)
        if dstip_arg == dstip:
            #print parse_pkt(pkt)
            attack_path = attack_paths.get(srcip, None)
            if attack_path is None:
                attack_paths[srcip] = AttackPath(srcip, dstip)
                attack_paths[srcip].add(pkt)
            else:
                attack_path.add(pkt)
