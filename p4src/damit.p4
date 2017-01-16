/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type tag_t {
    fields {
        id: 4;
        itself: 1;
        mark: 1;
        border: 1;
        add: 1;
        src: 32;
        dst: 32;
        dist: 8;
    }
}

header_type general_metadata_t {
    fields {
        nhop_ipv4 : 32;
        random : 8;
        has_trace: 1;
        reg: 32;
    }
}

/*header_type intrinsic_metadata_t {
    fields {
        ingress_global_timestamp : 48;
    }
}

metadata intrinsic_metadata_t intrinsic_metadata;

header_type queueing_metadata_t {
    fields {
        enq_timestamp: 48;
        enq_qdepth: 16;
        deq_timedelta: 32;
        deq_qdepth: 16;
    }
}

metadata queueing_metadata_t queueing_metadata;*/

#define ETHERTYPE_IPV4 0x0800
// Probability of marking a packet is: 1 / (PROBABILITY + 1)
#define PROBABILITY 49
#define PKTS_THRESHOLD 7
#define MARK_THRESHOLD 5
#define APPLY_MARK 0
#define APPLY_RATE 0

header ethernet_t ethernet;
header ipv4_t ipv4;
header tag_t tag;
metadata general_metadata_t gmeta;

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(current(0, 4)) {
        0 : parse_tag;
        4 : parse_ipv4;
        default: ingress;
    }
}

parser parse_tag {
    extract(tag);
    return parse_ipv4;
}

parser parse_ipv4 {
    extract(ipv4);
    return ingress;
}

field_list clone_list {
    standard_metadata;
    gmeta;
}

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}


action _drop() {
    drop();
}


action _no_op() {
    no_op();
}


action set_nhop(nhop_ipv4, port) {
    modify_field(gmeta.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
}

table ipv4_lpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_nhop;
        _drop;
    }
    size: 1024;
}

register fwd_register {
    width: 32;
    static: forward;
    instance_count: 512;
}

register time_register {
    width: 48;
    static: forward;
    instance_count: 512;
}

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}

action set_dmac_then_increase(dmac, reg_idx) {
    set_dmac(dmac);
    register_read(gmeta.reg, fwd_register, reg_idx);
    add_to_field(gmeta.reg, 1);
    register_write(fwd_register, reg_idx, gmeta.reg);
    //register_write(time_register, reg_idx, intrinsic_metadata.ingress_global_timestamp);
}

table forward {
    reads {
        gmeta.nhop_ipv4 : exact;
    }
    actions {
        set_dmac_then_increase;
        set_dmac;
        _drop;
    }
    size: 512;
}

action remove_then_rewrite(smac) {
    remove_header(tag);
    rewrite_mac(smac);
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        remove_then_rewrite;
        _drop;
    }
    size: 256;
}

action add_tag(router_id, border_bit) {
    add_header(tag);
    modify_field(tag.id, 0);
    set_tag(router_id, border_bit);
}

action set_tag(router_id, border_bit) {
    modify_field(tag.src, router_id);
    modify_field(tag.dist, 0);
    modify_field(tag.add, 1);
    modify_field(tag.border, border_bit);
    modify_field(tag.itself, 0);
}

table addition {
    reads {
        tag: valid;
    }
    actions {
        add_tag;
        set_tag;
    }
    size: 2;
}

action set_dst_tag(router_id) {
    modify_field(tag.dst, router_id);
    modify_field(tag.add, 0);
    inc_tag();
}

action inc_tag() {
    add_to_field(tag.dist, 1);
}

action remove_self() {
    modify_field(tag.itself, 0);
}

table modification {
    reads {
        tag: valid;
        tag.add: exact;
        tag.itself: exact;
    }
    actions {
        inc_tag;
        set_dst_tag;
        remove_self;
        _no_op;
    }
    size: 3;
}

action config_action(has_trace) {
    modify_field_rng_uniform(gmeta.random, 0, PROBABILITY);
    modify_field(gmeta.has_trace, has_trace);
}

table configure {
    actions {
        config_action;
    }
    size: 1;
}

table set_clone {
    reads {
        standard_metadata.instance_type: exact;
    }
    actions {
        set_dmac;
        _no_op;
    }
    size: 1;
}

action add_mark(router_id, border_bit) {
    add_tag(router_id, border_bit);
    modify_field(tag.itself, 1);
    set_mark();
}

action set_mark() {
    modify_field(tag.mark, 1);
}

table marking {
    reads {
        tag: valid;
    }
    actions {
        add_mark;
        set_mark;
    }
    size: 2;
}

action clone_pkt(mirror_id) {
    clone_ingress_pkt_to_egress(mirror_id, clone_list);
}

table clone_for_trace {
    reads {
        gmeta.has_trace: exact;
    }
    actions {
        clone_pkt;
        _no_op;
    }
    size: 1;
}

table drop_table {
    actions {
        _drop;
    }
    size: 1;
}

control ingress {
    apply(configure);
    if(valid(ipv4) and ipv4.ttl > 0) {
        apply(ipv4_lpm);
        apply(forward);
    }
    if(gmeta.reg > PKTS_THRESHOLD and APPLY_RATE == 1) {
        apply(drop_table);
    }
    apply(clone_for_trace);
}

control egress {
    apply(set_clone);
    if(gmeta.reg > MARK_THRESHOLD and APPLY_MARK == 1) {
        apply(marking);
    }
    if(gmeta.random == 0) {
        apply(addition);
    }
    else {
        apply(modification);
    }
    apply(send_frame);
}


