#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 0x06;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}


header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<3> res;
    bit<3> ecn;
    bit<6> ctrl;
    bit<16> window;

    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<13> flow_hash;
    bit<32> syn_lastseen;
    bit<32> flow_counter;
    bit<32> flow_rtcounter;
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    tcp_t	    tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ParserImpl(packet_in packet,
                  out headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control verifyChecksum(in headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    /* index: flow hash, value: last Syn */
    register<bit<32>>(32w8192) syn_register;
    /* index: 0, value: flow counter */
    register<bit<32>>(32w1) flow_counter_register;
    /* index: counter, value: flow hash */
    register<bit<13>>(32w8192) flow_hash_register;
    /* index: hash, value: flow source IP */
    register<ip4Addr_t>(32w8192) flow_source_register;
    /* index: hash, value: flow source port (16 bit) */
    register<bit<16>>(32w8192) flow_sourceport_register;
    /* index: hash, value: flow destination IP */
    register<ip4Addr_t>(32w8192) flow_destination_register;
    /* index: hash, value: flow destination port (16 bit) */
    register<bit<16>>(32w8192) flow_destinationport_register;
    /* Number of retransmissions */
    register<bit<32>>(32w8192) flow_rtcounter_register;

    action drop() {
        mark_to_drop();
    }

    action save_flow_information(){
        /* get flow counter, inrement and save */
        flow_counter_register.read(meta.flow_counter, (bit<32>) 0);
        meta.flow_counter = meta.flow_counter + 1;
        /* save flow information to registers */
        flow_counter_register.write((bit<32>) 0, meta.flow_counter); 
        flow_hash_register.write((bit<32>) meta.flow_counter, meta.flow_hash);
        flow_source_register.write((bit<32>) meta.flow_hash, hdr.ipv4.srcAddr);
        flow_sourceport_register.write((bit<32>) meta.flow_hash, hdr.tcp.srcPort);
        flow_destination_register.write((bit<32>) meta.flow_hash, hdr.ipv4.dstAddr);
        flow_destinationport_register.write((bit<32>) meta.flow_hash, hdr.tcp.dstPort);
        /* increment rt counter per flow */
        flow_rtcounter_register.read(meta.flow_rtcounter, (bit<32>) meta.flow_hash);
        meta.flow_rtcounter = meta.flow_rtcounter + 1;
        flow_rtcounter_register.write((bit<32>) meta.flow_hash, meta.flow_rtcounter);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        /* Let's make sure we forward the packet */
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        /* If it is TCP, let's see if the packet is a retransmission */
        if (hdr.tcp.isValid()) {
            hash(meta.flow_hash, 
                HashAlgorithm.crc16, 
                (bit<13>)0, 
                { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort },
                (bit<26>) 13);
            syn_register.read(meta.syn_lastseen, (bit<32>) meta.flow_hash);
            /* If we have seen this packet before, we save the flow information */
            if (meta.syn_lastseen == hdr.tcp.seqNo) {
                /* Let's see if we have seen the same flow producing retransmissions */
                save_flow_information();
            }
            syn_register.write((bit<32>) meta.flow_hash, hdr.tcp.seqNo);
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control computeChecksum(
    inout headers  hdr,
    inout metadata meta)
{
    Checksum16() ipv4_checksum;

    apply {
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdrChecksum = ipv4_checksum.get(
                {
                    hdr.ipv4.version,
                    hdr.ipv4.ihl,
                    hdr.ipv4.diffserv,
                    hdr.ipv4.totalLen,
                    hdr.ipv4.identification,
                    hdr.ipv4.flags,
                    hdr.ipv4.fragOffset,
                    hdr.ipv4.ttl,
                    hdr.ipv4.protocol,
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr
                });
        }
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
ParserImpl(),
verifyChecksum(),
ingress(),
egress(),
computeChecksum(),
DeparserImpl()
) main;

