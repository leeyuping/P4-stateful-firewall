/*
Copyright 2013-present Barefoot Networks, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Template headers.p4 file for basic_switching
// Edit this file as needed for your P4 program

// Here's an ethernet header to get started.

header ethernet_t {
	bit<48> dstAddr;
	bit<48> srcAddr;
	bit<16> etherType;
}
header cpu_ethernet_t {
	bit<48> dstAddr;
	bit<48> srcAddr;
	bit<16> etherType;
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
	bit<32>   srcAddr;
	bit<32>   dstAddr;
}

header tcp_t {
	bit<16> srcPort;
	bit<16> dstPort;
	bit<32> seqNo;
	bit<32> ackNo;
	bit<4>  dataOffset;
	bit<3>  res;
	bit<3>  ecn;
	bit<6>  ctrl;
	bit<16> window;
	bit<16> checksum;
	bit<16> urgentPtr;
}

header udp_t {
	bit<16> srcPort;
	bit<16> dstPort;
	bit<16> checksum;
	bit<16> hdr_length;
}

header icmp_t {
	bit<8> icmp_type;
	bit<8> icmp_code;
	bit<16> icmp_csum;
}

header time_info_t {
	bit<32> deq_timedelta;
	bit<32> ingress_global;
	bit<48> egress_global;
}
// what these lines are??
// header ethernet_t ethernet;
// header ipv4_t ipv4;
// header udp_t udp;
// header tcp_t tcp;
// header icmp_t icmp;
// header time_info_t time_info;

struct headers {
	ethernet_t ethernet;
	ipv4_t ipv4;
	udp_t udp;
	tcp_t tcp;
	icmp_t icmp;
	time_info_t time_info;
}

// struct state_meta_t {
struct state_meta_t {
	bit<32> src;
	bit<32> dst;
	bit<16> sport;
	bit<16> dport;
	bit<8> cur_state;
	bit<8> nxt_ctrl;
	// bit<8> cur_ctrl;
	bit<6> cur_ctrl;
	bit<8> predict;
	bit<8> predict2;
	bit<8> ack_seq_predict;
	bit<8> init;
	bit<8> temp;
	bit<8> temp2;
	bit<8> test;
	bit<18> index;
	// bit<32> index;
}

struct notify_digest_t {
	bit<18> index;
	// bit<32> index;
	bit<8> predict;
	bit<8> ack_seq_predict;
	bit<32> ackNo;
	bit<32> seqNo;
}

struct flowinit_digest_t {
	bit<32> src;
	bit<32> dst;
	bit<16> sport;
	bit<16> dport;
	bit<8> protocol;
}

struct pren_digest_t {
	bit<32> src;
	bit<32> dst;
	bit<16> sport;
	bit<16> dport;
	bit<8> protocol;
	bit<18> index;
	// bit<32> index;
}

struct fin_digest_t {
	bit<32> src;
	bit<32> dst;
	bit<16> sport;
	bit<16> dport;
	bit<8> protocol;
}

// struct metadata {
// 	state_meta_t state_meta;
// }
// metadata state_meta_t state_meta;
