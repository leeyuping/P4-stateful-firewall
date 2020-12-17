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

// Template parser.p4 file for basic_switching
// Edit this file as needed for your P4 program

// This parses an ethernet header
#include <core.p4>
#include <v1model.p4>

#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_TIMEINFO 0x8888
#define UDP_PROTOCOL 17 
#define TCP_PROTOCOL 6 

@pragma parser_values_set_size 2


parser MyParser(packet_in packet,
                out headers hdr,
                inout state_meta_t state_meta,  // as call by address
                inout standard_metadata_t standard_metadata) {
                    
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_TIMEINFO : parse_time_info;
            default : accept;
        }
    }

    state parse_time_info {
        packet.extract(hdr.time_info);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        //state_meta.test = state_meta.test - 1;
        //set_metadata( state_meta.test, ipv4.protocol - 1);
        transition select(hdr.ipv4.protocol) {
            TCP_PROTOCOL : parse_tcp;
            UDP_PROTOCOL : parse_udp;
            1	:	parse_icmp;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.srcPort) {
            default : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition  select(hdr.tcp.srcPort) {
            default : accept;
        }
    }

}