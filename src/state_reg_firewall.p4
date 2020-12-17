#include "includes/headers.p4"
#include "includes/parser.p4"
/*#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>
#include <tofino/constants.p4>
#include <tofino/stateful_alu_blackbox.p4>*/

#include <core.p4>
#include <v1model.p4>

#define FLOWCOUNT 262144//364000
#define FLOWCHECK 120000

control MyVerifyChecksum(inout headers hdr, inout state_meta_t state_meta) {
    apply {  }
}

control MyIngress(inout headers hdr,
                  inout state_meta_t state_meta,
                  inout standard_metadata_t standard_metadata) {
	action nop() {
	}

	action discard() {
			// ig_intr_md_for_tm.drop_ctl = 1;
			mark_to_drop(standard_metadata);
	}
	action _drop() {
			// drop();
		mark_to_drop(standard_metadata);
	}


	action _outbound_set() {
			state_meta.src = hdr.ipv4.srcAddr;
			state_meta.dst = hdr.ipv4.dstAddr;
			state_meta.sport = hdr.tcp.srcPort;
			state_meta.dport = hdr.tcp.dstPort;
	//        modify_field(state_meta.cur_ctrl, tcp.ctrl);
	}
	action _inbound_set() {
			state_meta.src = hdr.ipv4.dstAddr;
			state_meta.dst = hdr.ipv4.srcAddr;
			state_meta.sport = hdr.tcp.dstPort;
			state_meta.dport = hdr.tcp.srcPort;
	//        modify_field(state_meta.cur_ctrl, tcp.ctrl);
	}

	@pragma ternary 1
	table drop_tbl {
		actions = {
			discard;
		}
		default_action = discard();
		size = 1;
	}

	@pragma ternary 1
	table outbound_set {
		key = {
			// ig_intr_md.ingress_port: exact;
			standard_metadata.ingress_port: exact;
		}
		actions = {
			_outbound_set;
			_inbound_set;
		}
		size = 8;
	}

	// action _calc() {
	// 		bit_or(state_meta.predict2, state_meta.predict, state_meta.ack_seq_predict);
	// 		//bit_or(state_meta.temp2, state_meta.temp, state_meta.cur_state);
	// }

	// @pragma ternary 1
	// table calc_table {
	// 		actions = {
	// 				_calc;
	// 		}
	// 	default_action = _calc();
	// 	size = 1;
	// }
	// action _calc2() {
	// 		//bit_or(state_meta.predict2, state_meta.cur_state, state_meta.predict2);
	// 		// modify_field(state_meta.cur_state,1);
	// 		state_meta.cur_state = 1;
	// }

	// @pragma ternary 1
	// table calc_table2 {
	// 	actions = {
	// 		_calc2;
	// 	}
	// 	default_action = _calc2();
	// 	size = 1;
	// }

	register<bit<32>>(FLOWCHECK) ack_seq;
	// register ack_seq {
	// 	width : 32;
	// 	instance_count : FLOWCHECK;
	// }

	// blackbox stateful_alu ack_seq_predict {
	// reg : ack_seq;

	// initial_register_lo_value: 0;

	// condition_lo : register_lo == hdr.tcp.ackNo;

	// update_lo_1_predicate: condition_lo;
	// update_lo_1_value: hdr.tcp.seqNo + 1;

	// update_lo_2_predicate: not condition_lo;
	// update_lo_2_value: 128;

	// output_predicate : not condition_lo;
	// output_value : alu_lo;
	// output_dst : state_meta.ack_seq_predict;
	// }
	action _ack_seq_predict() {
			// ack_seq_predict.execute_stateful_alu(state_meta.index);
		if(hdr.tcp.ackNo != 0){
			state_meta.ack_seq_predict = 128;
		}
		
		// ack_seq.read()

		
	}

	@pragma ternary 1
	table ack_seq_predict {
		actions = {
			_ack_seq_predict;
		}
		default_action = _ack_seq_predict();
		size = 1;
	}
	register<bit<32>>(FLOWCHECK) state_reg;
	// register state_reg {
	// 	width : 32;
	// 	instance_count : FLOWCHECK;
	// }	
	// blackbox stateful_alu state_predict {
	// 	reg : state_reg;
	// 	initial_register_lo_value: 2;

	// 	condition_lo : register_lo == state_meta.cur_ctrl;

	// 	update_lo_1_predicate: condition_lo;
	// 	update_lo_1_value: state_meta.nxt_ctrl;

	// 	update_lo_2_predicate: not condition_lo;
	// 	update_lo_2_value: 127;

	// 	output_predicate : not condition_lo;
	// 	output_value : alu_lo;
	// 	output_dst : state_meta.predict;
	// }
	action _predict() {
			// state_predict.execute_stateful_alu(state_meta.index);
		if(state_meta.cur_ctrl != 2){
			state_meta.predict = 127;
		}
	}
	@pragma ternary 1
	table predict {
		actions = {
			_predict;
		}
		default_action = _predict();
		size = 1;
	}

	// counter(bit<32> size, CounterType.packets);
	direct_counter(CounterType.packets) syncounter;
	// counter syncounter {
	// 	type : packets;
	// 	direct : syntable;
	// }
	action _syn() {}
	table syntable {
		key = {
			state_meta.cur_ctrl : exact;
		}
		actions = {
			_syn;
		}
		counters = syncounter;
		size = 8;
	}


	//State pre-fetch register
	//Description:
	//The register(temp_reg) is used to store temporary state when three-handshaking is complete.
	register<bit<8>>(FLOWCHECK) temp_reg;
	// register temp_reg  {
	// width : 32;
	// instance_count : FLOWCHECK;
	// }
	// blackbox stateful_alu temp_write_reg {
	// reg : temp_reg;
	// initial_register_lo_value: 0;
	// update_lo_1_value: 1;
	// output_value : alu_lo;
	// output_dst : state_meta.cur_state;
	// //output_dst : state_meta.temp;
	// }
	action _temp_write() {
			// temp_write_reg.execute_stateful_alu(state_meta.index);
			// bit_or(state_meta.predict2, state_meta.predict, state_meta.ack_seq_predict);
		state_meta.cur_state = 1;
		temp_reg.write((bit<32>) state_meta.index, state_meta.cur_state);
		
	}
	@pragma ternary 1
	table temp_write {
		actions = {
			_temp_write;
		}
		default_action = _temp_write();
		size = 1;
	}




	// blackbox stateful_alu temp_read_reg {
	// reg : temp_reg;
	// output_value : register_lo;
	// output_dst : state_meta.cur_state;//state_meta.temp2;
	// //output_dst : state_meta.temp;//state_meta.temp2;
	// }
	action _temp_read() {
			// temp_read_reg.execute_stateful_alu(state_meta.index);
			// bit_or(state_meta.predict2, state_meta.predict, state_meta.ack_seq_predict);
		temp_reg.read(state_meta.cur_state, (bit<32>) state_meta.index);
	}
	@pragma ternary 1
	table temp_read {
		actions = {
			_temp_read;
		}
		default_action = _temp_read();
		size = 1;
	}


	// field_list notify_digest {
	// 	state_meta.index;
	// 	state_meta.predict;
	// 	state_meta.ack_seq_predict;
	// 	hdr.tcp.ackNo;
	// 	hdr.tcp.seqNo;
	// }


	action _notify(){
		// generate_digest(FLOW_LRN_DIGEST_RCVR, notify_digest);
		notify_digest_t notify_digest;
		notify_digest.index = state_meta.index;
		notify_digest.predict = state_meta.predict;
		notify_digest.ack_seq_predict = state_meta.ack_seq_predict;
		notify_digest.ackNo = hdr.tcp.ackNo;
		notify_digest.seqNo = hdr.tcp.seqNo;
		digest(1, notify_digest);
	}

	table notify {
		actions = {
			_notify;
		}
	default_action = _notify();
	size = 1;
	}


	/*
	Flow cntxt initilization
	*/


	// field_list flowinit_digest {
	// 	state_meta.src;
	// 	state_meta.dst;
	// 	state_meta.sport;
	// 	state_meta.dport;
	// 	hdr.ipv4.protocol;
	// }
	action flowcntx_init(){
			state_meta.init = 0;
			flowinit_digest_t flowinit_digest;
			flowinit_digest.src = state_meta.src;
			flowinit_digest.dst = state_meta.dst;
			flowinit_digest.sport = state_meta.sport;
			flowinit_digest.dport = state_meta.dport;
			flowinit_digest.protocol = hdr.ipv4.protocol;
			// generate_digest(FLOW_LRN_DIGEST_RCVR, flowinit_digest);
			digest(1, flowinit_digest);
	}
	@pragma ternary 1
	table flowinit {
		actions = {
			flowcntx_init;
		}
		default_action = flowcntx_init();
		size = 1;
	}

	/*
	Flow cntxt table
	*/

	action cntx(bit<8> set_state, bit<18> set_index) {
			state_meta.cur_state = set_state;
			state_meta.index = set_index;
			state_meta.cur_ctrl = hdr.tcp.ctrl;
			state_meta.cur_state = 1;
	}

	action on_miss() {
			// modify_field(state_meta.cur_ctrl, tcp.ctrl);
		state_meta.cur_ctrl = hdr.tcp.ctrl;
	}
	//@pragma stage 1 76800
	//@pragma stage 2 76800
	//@pragma stage 3 76800
	//@pragma state 4 76800
	@pragma idletime_precision 3
	table flowcntx {
		key = {
				state_meta.dst: exact;
				state_meta.src: exact;
				hdr.ipv4.protocol: exact;
				state_meta.sport: exact;
				state_meta.dport: exact;
		}
		actions = {
				cntx;
				on_miss;
		}
		default_action = on_miss();
		size = FLOWCOUNT;
		support_timeout = true;  
	}

	/*
	TRANSITION - it's a transition function that changes state to next what specified, and update state into flowcntx table
	*/ //除了改掉metadata，還需要改掉register???

	action trans(bit<8> next_state) {
			// modify_field(state_meta.nxt_ctrl, next_state);
			state_meta.nxt_ctrl = next_state;
	}
	@pragma ternary 1
	table transition_table {
		key = {
			state_meta.cur_state: exact;  // exact：與 match 值完全相同的 match  所以就是照用的意思？
			state_meta.cur_ctrl: exact;
		}
		actions = {
				trans;
		}
		size = 4;
	}


	// field_list pren_digest {
	// 	state_meta.src;
	// 	state_meta.dst;
	// 	state_meta.sport;
	// 	state_meta.dport;
	// 	hdr.ipv4.protocol;
	// 	state_meta.index;

	// }
	action prenn() {
		// modify_field(state_meta.temp, 1); //Set the temporary state for state pre-fetch register
		state_meta.temp = 1;
		pren_digest_t pren_digest;
		pren_digest.src = state_meta.src;
		pren_digest.dst = state_meta.dst;
		pren_digest.sport = state_meta.sport;
		pren_digest.dport = state_meta.dport;
		pren_digest.protocol = hdr.ipv4.protocol;
		pren_digest.index = state_meta.index;
		
		digest(1, pren_digest);
		// generate_digest(FLOW_LRN_DIGEST_RCVR, pren_digest);
	}
	@pragma ternary 1
	table pren {
		key = {
			state_meta.predict : exact;
			state_meta.ack_seq_predict: exact;
			state_meta.cur_ctrl : exact;
		}
		actions = {
			prenn;
		}
		size = 8;
	}


	// field_list fin_digest {
	// 	state_meta.src;
	// 	state_meta.dst;
	// 	state_meta.sport;
	// 	state_meta.dport;
	// 	hdr.ipv4.protocol;
	// }



	action _fin() {
		fin_digest_t fin_digest;
		fin_digest.src = state_meta.src;
		fin_digest.dst = state_meta.dst;
		fin_digest.sport = state_meta.sport;
		fin_digest.dport = state_meta.dport;
		fin_digest.protocol = hdr.ipv4.protocol;
		digest(1, fin_digest);
		// generate_digest(FLOW_LRN_DIGEST_RCVR, fin_digest);
	}
	@pragma ternary 1
	table fin {
		key = {
			state_meta.cur_state : exact;
			state_meta.cur_ctrl : exact;
		}
		actions = {
			_fin;
		}
		//default_action : _fin();
		size = 8;
	}

	/*   State-Action table */
 

	action stateaction(bit<9> egress_port){
		// modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_port);
		standard_metadata.egress_port = egress_port;
		// ig_intr_md_for_tm.ucast_egress_port = egress_port;
		//modify_field(state_meta.ingress_global_tstamp, ig_intr_md_from_parser_aux.ingerss_global_tstamp);
	}

	@pragma ternary 1
	table stateAction {
		key = {
			//ipv4.dstAddr : exact;
			standard_metadata.ingress_port: exact;
		}
		actions = {
			stateaction;
		}
		size = 8;
	}


	// action eg_add_time_info() {
	// 	add_header(time_info);

	// 	time_info.deq_timedelta = eg_intr_md.deq_timedelta;
	// 	time_info.ingress_global = ig_intr_md_from_parser_aux.ingress_global_tstamp;
	// 	time_info.egress_global = eg_intr_md_from_parser_aux.egress_global_tstamp;
	// 	hdr.ethernet.etherType = 0x8888;
	// }


	// table eg_time_info_table {
	// 	actions = {
	// 		eg_add_time_info;
	// 	}
	// 	default_action = eg_add_time_info;
	// }

    apply {
		outbound_set.apply();

		// on_miss {
		if(!flowcntx.apply().hit) {
			if ( state_meta.cur_ctrl == 2 || hdr.ipv4.protocol == 7) {
				// apply(flowinit);  // table miss??  cur_ctrl = 2 due to 
				flowinit.apply();
			}
			
		}	

		if (state_meta.init == 1) {//original == 1  //why init == 1 ??
			if ( state_meta.cur_state == 0 && hdr.ipv4.protocol == 6) {//cur_state = 0  TCP=6
				transition_table.apply();
				predict.apply();
				ack_seq_predict.apply();
				pren.apply();

				//apply(calc_table);
				//apply(calc2);
				if (state_meta.temp == 1) {
					// apply(temp_write);
					temp_write.apply();
				}
				else {
					// apply(temp_read);
					temp_read.apply();
				}
				//apply(calc2_table);
			}

			// apply(fin);
			fin.apply();
			//if( state_meta.cur_state == 1 or state_meta.predict2 == 0) {
			if( state_meta.predict2 == 0 || state_meta.cur_state == 1) {
				syntable.apply();
				stateAction.apply();
			}
			//else {
			//    apply(drop_tbl);    
			//}
		}
    }
}


control MyEgress(inout headers hdr,
                  inout state_meta_t state_meta,
                  inout standard_metadata_t standard_metadata) {
						apply {}
				  }



control MyComputeChecksum(inout headers hdr, inout state_meta_t state_meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
	      hdr.ipv4.diffserv,
	    //   hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

// control egress {
//     ///apply(eg_time_info_table);
// }
