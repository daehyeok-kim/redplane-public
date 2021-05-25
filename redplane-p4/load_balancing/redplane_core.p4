#ifndef _REDPLANE_CORE_
#define _REDPLANE_CORE_

#include "headers.p4"
#include "types.p4"

control RedplaneIngress (
    inout ingress_headers_t hdr,
    inout ingress_metadata_t ig_md,
    in    ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    
    // Per-flow sequence number register initialized by 1
    // It's a switch local state so it does not need to be consistent with other switches.
    DirectRegister<bit<16>>() req_seqnum_reg;
    DirectRegisterAction<bit<16>, bit<16>> (req_seqnum_reg) get_seqnum_act = {
        void apply(inout bit<16> reg_val, out bit<16> seqnum) {
            seqnum = reg_val + 1;

            // reset the seqnum to 1 if it reaches MAX_SEQ_NUM
            if (reg_val == MAX_SEQ_NUM) {
                reg_val = 1;
            } 
            // otherwise, just increase it by 1.
            else {
                reg_val = reg_val + 1;
            }
        }
    };
    
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action req_renew_lease_write () {
        hdr.redplane_req.req_type = req_type_t.LEASE_RENEW_REQ;
        hdr.redplane_req.seq_num = get_seqnum_act.execute();
        hdr.redplane_ipv4.total_len = REDPLANE_REQ_IP_LEN + hdr.ipv4.total_len; // 20 (ip) + 8 (udp) + 22 (redplane req)
        hdr.redplane_udp.hdr_length = REDPLANE_REQ_UDP_LEN + hdr.ipv4.total_len; // 8 (udp) + 22 (redplane req)
        ig_md.is_renew_req = true;
    }
    action req_renew_lease_read () {
        hdr.redplane_req.req_type = req_type_t.LEASE_RENEW_REQ;
        hdr.redplane_req.seq_num = 0;
        hdr.redplane_ipv4.total_len = REDPLANE_REQ_IP_LEN + hdr.ipv4.total_len; // 20 (ip) + 8 (udp) + 22 (redplane req)
        hdr.redplane_udp.hdr_length = REDPLANE_REQ_UDP_LEN + hdr.ipv4.total_len; // 8 (udp) + 22 (redplane req)
        ig_md.is_renew_req = true;
    }

    // Lease data structure
    table req_renew_lease {
        key = {
            ig_md.flow_key.ip_addr : exact; 
            ig_md.flow_key.port : exact;
        }
        actions = {
           req_renew_lease_write;
        }
        registers = req_seqnum_reg;
    }
    
    action req_new_lease() {
        // Set req_type to LEASE_NEW_REQ;
        hdr.redplane_req.req_type = req_type_t.LEASE_NEW_REQ;
        // Assign a seq number
        hdr.redplane_req.seq_num = 0;
        hdr.redplane_ipv4.total_len = REDPLANE_REQ_IP_LEN + hdr.ipv4.total_len;
        hdr.redplane_udp.hdr_length = REDPLANE_REQ_UDP_LEN + hdr.ipv4.total_len;
    }

    // Add redplane req header and fill in switch and state store info based on the flow key
    action create_req_header_act (ipv4_addr_t switch_addr, ipv4_addr_t state_store_addr, bit<16> state_store_port, PortId_t state_store_egress_port) {
        hdr.redplane_req.setValid();
        hdr.redplane_ipv4.setValid();
        hdr.redplane_udp.setValid();

        hdr.redplane_ipv4.version = 4;
        hdr.redplane_ipv4.ihl = 5;
        hdr.redplane_ipv4.diffserv = 0;
        hdr.redplane_ipv4.identification = 1;
        hdr.redplane_ipv4.flags = 0;
        hdr.redplane_ipv4.ttl = 64;
        hdr.redplane_ipv4.protocol = IP_PROTOCOLS_UDP;

        hdr.redplane_ipv4.dst_addr = state_store_addr;
        hdr.redplane_udp.dst_port = state_store_port;
        hdr.bridged_md.store_egress_port = state_store_egress_port;
        ig_tm_md.ucast_egress_port = state_store_egress_port; // for LEASE_NEW_REQ
        
        // Add Switch addr and port 
        hdr.redplane_ipv4.src_addr = switch_addr;
        hdr.redplane_udp.src_port = SWITCH_UDP_PORT; 

         // COMPILER: Add a flow key to the header 
        hdr.redplane_req.flow_key.ip_addr = ig_md.flow_key.ip_addr;
        hdr.redplane_req.flow_key.port = ig_md.flow_key.port;
        
        ig_md.checksum_update_redplane_ipv4 = true;
    }

    table create_req_header {
        key = {
            ig_md.hashed_key : range;
        }
        actions = {
            create_req_header_act;
        }
    }
    
    // COMPILER: This should be generated by redplane compiler.
    Hash<bit<2>>(HashAlgorithm_t.CRC32) hash_crc32;
    action hash_flow_key() {
        ig_md.hashed_key = hash_crc32.get({
            ig_md.flow_key.ip_addr,
            ig_md.flow_key.port
        });
    }
    
    action send_to_CPU () {
        ig_tm_md.ucast_egress_port = CPU_PORT;
        hdr.cpu_ethernet.setValid();
        hdr.cpu_ethernet.dst_addr   = 0xFFFFFFFFFFFF;
        hdr.cpu_ethernet.src_addr   = (bit<48>)ig_md.new_lease_expire_time;
        hdr.cpu_ethernet.ether_type = ETHERTYPE_TO_CPU;
        hdr.bridged_md.setInvalid();
        ig_tm_md.bypass_egress = 1;
    }
    
    const bit<32> lease_register_table_size = 1 << 15; //65536
    Register<bit<32>, bit<32>>(lease_register_table_size, 0) lease_expire_time_reg;
    RegisterAction<bit<32>, bit<32>, bool>(lease_expire_time_reg) lease_expire_reg_update = {
        void apply(inout bit<32> reg_val) {
            reg_val = ig_md.new_lease_expire_time;
        }
    };
    RegisterAction<bit<32>, bit<32>, bool>(lease_expire_time_reg) lease_expire_reg_check = {
        void apply(inout bit<32> reg_val, out bool expired) {
            expired = false; 
            if (reg_val < ig_md.current_time) {
                expired = true; 
            }
        }
    };

    // if it is an ACK 
    action lease_expire_time_update (bit<32> reg_idx) {
        lease_expire_reg_update.execute(reg_idx);
    }

    // if it is not an ACK 
    action lease_expire_time_check (bit<32> reg_idx) {
        ig_md.lease_expired = lease_expire_reg_check.execute(reg_idx);
    }

    table lease_tbl {
        key = {
            ig_md.flow_key.ip_addr: exact;
            ig_md.flow_key.port: exact;
            hdr.redplane_ack.isValid() : exact;
        }
        actions = {
            lease_expire_time_update; 
            lease_expire_time_check;
        }
    }

    action generate_flow_key_ext () {
        ig_md.flow_key.ip_addr = hdr.ipv4.dst_addr;
        ig_md.flow_key.port = hdr.tcp.dst_port;
    }
    action generate_flow_key_int () {
        ig_md.flow_key.ip_addr = hdr.ipv4.src_addr;
        ig_md.flow_key.port = hdr.tcp.src_port;
    }
    
    table generate_flow_key {
        key = {
            ig_md.nat_meta.is_ext : exact;
        }
        actions = {
            generate_flow_key_ext;
            generate_flow_key_int;
            drop;
        }
        default_action = drop();     
        const entries = {
            (true) : generate_flow_key_ext();
            (false) : generate_flow_key_int();
        }
    }

    action validate_bridged_md () {
        hdr.bridged_md.setValid();
        hdr.bridged_md.pkt_type = PKT_TYPE_NORMAL;
        bit<48> tmp = ig_intr_md.ingress_mac_tstamp + LEASE_PERIOD; 
        ig_md.new_lease_expire_time = tmp[47:16];
        ig_md.current_time = ig_intr_md.ingress_mac_tstamp[47:16];
        hdr.bridged_md.is_write = 0;
    }

    action set_if_info(bool is_ext) {
        ig_md.nat_meta.is_ext = is_ext; // false: internal, true: external
    }

    table if_info {
        key = { 
            hdr.ipv4.src_addr : lpm;
        }
        actions = { 
            drop; 
            set_if_info; 
        }
        default_action = drop();     
    }

    apply {
        validate_bridged_md();
        if_info.apply();

        // Injected by the control plane after processing LEASE_NEW_ACK or LEASE_MIGRATE_ACK
        if (hdr.redplane_req.isValid() == true) {
            hdr.bridged_md.is_write = 1;
        }
        if (hdr.redplane_ack.isValid() == false && hdr.redplane_req.isValid() == false)
        {
            generate_flow_key.apply();
        }
        lease_tbl.apply();
        // Handle LEASE_NEW_ACK and LEASE_MIGRATE_ACK
        if (hdr.redplane_ack.isValid()) {
            if (hdr.redplane_ack.ack_type == ack_type_t.LEASE_NEW_ACK || 
            hdr.redplane_ack.ack_type == ack_type_t.LEASE_MIGRATE_ACK) {
                // Forward it to the CPU
                send_to_CPU();
            } 
            // Handle LEASE_RENEW_ACK
            else {
                ig_tm_md.bypass_egress = 0;
                // if LEASE_RENEW_ACK does not have an original payload, use the default egress port
                hdr.bridged_md.store_egress_port = DEFAULT_STORE_PORT;
                ig_tm_md.ucast_egress_port = DEFAULT_STORE_PORT;
            }
        } 
        // Handle regular packets
        else { 
            ig_tm_md.bypass_egress = 0;
            hash_flow_key(); // Hash the flow key
            create_req_header.apply(); // Find the state store's IP and UDP port and update the header fields
            if (ig_md.lease_expired == true) {
                req_new_lease();
            }
            else {
                if (hdr.bridged_md.is_write == 1)
                    req_renew_lease.apply();
                else
                    req_renew_lease_read();
            } 
        }
    }
}

control RedplaneEgress (
    inout egress_headers_t hdr,
    out egress_metadata_t eg_md,
    in    egress_intrinsic_metadata_t eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md
) {
    action egress_drop() {
        eg_dprsr_md.drop_ctl = eg_dprsr_md.drop_ctl | 0b001;
    }
    action mirror_drop() {
        eg_dprsr_md.drop_ctl = eg_dprsr_md.drop_ctl | 0b100;
    }

    action set_mirror (MirrorId_t mirror_session) {
        eg_md.egr_mir_ses = mirror_session; // set mirror session
        eg_md.pkt_type = PKT_TYPE_EGR_MIRROR;
        eg_dprsr_md.mirror_type = MIRROR_TYPE_E2E; // egress-to-egress mirroring
        eg_dprsr_md.drop_ctl = eg_dprsr_md.drop_ctl & 0b011; // make sure the mirrored packet won't be dropped.
    }

    table logging {
        key = { 
            // Egress port for the state store. This must be set in the ingress for regular packets 
            eg_md.bridged_md.store_egress_port: exact; 
            // Check whether this is a logged transaction or an original packet
            eg_md.is_logged_req: exact;
            eg_md.bridged_md.is_write : exact;
        } 
        actions = { 
            set_mirror; 
            egress_drop; 
        }
    }

    action update_tstamp()
    {
        eg_md.tstamp = eg_prsr_md.global_tstamp; // update the timestamp 
    }

    table check_req_timeout {
        key = {
            // 1 sec == 0x3b9aca00 (32bits)
            // 2.5 sec == 0x9502F900
            // timeout condition:
            // 1) diff_1 >= 0x3b9a or 
            // 2) diff_1 == 0x3b9a && diff_2 > ca00
            eg_md.time_diff_hi: range;  
            eg_md.time_diff_lo: range;
        }
        actions = {
            egress_drop; // if it has not been timed out, dropped the packet;
            update_tstamp; // Otherwise, update the timestamp and foward it to state store (retransmission)
        }
        const entries = {
            //(0x3b9a .. 0xfffe, 0x0000 .. 0xfffe): update_tstamp();
            //(0x3b9a .. 0x3b9b, 0xca00 .. 0xfffe): update_tstamp();
            (0x9502 .. 0xfffe, 0x0000 .. 0xfffe): update_tstamp();
            (0x9502 .. 0x9503, 0xF900 .. 0xfffe): update_tstamp();
        }
        default_action = egress_drop();
    }

    //hdr.redplane_ack.seq_num < eg_md.last_sent
    Register<bit<16>, bit<16>>(65536, 0) last_ack_register_reg;
    RegisterAction<bit<16>, bit<16>, bit<16>>(last_ack_register_reg) last_ack_reg_update_right = {
        void apply(inout bit<16> reg_val) {
            if (eg_md.last_sent < reg_val) // last_sent < last_acked // last_sent < seq_num
            { 
                if(reg_val < hdr.redplane_ack.seq_num) { //
                    reg_val = hdr.redplane_ack.seq_num;
                } 
            } 
        }
    };
    RegisterAction<bit<16>, bit<16>, bit<16>>(last_ack_register_reg) last_ack_reg_update_left = {
        void apply(inout bit<16> reg_val) {
            if (eg_md.last_sent > reg_val)
            { 
                if(reg_val < hdr.redplane_ack.seq_num) { // if not ack, 
                    reg_val = hdr.redplane_ack.seq_num;
                } 
            }
        }
    };
    RegisterAction<bit<16>, bit<16>, bit<16>>(last_ack_register_reg) last_ack_reg_update = {
        void apply(inout bit<16> reg_val) {
            reg_val = hdr.redplane_ack.seq_num;
        }
    };
    RegisterAction<bit<16>, bit<16>, bit<16>>(last_ack_register_reg) last_ack_reg_read = {
        void apply(inout bit<16> reg_val, out bit<16> val ) {
            val = reg_val;
        }
    };
    action set_last_acked (bit<16> reg_idx) {
        last_ack_reg_update.execute(reg_idx);
        egress_drop();
    }
    action set_last_acked_right (bit<16> reg_idx) {
        last_ack_reg_update_right.execute(reg_idx);
        egress_drop();
    }
    action set_last_acked_left (bit<16> reg_idx) {
        last_ack_reg_update_left.execute(reg_idx);
        egress_drop();
    }
    action check_last_acked (bit<16> reg_idx) {
        eg_md.bridged_md.store_egress_port = eg_intr_md.egress_port;
        eg_md.last_acked = last_ack_reg_read.execute(reg_idx);
    }
    table last_acked {
        key = {
            eg_md.flow_key.ip_addr: exact;
            eg_md.flow_key.port: exact;
            hdr.redplane_ack.isValid(): exact;
            eg_md.is_logged_req : exact;
            eg_md.seq_diff : range;
            eg_md.seq_same : range; 
        }
        actions = {
            set_last_acked; // If it is ACK, update the last_ack 
            set_last_acked_right; // If it is ACK, update the last_ack 
            set_last_acked_left; // If it is ACK, update the last_ack 
            check_last_acked;// If it is a req, check whether we should log it.
        }
    }
    
    Register<bit<16>, bit<16>>(65536, 0) last_sent_reg;
    RegisterAction<bit<16>, bit<16>, bit<16>>(last_sent_reg) last_sent_reg_update = {
        void apply(inout bit<16> reg_val) {
            if (eg_md.cur_seq_num == 1 || reg_val < eg_md.cur_seq_num) {
                reg_val = eg_md.cur_seq_num;
            }
        }
    };
    RegisterAction<bit<16>, bit<16>, bit<16>>(last_sent_reg) last_sent_reg_check = {
        void apply(inout bit<16> reg_val, out bit<16> last_sent) {
            last_sent = reg_val;
        }
    };
    // updated by non_logged_req (i.e., eg_md.is_logged req == true && hdr.redplane_ack.isValid() == False)
    action set_last_sent (bit<16> reg_idx) {
        last_sent_reg_update.execute(reg_idx);
    }

    // read by an renew ack (i.e., eg_md.is_logged_req == False && hdr.redplane_ack.isValid() == True)
    action check_last_sent (bit<16> reg_idx) {
        eg_md.last_sent = last_sent_reg_check.execute(reg_idx);
    }

    table last_sent {
        key = {
            eg_md.flow_key.ip_addr: exact;
            eg_md.flow_key.port: exact;
            hdr.redplane_ack.isValid(): exact;
            eg_md.is_logged_req : exact;
        }
        actions = {
            set_last_sent; // If it is REQ, update the last_sent
            check_last_sent; // If it is a ack, check the last sent.
        }
    }

    action acked() {
        eg_md.is_acked_req = true;
    }
    
    table check_acked {
        key = {
            eg_md.seq_diff : range;
            eg_md.seq_diff1 : range;
            eg_md.seq_diff2 : range;
            eg_md.last_acked: range;
            eg_md.is_logged_req : exact;
        }
        actions = {
            acked; // If it is a ack, check the last sent.
        }
        const entries = {
            (0x0 .. 0x1, 0x0 .. 0xfffe, 0x0 .. 0x0, 0x1 .. 0xfffe, true): acked(); // last_sent >= seq_num && last_acked <= last_sent && seq_num <= last_acked
            (0x1 .. 0xfffe, 0x0 .. 0x1, 0x0 .. 0x0, 0x1 .. 0xfffe, true): acked(); // last_sent < seq_num && last_acked >= last_sent && seq_num <= last_acked
        }
    }

    apply {
        last_sent.apply();
        eg_md.seq_diff = eg_md.last_sent |-| eg_md.cur_seq_num;
        eg_md.seq_same = eg_md.last_sent - eg_md.cur_seq_num;
        last_acked.apply();
        if (hdr.redplane_req.isValid() && hdr.redplane_req.req_type == req_type_t.LEASE_RENEW_REQ) {
            eg_md.seq_diff1 = eg_md.last_sent |-| eg_md.last_acked;
            eg_md.seq_diff2 = eg_md.cur_seq_num |-| eg_md.last_acked;
            if (hdr.redplane_req.seq_num != 0) {
                check_acked.apply();
            }
            // Regular packets and unacked req 
            if (eg_md.is_acked_req == false) { 
                if (eg_md.is_first_time == 0 || hdr.redplane_req.seq_num != 0) {
                    logging.apply(); // configure mirroring session for logging.
                }
                if (eg_md.is_logged_req == true && eg_md.is_first_time == 0) {
                    // check if the logged req is timed out
                    if (eg_prsr_md.global_tstamp[47:32] == eg_md.tstamp[47:32]) {
                        eg_md.time_diff_hi = eg_prsr_md.global_tstamp[31:16] - eg_md.tstamp[31:16];
                        eg_md.time_diff_lo = eg_prsr_md.global_tstamp[15:0] - eg_md.tstamp[15:0];
                        check_req_timeout.apply();
                    } else {
                        update_tstamp();
                    }
                    hdr.redplane_ipv4.total_len = REDPLANE_REQ_IP_LEN; // 20 (ip) + 8 (udp) + 22 (redplane req); 
                    hdr.redplane_udp.hdr_length = REDPLANE_REQ_UDP_LEN; // 8 (udp) + 22 (redplane req);
                } else {
                    eg_md.is_first_time = 0;
                    update_tstamp();
                    // For write req packet, we need to mirror it to the state store's egress
                    if (eg_md.bridged_md.is_write == 1 || eg_intr_md.egress_rid_first == 1) 
                    {
                        eg_md.is_first_time = 1;
                        egress_drop();
                    }
                    hdr.redplane_ipv4.total_len = REDPLANE_REQ_IP_LEN; // 20 (ip) + 8 (udp) + 22 (redplane req); 
                    hdr.redplane_udp.hdr_length = REDPLANE_REQ_UDP_LEN; // 8 (udp) + 22 (redplane req);
                }
            } 
            else {
                egress_drop(); // drop the req if it's been acked.
            }
        }
    }
}

#endif /* _REDPLANE_CORE_ */