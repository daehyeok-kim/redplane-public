#ifndef _PARSERS_
#define _PARSERS_

parser IngressParser(packet_in pkt,
    out ingress_headers_t hdr,
    out ingress_metadata_t ig_md,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    Checksum() ipv4_checksum;
    Checksum() tcp_checksum;
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    state meta_init {
        //Initialize ingress metadata
        ig_md.checksum_update_redplane_ipv4 = false;
        ig_md.ipv4_checksum_err = false;
        ig_md.is_renew_req = false;
        ig_md.lease_expired = true;
        ethernet_h tmp_eth_hdr = pkt.lookahead<tmp_eth_hdr_t>();

        transition select(tmp_eth_hdr.ether_type) {
            ETHERTYPE_IPV4: parse_ethernet;
            default: parse_pktgen;
        } 
    }

    state parse_pktgen {
        pkt.extract(hdr.pktgen_hdr);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract (hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        ipv4_h tmp_ipv4 = pkt.lookahead<ipv4_h>();
        transition select(tmp_ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_regular_ipv4;
            IP_PROTOCOLS_UDP: parse_regular_or_redplane_ipv4;
            default: reject;
        }
    }

    state parse_regular_or_redplane_ipv4 {
        transition select(pkt.lookahead<bit<192>>()[15:0]) {
            SWITCH_UDP_PORT: parse_redplane_ipv4_udp_ack;
            STORE_UDP_PORT &&& 0xffc0 : parse_redplane_ipv4_udp_req; // 8000-8063
            default: parse_regular_ipv4; 
        }
    }

    state parse_redplane_ipv4_udp_ack {
        pkt.extract (hdr.redplane_ipv4);
        pkt.extract (hdr.redplane_udp);
        pkt.extract (hdr.redplane_ack);
        
        ig_md.flow_key.ip_addr = hdr.redplane_ack.flow_key.ip_addr;
        ig_md.flow_key.port = hdr.redplane_ack.flow_key.port;
        
        transition select (hdr.redplane_ack.ack_type, hdr.redplane_ipv4.total_len){
            (ack_type_t.LEASE_NEW_ACK, _)  : parse_regular_ipv4;
            (ack_type_t.LEASE_MIGRATE_ACK, _) : parse_lease_migrate_ack; 
            (ack_type_t.LEASE_RENEW_ACK, REDPLANE_ACK_IP_LEN) : accept; // no trailer (i.e., original payload) 
            (ack_type_t.LEASE_RENEW_ACK, _) : parse_regular_ipv4;
            default: reject; // reject all other invalid ack packets.
        }
    }

    state parse_lease_migrate_ack {
        pkt.extract(hdr.redplane_values);
        transition parse_regular_ipv4;
    }
    
    state parse_redplane_ipv4_udp_req {
        pkt.extract (hdr.redplane_ipv4);
        pkt.extract (hdr.redplane_udp);
        pkt.extract (hdr.redplane_req);
        
        ig_md.flow_key.ip_addr = hdr.redplane_req.flow_key.ip_addr;
        ig_md.flow_key.port = hdr.redplane_req.flow_key.port;
        
        transition parse_regular_ipv4;
    }
    
    state parse_regular_ipv4 {
        pkt.extract (hdr.ipv4);
        ipv4_checksum.add(hdr.ipv4);
        ig_md.ipv4_checksum_err = ipv4_checksum.verify();
        
        tcp_checksum.subtract({hdr.ipv4.src_addr});
        tcp_checksum.subtract({hdr.ipv4.dst_addr});
        
        transition select (hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            IP_PROTOCOLS_UDP: parse_udp;
            default: reject;
        }
    }
    
    state parse_tcp {
        pkt.extract(hdr.tcp);
        // The tcp checksum cannot be verified, since we cannot compute
        // the payload's checksum.
        tcp_checksum.subtract({hdr.tcp.checksum});
        tcp_checksum.subtract({hdr.tcp.src_port});
        tcp_checksum.subtract({hdr.tcp.dst_port});
        ig_md.checksum_tcp_tmp = tcp_checksum.get();

        transition accept;
    }

    state parse_tstamp {
        pkt.extract(hdr.tstamp);
        transition accept;
    }
    
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

control IngressDeparser(packet_out pkt,
    inout ingress_headers_t hdr,
    in    ingress_metadata_t ig_md,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    Checksum() ipv4_checksum;
    Checksum() tcp_checksum;
    Checksum() redplane_ipv4_checksum;
    Mirror() mirror;

    apply {
        if (ig_md.checksum_update_redplane_ipv4) {
            hdr.redplane_ipv4.hdr_checksum = redplane_ipv4_checksum.update({
                hdr.redplane_ipv4.version,
                hdr.redplane_ipv4.ihl,
                hdr.redplane_ipv4.diffserv,
                hdr.redplane_ipv4.total_len,
                hdr.redplane_ipv4.identification,
                hdr.redplane_ipv4.flags,
                hdr.redplane_ipv4.frag_offset,
                hdr.redplane_ipv4.ttl,
                hdr.redplane_ipv4.protocol,
                hdr.redplane_ipv4.src_addr,
                hdr.redplane_ipv4.dst_addr
            });
        }
        
        if (ig_md.checksum_update_ipv4) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }

        if (ig_md.checksum_update_tcp) {
            hdr.tcp.checksum = tcp_checksum.update({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                ig_md.checksum_tcp_tmp
            });
        }

        pkt.emit(hdr);
    }
}

parser EgressParser(packet_in pkt,
    out egress_headers_t hdr,
    out egress_metadata_t eg_md,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        transition parse_metadata;
    }

    state parse_metadata {
        eg_md.is_logged_req = false;
        eg_md.is_acked_req = false;
        eg_md.is_first_time = 0;
        eg_md.tstamp = 0;

        egr_mirror_h mirror_md = pkt.lookahead<egr_mirror_h>();
        transition select(mirror_md.pkt_type) {
            PKT_TYPE_EGR_MIRROR : parse_egr_mirror_md; // cloned from egress
            PKT_TYPE_NORMAL : parse_bridged_md; // from the ingress
            default : accept;
        }
    }
    
    state parse_egr_mirror_md {
        egr_mirror_h mirror_md;
        pkt.extract(mirror_md);
        eg_md.is_logged_req = true;
        eg_md.tstamp = mirror_md.tstamp; // store the logged timestamp
        eg_md.is_first_time = mirror_md.is_first_time; 
        transition parse_ethernet;
    }

    state parse_bridged_md {
        pkt.extract(eg_md.bridged_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract (hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        ipv4_h tmp_ipv4 = pkt.lookahead<ipv4_h>();
        transition select(tmp_ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_regular_ipv4;
            IP_PROTOCOLS_UDP: parse_regular_or_redplane_ipv4;
            default: reject;
        }
    }

    state parse_regular_or_redplane_ipv4 {
        transition select(pkt.lookahead<bit<192>>()[15:0]) {
            SWITCH_UDP_PORT: parse_redplane_ipv4_udp_ack;
            STORE_UDP_PORT &&& 0xffc0 : parse_redplane_ipv4_udp_req; // 8000-8063
            default: parse_regular_ipv4; 
        }
    }

    state parse_redplane_ipv4_udp_ack {
        pkt.extract (hdr.redplane_ipv4);
        pkt.extract (hdr.redplane_udp);
        pkt.extract (hdr.redplane_ack);
        
        eg_md.flow_key.ip_addr = hdr.redplane_ack.flow_key.ip_addr;
        eg_md.flow_key.port = hdr.redplane_ack.flow_key.port;
        eg_md.cur_seq_num = hdr.redplane_ack.seq_num;
        transition select (hdr.redplane_ack.ack_type, hdr.redplane_ipv4.total_len){
            (ack_type_t.LEASE_NEW_ACK, _)  : parse_regular_ipv4;
            (ack_type_t.LEASE_MIGRATE_ACK, _) : parse_lease_migrate_ack; 
            (ack_type_t.LEASE_RENEW_ACK, REDPLANE_ACK_IP_LEN) : accept; // no trailer (i.e., original payload) 
            (ack_type_t.LEASE_RENEW_ACK, _) : parse_regular_ipv4;
            default: reject; // reject all other invalid ack packets.
        }
    }

    state parse_lease_migrate_ack {
        pkt.extract(hdr.redplane_values);
        transition parse_regular_ipv4;
    }
    
    state parse_redplane_ipv4_udp_req {
        pkt.extract (hdr.redplane_ipv4);
        pkt.extract (hdr.redplane_udp);
        pkt.extract (hdr.redplane_req);
        
        eg_md.flow_key.ip_addr = hdr.redplane_req.flow_key.ip_addr;
        eg_md.flow_key.port = hdr.redplane_req.flow_key.port;
        eg_md.cur_seq_num = hdr.redplane_req.seq_num;
        
        transition parse_regular_ipv4;
    }

    state parse_regular_ipv4 {
        pkt.extract (hdr.ipv4);
        transition accept;
    }
}

control EgressDeparser(packet_out pkt,
    inout egress_headers_t hdr,
    in    egress_metadata_t eg_md,
    in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
 {
    Mirror() mirror;
    Checksum() redplane_ipv4_checksum;
    apply {
        hdr.redplane_ipv4.hdr_checksum = redplane_ipv4_checksum.update({
            hdr.redplane_ipv4.version,
            hdr.redplane_ipv4.ihl,
            hdr.redplane_ipv4.diffserv,
            hdr.redplane_ipv4.total_len,
            hdr.redplane_ipv4.identification,
            hdr.redplane_ipv4.flags,
            hdr.redplane_ipv4.frag_offset,
            hdr.redplane_ipv4.ttl,
            hdr.redplane_ipv4.protocol,
            hdr.redplane_ipv4.src_addr,
            hdr.redplane_ipv4.dst_addr
        });
 
        if (eg_dprsr_md.mirror_type == MIRROR_TYPE_E2E) { 
            mirror.emit<egr_mirror_h>(eg_md.egr_mir_ses, {eg_md.pkt_type, eg_md.tstamp, 0, eg_md.is_first_time});
        }
        
        pkt.emit(hdr);
        
    }
}

#endif /* _PARSERS_ */