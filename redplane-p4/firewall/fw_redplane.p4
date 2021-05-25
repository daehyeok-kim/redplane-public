#include <core.p4>

#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "types.p4"
#include "headers.p4"
#include "parsers.p4"
#include "l3_routing.p4"
#include "replication.p4"
#include "redplane_core.p4"
#include "firewall.p4" //FW  P4 we want to make fault-tolerant

control Ingress(
    inout ingress_headers_t hdr,
    inout ingress_metadata_t ig_md,
    in    ingress_intrinsic_metadata_t ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    // COMPILER: This line should be added by Redplane compiler.
    RedplaneIngress() redplane_ig;
    Fw_Ingress() Fw_Ingress; // Instantiate the original application 
    L3Routing() L3_routing;
    Replication() replication;
    
    apply {
        //if (hdr.redplane_ack.isValid() == false && hdr.redplane_req.isValid() == false) {
        //if (hdr.redplane_req.isValid() == false) {
        //}
        //if (hdr.redplane_ack.isValid() == true && hdr.redplane_ack.ack_type == ack_type_t.LEASE_NEW_ACK) {
        //    hdr.tstamp.in_time = ig_intr_md.ingress_mac_tstamp;
        //}
        // COMPILER: This line should be added by Redplane compiler.
        redplane_ig.apply(hdr, ig_md, ig_intr_md, ig_dprsr_md, ig_tm_md);
        
        // COMPILER: This line should be added by Redplane compiler.
        // If the packet is an Redplane ACK from the state store, the app must not process it.
        if (ig_md.is_renew_req == true) { 
            // App's ingress logic.
            // hdr.tstamp.out_time = ig_intr_md.ingress_mac_tstamp;
            Fw_Ingress.apply(hdr, ig_md, ig_intr_md, ig_prsr_md, ig_dprsr_md, ig_tm_md);
        } 

        if ((ig_md.is_renew_req == true || (hdr.redplane_ack.isValid() == true && hdr.ipv4.isValid() == true)) && ig_tm_md.ucast_egress_port != CPU_PORT) {
            L3_routing.apply(hdr, ig_md, ig_intr_md, ig_dprsr_md, ig_tm_md);
        }
        
        if ((hdr.bridged_md.is_write == 0 && hdr.redplane_req.isValid() == true && hdr.redplane_req.req_type != req_type_t.LEASE_NEW_REQ) || // If it's a read renew request, 
        (hdr.redplane_ack.isValid() == true && hdr.redplane_ack.ack_type == ack_type_t.LEASE_RENEW_ACK && hdr.ipv4.isValid() == true)) // if it's an ack with a piggybacked original packet
        {
            //then replicate it!
            replication.apply(hdr, ig_md, ig_intr_md, ig_dprsr_md, ig_tm_md);
        }
    }
}

control Egress(
    inout egress_headers_t hdr,
    inout egress_metadata_t eg_md,
    in    egress_intrinsic_metadata_t eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    
    // COMPILER: This line should be added by Redplane compiler.
    RedplaneEgress() redplane_eg;

    action invalidate_redplane_hdr() {
        hdr.redplane_ipv4.setInvalid();
        hdr.redplane_udp.setInvalid();
        hdr.redplane_req.setInvalid();
        hdr.redplane_ack.setInvalid();
        hdr.redplane_values.setInvalid();
    }
    apply {
        // Redplane packet destined to the state store  OR Write packet is processed
        if (eg_intr_md.egress_rid_first == 1 // replicated packet (RENEW ACK or RENEW REQ) 
        || eg_md.bridged_md.is_write == 1 // RENEW REQ with  write
        || (hdr.redplane_ack.isValid() && hdr.ipv4.isValid() ==false)  // RENEW ACK without payload
        || eg_md.is_logged_req == true) 
        {
            if (hdr.redplane_req.req_type != req_type_t.LEASE_NEW_REQ) {
                redplane_eg.apply(hdr, eg_md, eg_intr_md, eg_prsr_md, eg_dprsr_md);
            }
        } else if (hdr.redplane_req.req_type != req_type_t.LEASE_NEW_REQ) {
            invalidate_redplane_hdr();
        }
    }
}

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
