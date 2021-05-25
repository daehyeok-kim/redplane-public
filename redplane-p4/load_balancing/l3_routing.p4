#ifndef _L3_ROUTING_
#define _L3_ROUTING_

#include "headers.p4"
#include "types.p4"

control L3Routing (
    inout ingress_headers_t hdr,
    inout ingress_metadata_t ig_md,
    in    ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    
    action set_nhop(bit<9> port){
        ig_tm_md.ucast_egress_port = port;
    }
    
    table ipv4_lpm {
        key = {hdr.ipv4.dst_addr : lpm;}  
        actions = { set_nhop; }
    }

    apply {
        ipv4_lpm.apply();
    }
}
#endif /* _L3_ROUTING_ */