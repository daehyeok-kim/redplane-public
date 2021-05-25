#ifndef _LOAD_BALANCE_
#define _LOAD_BALANCE_

#include "headers.p4"

/***************** M A T C H - A C T I O N  *********************/
control Lb_Ingress(
    /* User */
    inout ingress_headers_t                       hdr,
    inout ingress_metadata_t                      ig_md,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }
    action lb_hit_int_to_ext(bit<32> front_addr) { 
        hdr.ipv4.src_addr = front_addr;
        ig_md.checksum_update_ipv4 = true;
        ig_md.checksum_update_tcp = true;
    }
    table lb_int_to_ext {
        key = { 
            hdr.ipv4.src_addr: exact; 
            hdr.ipv4.dst_addr: exact; 
            hdr.tcp.src_port: exact; 
            hdr.tcp.dst_port: exact;
        }
        actions = {drop; lb_hit_int_to_ext; }
        default_action = drop();     
    }

    action lb_hit_ext_to_int(bit<32> back_addr) {
        hdr.ipv4.dst_addr = back_addr;
        ig_md.checksum_update_ipv4 = true;
        ig_md.checksum_update_tcp = true;
    }
    table lb_ext_to_int {
	    key = { 
            hdr.ipv4.src_addr: exact; 
            hdr.ipv4.dst_addr: exact; 
            hdr.tcp.src_port: exact; 
            hdr.tcp.dst_port: exact;
        }
        actions = { drop; lb_hit_ext_to_int;  }
        default_action = drop();
    }
    
    apply {
        //if(hdr.ipv4.isValid() && !ig_md.ipv4_checksum_err) {
        if(hdr.ipv4.isValid()) {
            //if(if_info.apply().hit) 
            { // check whether the pkt comes from internal or external
                if(ig_md.nat_meta.is_ext == false){ // from internal
                    lb_int_to_ext.apply();
                } else { // from external 
                    lb_ext_to_int.apply(); 
                } 
            } 
        }
    }
}

#endif /* _LOAD_BALANCE_ */