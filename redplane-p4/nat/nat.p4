#ifndef _NAT_
#define _NAT_

#include "headers.p4"

/***************** M A T C H - A C T I O N  *********************/
control Nat_Ingress(
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
    /***************************** NAT control *****************************************/
    action nat_hit_int_to_ext(bit<32> src_addr, bit<16> src_port) { 
        hdr.ipv4.src_addr= src_addr;
        hdr.tcp.src_port = src_port;
        
        /******************* For RTT measurement **************/
        //hdr.ipv4.dst_addr= src_addr;
        //hdr.tcp.dst_port = src_port;
        /////////////////////////////////////////////////////////

        ig_md.checksum_update_ipv4 = true;
        ig_md.checksum_update_tcp = true;
    }
    table nat_int_to_ext {
        key = { 
            hdr.ipv4.src_addr: exact;
            hdr.tcp.src_port: exact;
        }
        actions = {nat_hit_int_to_ext; }
        //default_action = natTcp_learn();     
    }

    action nat_hit_ext_to_int(bit<32> dst_addr, bit<16> dst_port) {
        hdr.ipv4.dst_addr = dst_addr;
        hdr.tcp.dst_port = dst_port; 
        
        ig_md.checksum_update_ipv4 = true;
        ig_md.checksum_update_tcp = true;
    }
    table nat_ext_to_int {
	    key = { 
            hdr.ipv4.dst_addr: exact; 
            hdr.tcp.dst_port: exact;
        }
        actions = { drop; nat_hit_ext_to_int;  }
        default_action = drop();
    }
    
    apply {
        if(hdr.ipv4.isValid()) 
        { // check whether the pkt comes from internal or external
            if(ig_md.nat_meta.is_ext == false){ // from internal
                nat_int_to_ext.apply();
            } else { // from external 
                nat_ext_to_int.apply(); 
            } 
        } 
    }
}

#endif /* _NAT_ */