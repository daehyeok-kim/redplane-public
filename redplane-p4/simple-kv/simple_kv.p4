/***********************************************************************
 * nat.p4:
 * NAT implementaton in P4 for TNA. 
 *
 * Author: Daehyeok Kim <daehyeok.kim@microsoft.com>
 **********************************************************************/

#ifndef _NAT_
#define _NAT_

#include "headers.p4"

/***************** M A T C H - A C T I O N  *********************/
control KV_Ingress(
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
    action kv_hit(bit<32> src_addr, bit<16> src_port) { 
        hdr.ipv4.src_addr= src_addr;
        hdr.tcp.src_port = src_port;
        
        ig_md.checksum_update_ipv4 = true;
        ig_md.checksum_update_tcp = true;
    }
    table handle_kv_query {
        key = { 
            hdr.ipv4.src_addr: exact;
            hdr.tcp.src_port: exact;
        }
        actions = {kv_hit; }
        //default_action = natTcp_learn();     
    }

    apply {
        //if(hdr.ipv4.isValid() && !ig_md.ipv4_checksum_err) {
        if(hdr.ipv4.isValid()) {
            handle_kv_query.apply();
        }
    }
}

#endif /* _NAT_ */