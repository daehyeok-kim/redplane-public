#ifndef _FIREWALL_
#define _FIREWALL_

#include "headers.p4"

/***************** M A T C H - A C T I O N  *********************/
control Fw_Ingress(
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

    table fw_ext_to_int {
	    key = { 
            hdr.ipv4.dst_addr: exact; 
            hdr.tcp.dst_port: exact;
        }
        actions = { drop; NoAction;  }
        default_action = drop();
    }
    
    apply {
        if(hdr.ipv4.isValid()) {
            if(ig_md.nat_meta.is_ext == true){ // from internal
                fw_ext_to_int.apply(); 
            } 
        }
    }
}

#endif /* _FIREWALL_ */