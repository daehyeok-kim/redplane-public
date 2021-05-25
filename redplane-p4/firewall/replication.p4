#ifndef _Replication_
#define _Replication_

#include "headers.p4"
#include "types.p4"

control Replication (
    inout ingress_headers_t hdr,
    inout ingress_metadata_t ig_md,
    in    ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    
    // Instead of mirroring, let's use replication.
    action set_multicast (MulticastGroupId_t mcast_grp) {
        ig_tm_md.mcast_grp_a = mcast_grp;
        hdr.bridged_md.pkt_type = PKT_TYPE_NORMAL;
    }

    // We do this for (1) Read-only packet (2) ACK packets 
    table replication {
        key = {
            hdr.bridged_md.store_egress_port : exact; // egress port for state store
        }
        actions = {
            set_multicast;
        }
    }

    apply {
        replication.apply();
    }
}
#endif /* _Replication_ */