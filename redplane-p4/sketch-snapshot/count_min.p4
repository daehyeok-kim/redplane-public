/***********************************************************************
 * count_min.p4:
 * 64 x 3 count-min sketch implementaton in P4 for TNA.
 *
 * Author: Daehyeok Kim <daehyeok.kim@microsoft.com>
 **********************************************************************/

#ifndef _COUNT_MIN_
#define _COUNT_MIN_

#include "headers.p4"
#include "sketch.p4"

control CM_Ingress(
    /* User */
    inout ingress_headers_t                       hdr,
    inout ingress_metadata_t                      ig_md,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    Hash<bit<8>>(HashAlgorithm_t.CRC32) hash_crc32;
    action hash_flow_key1() {
        ig_md.sketch_key1 = hash_crc32.get({
            ig_md.flow_key.ip_addr,
            ig_md.flow_key.port
        });
    }
    Hash<bit<8>>(HashAlgorithm_t.CRC64) hash_crc64;
    action hash_flow_key2() {
        ig_md.sketch_key2 = hash_crc64.get({
            ig_md.flow_key.ip_addr,
            ig_md.flow_key.port
        });
    }
    Hash<bit<8>>(HashAlgorithm_t.CRC16) hash_crc16;
    action hash_flow_key3() {
        ig_md.sketch_key3 = hash_crc16.get({
            ig_md.flow_key.ip_addr,
            ig_md.flow_key.port
        });
    }

    /* Definition of sketches (64 x 3)*/
    Sketch() sketch1;
    Sketch() sketch2;
    Sketch() sketch3;

    //////////////////////////////////////////////////////////////////////////////
    apply {
        // is this a snapshot packet?
        if (hdr.pktgen_hdr.isValid() == true) {
            // yes, copy packet_id to sketch_keys
            ig_md.sketch_key1 = (bit<8>)(hdr.pktgen_hdr.packet_id);
            ig_md.sketch_key2 = (bit<8>)(hdr.pktgen_hdr.packet_id);
            ig_md.sketch_key3 = (bit<8>)(hdr.pktgen_hdr.packet_id);
            ig_md.update_val = 0;
        } else {
            // no, get sketch keys by hashing flow key
            hash_flow_key1();
            hash_flow_key2();
            hash_flow_key3();
            ig_md.update_val = 1;
        }
        sketch1.apply(hdr, ig_md.active_buffer1, ig_md.last_updated_buffer_for_index1, ig_md.sketch_key1, ig_md.update_val, hdr.redplane_req.values.sketch_1);
        sketch2.apply(hdr, ig_md.active_buffer2, ig_md.last_updated_buffer_for_index2, ig_md.sketch_key2, ig_md.update_val, hdr.redplane_req.values.sketch_2);
        sketch3.apply(hdr, ig_md.active_buffer3, ig_md.last_updated_buffer_for_index3, ig_md.sketch_key3, ig_md.update_val, hdr.redplane_req.values.sketch_3); 
    }
}

#endif /* _COUNT_MIN_ */