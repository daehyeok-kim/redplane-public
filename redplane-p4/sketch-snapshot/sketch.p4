#ifndef _SKETCH_
#define _SKETCH_

#include "headers.p4"

struct pair {
    bit<32>     first;
    bit<32>     second;
} 

control Sketch (
    /* User */
    inout ingress_headers_t hdr,
    inout snapshot_meta_t   active_buffer_md,
    inout snapshot_meta_t   last_updated_buffer_for_index_md,
    in    bit<8>            sketch_key,
    in    bit<32>           update_val,
    out   bit<32>           result)
{
    /***************************** ACTIVE BUFFER *******************************/
    Register<snapshot_meta_t, bit<1>>(1, 0) active_buffer;
    RegisterAction<snapshot_meta_t, bit<1>, snapshot_meta_t>(active_buffer) swap_active_buffer = {
        void apply(inout snapshot_meta_t reg_val, out snapshot_meta_t new_val) {
            reg_val = ~reg_val;
            new_val = reg_val;
        }
    };
    RegisterAction<snapshot_meta_t, bit<1>, snapshot_meta_t>(active_buffer) get_active_buffer = {
        void apply(inout snapshot_meta_t reg_val, out snapshot_meta_t new_val) {
            new_val = reg_val;
        }
    };
    
    /**************************** LAST UPDATED BUFFER *************************/
    Register<snapshot_meta_t, bit<8>>(64, 0) last_updated_buffer;
    RegisterAction<snapshot_meta_t, bit<8>, snapshot_meta_t>(last_updated_buffer) update_last_updated_buffer = {
        void apply(inout snapshot_meta_t reg_val, out snapshot_meta_t cur_val) {
            cur_val = reg_val;
            reg_val = active_buffer_md;
        }
    };
    
    /******************************** CM SKETCH ************************************/
    Register<pair, bit<8>>(64) SKETCH;
    RegisterAction<pair, bit<8>, bit<32>>(SKETCH) copy_update_and_read_buffer_0 = {
        void apply(inout pair reg_val, out bit<32> cur_val) {
            reg_val.first = reg_val.second + update_val;
            cur_val = reg_val.first;
        }
    };
    RegisterAction<pair, bit<8>, bit<32>>(SKETCH) copy_update_and_read_buffer_1 = {
        void apply(inout pair reg_val, out bit<32> cur_val) {
            reg_val.second = reg_val.first + update_val;
            cur_val = reg_val.second;
        }
    };
    RegisterAction<pair, bit<8>, bit<32>>(SKETCH) update_and_read_buffer_0 = {
        void apply(inout pair reg_val, out bit<32> cur_val) {
            reg_val.first = reg_val.first + update_val;
            cur_val = reg_val.first;
        }
    };
    RegisterAction<pair, bit<8>, bit<32>>(SKETCH) update_and_read_buffer_1 = {
        void apply(inout pair reg_val, out bit<32> cur_val) {
            reg_val.second = reg_val.second + update_val;
            cur_val = reg_val.second;
        }
    };
    /************************Snapshot update_and/or_read logic***********************/
    action act_copy_update_and_read_buffer_0() {
        result = copy_update_and_read_buffer_0.execute(sketch_key);
    }

    action act_copy_update_and_read_buffer_1() {
        result = copy_update_and_read_buffer_1.execute(sketch_key);
    }

    action act_update_and_read_buffer_0() {
        result = update_and_read_buffer_0.execute(sketch_key);
    }

    action act_update_and_read_buffer_1() {
        result = update_and_read_buffer_1.execute(sketch_key);
    }
    
    table sketch_snapshot_tbl {
        key = {
            hdr.pktgen_hdr.isValid(): exact;
            active_buffer_md: exact;
            last_updated_buffer_for_index_md: exact; 
        }
        actions = {
            act_copy_update_and_read_buffer_0; 
            act_copy_update_and_read_buffer_1;
            act_update_and_read_buffer_0; 
            act_update_and_read_buffer_1; 
        }
        const entries = {
            (true, 0, 1): act_copy_update_and_read_buffer_0();
            (true, 1, 0): act_copy_update_and_read_buffer_1();
            (true, 0, 0): act_update_and_read_buffer_1();
            (true, 1, 1): act_update_and_read_buffer_0();
            (false, 0, 1): act_copy_update_and_read_buffer_0();
            (false, 1, 0): act_copy_update_and_read_buffer_1();
            (false, 0, 0): act_update_and_read_buffer_0();
            (false, 1, 1): act_update_and_read_buffer_1();
        }
    }

    apply {
        // is this the first packet of a snapshot read burst?
        if (hdr.pktgen_hdr.isValid() == true && hdr.pktgen_hdr.packet_id == 0) {
            // yes, so swap buffers
            active_buffer_md = swap_active_buffer.execute(0);
        } else {
            // no, so active buffer is unchanged
            active_buffer_md = get_active_buffer.execute(0);
        }
        last_updated_buffer_for_index_md = update_last_updated_buffer.execute(sketch_key);
        sketch_snapshot_tbl.apply();
    }
}

#endif /* _SKETCH_ */