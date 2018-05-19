#ifndef LWIDS_TYPE_H
#define LWIDS_TYPE_H

typedef struct
{
    // do PM times
    unsigned long pm_count;
    // pacp recv package count
    unsigned long recv_package;
    // recv size
    unsigned long package_total_size;
    unsigned long package_total_size_in_mb;
    // recv size
    unsigned long payload_total_size;
    unsigned long payload_total_size_in_mb;
    // recv size
    unsigned long pm_total_size;
    unsigned long pm_total_size_in_mb;
    // stream count
    unsigned long total_stream;
    // stream count
    unsigned long current_stream;

    // page size over 4K count
    unsigned long huge_package;
    unsigned long empty_package;
    unsigned long drop_package;
    unsigned long pm_segment_count_overflow;
    unsigned long pm_buffer_overflow;
    unsigned long pm_in_fin;
    unsigned long pm_time_out;
    unsigned long pm_ret_sum;
    unsigned long drop_by_port_filter;

    // non-tcp packet
    unsigned long non_tcp_pkt;

    //output value
    unsigned long time_gap;
    unsigned long package_time;
    unsigned long throuthput;

}exp_data_t;

typedef struct {
    int pattern_count;

    int round_size;
    int num_round;

    int is_caida;
}lwids_param_t;

#endif