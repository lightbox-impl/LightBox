#ifndef LB_NET_T_H
#define LB_NET_T_H

#include "../../lb_networking/libpcap/trusted/pcap.h"
#include <stdint.h>
#include <time.h>

typedef struct timeval timeval_t;

void read_pkt(uint8_t* pkt, int* size, timeval_t* ts);

void write_pkt(const uint8_t* pkt, int size, timeval_t ts);

void get_clock(timeval_t* ts);

void etap_set_flow(int crt_flow);

#endif
