#ifndef LB_NET_T_H
#define LB_NET_T_H

#include <stdint.h>
#include <time.h>

void read_pkt(uint8_t *pkt, int *size, time_t *ts);

void write_pkt(const uint8_t *pkt, int size, time_t ts);

#endif
