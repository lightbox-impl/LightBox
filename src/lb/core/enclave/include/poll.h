#ifndef POLL_H
#define POLL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include "etap_t.h"

void poll_read_pkt(uint8_t* pkt, int* size, timeval_t* ts);
void poll_write_pkt(const uint8_t* pkt, int pkt_size, timeval_t ts);
int poll_driver_init();

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* end of include guard: POLL_H */
