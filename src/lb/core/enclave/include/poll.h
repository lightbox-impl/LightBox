#ifndef POLL_H
#define POLL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include "etap_t.h"
void poll_read_pkt(uint8_t* pkt, int* pkt_size, timeval_t* ts,
		   etap_controller_t* etap);
void poll_write_pkt(const uint8_t* pkt, int pkt_size, timeval_t ts,
		    etap_controller_t* etap);
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* end of include guard: POLL_H */
