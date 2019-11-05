#include "etap_t.h"

int read_pkt(uint8_t* pkt, int* size, timeval_t* ts, rx_ring_data_t* data);

int write_pkt(const uint8_t* pkt, int pkt_size, timeval_t ts,
	      rx_ring_data_t* data);

int read_pkt_nonblock(uint8_t* pkt, int* size, timeval_t* ts, rx_ring_data_t* data);

int write_pkt_nonblock(const uint8_t* pkt, int pkt_size, timeval_t ts,
		   rx_ring_data_t* data);
