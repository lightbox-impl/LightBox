#include "etap_t.h"

int read_pkt_lockless_cache_efficient(uint8_t* pkt, int* size, timeval_t* ts,
				       rx_ring_data_t* data);

int write_pkt_lockless_cache_efficient(const uint8_t* pkt, int pkt_size,
					timeval_t ts, rx_ring_data_t* data);

int read_pkt_lockless_cache_efficient_nonblock(uint8_t* pkt, int* size, timeval_t* ts,
				       rx_ring_data_t* data);

int write_pkt_lockless_cache_efficient_nonblock(const uint8_t* pkt, int pkt_size,
					timeval_t ts, rx_ring_data_t* data);

int read_pkt_lockless(uint8_t* pkt, int* size, timeval_t* ts,
		       rx_ring_data_t* data);

int write_pkt_lockless(const uint8_t* pkt, int pkt_size, timeval_t ts,
			rx_ring_data_t* data);

int read_pkt_lock(uint8_t* pkt, int* size, timeval_t* ts,
		   rx_ring_data_t* data);

int write_pkt_lock(const uint8_t* pkt, int pkt_size, timeval_t ts,
		    rx_ring_data_t* data);

// double ecall_etap_start_caida(rx_ring_t* handle, int lbn_record_size,
				  // int lbn_record_per_batch);

// double ecall_etap_start_live(rx_ring_t* handle, int lbn_record_size,
				 // int lbn_record_per_batch);

// double ecall_etap_start_micro(rx_ring_t* handle, int lbn_record_size,
				  // int lbn_record_per_batch);
