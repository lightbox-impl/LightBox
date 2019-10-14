#include "poll.h"

extern etap_controller_t* etap_controller_instance;

void poll_read_pkt(uint8_t* pkt, int* size, timeval_t* ts) {
	etap_controller_instance->rx_ring_instance->read_pkt(
	    pkt, size, ts, etap_controller_instance->rx_ring_instance->rData);
}

void poll_write_pkt(const uint8_t* pkt, int pkt_size,
					timeval_t ts) {
	etap_controller_instance->tx_ring_instance->write_pkt(
	    pkt, pkt_size, ts,
	    etap_controller_instance->tx_ring_instance->rData);
}


/* 
 * To be called within etap_controller_instance init function call
 */ 
int poll_driver_init() {
	poll_driver_t* pd = (poll_driver_t*)malloc(sizeof(poll_driver_t));
	pd->read_pkt = poll_read_pkt;
	pd->write_pkt = poll_write_pkt;
	if (etap_controller_instance == NULL) return -1;
	etap_controller_instance->pd = pd;
	return 0;
}
