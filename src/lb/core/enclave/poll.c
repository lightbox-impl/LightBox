#include "poll.h"

extern etap_controller_t* etap_controller_instance;


void poll_read_pkt(uint8_t* pkt, int* pkt_size, timeval_t* ts,etap_controller_t* etap ) {
	rx_ring_t* rx = etap->rx_ring_instance;
	rx->read_pkt(pkt, pkt_size, ts, rx->rData);
}


void poll_write_pkt(const uint8_t* pkt, int pkt_size,
					timeval_t ts, etap_controller_t* etap) {
	rx_ring_t* tx = etap->tx_ring_instance;
	tx->write_pkt(pkt, pkt_size, ts, tx->rData);
}


/* 
 * To be called within etap_controller_instance init function call
 */ 
poll_driver_t* poll_driver_init() {
	poll_driver_t* pd = (poll_driver_t*)malloc(sizeof(poll_driver_t));
	pd->read_pkt = poll_read_pkt;
	pd->write_pkt = poll_write_pkt;
	pd->etap = etap_controller_init(0, 0);
	etap_controller_instance = pd->etap;
	return pd;
}

