#include "poll.h"

extern etap_controller_t* etap_controller_instance;

/* void poll_read_pkt(uint8_t* pkt, int* pkt_size, timeval_t* ts) { */
    /* rx_ring_t* rx = rx_ring_instance; */
    /* read_pkt(pkt, pkt_size, ts); */
/* } */

/* void poll_write_pkt(const uint8_t* pkt, int pkt_size, timeval_t ts) { */
    /* rx_ring_t* tx = etap->tx_ring_instance; */
    /* write_pkt(pkt, pkt_size, ts); */
/* } */

/*
 * To be called within etap_controller_instance init function call
 */
poll_driver_t* poll_driver_init(int mode) {
    poll_driver_t* pd = (poll_driver_t*)malloc(sizeof(poll_driver_t));
	if (mode == 0) {
		pd->read_pkt = read_pkt;
		pd->write_pkt = write_pkt_tx;
	} else {
		pd->read_pkt = read_pkt_nonblock;
		pd->write_pkt = write_pkt_nonblock_tx;
	}
    /* pd->read_pkt = read_pkt; */
    /* pd->write_pkt = write_pkt; */
    /* pd->etap = etap_controller_init(mode, 0); */
    /* etap_controller_instance = pd->etap; */
    return pd;
}

