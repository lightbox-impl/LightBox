#ifdef LOCKLESS
#ifndef CACHE_EFFICIENT
#include "rx_ring_opt.h"

extern timeval_t etap_clock;

int read_pkt(uint8_t* pkt, int* size, timeval_t* ts, rx_ring_data_t* data) {
	// busy waiting
	while (data->read == data->write)
		;

	memcpy(pkt, &data->in_rbuf[data->read].pkt,
	       data->in_rbuf[data->read].size);
	*size = data->in_rbuf[data->read].size;
	/* *ts = in_rbuf[read].ts; */
	memcpy(ts, &(data->in_rbuf[data->read].ts), sizeof(timeval_t));
	data->read = NEXT(data->read);
}

int write_pkt(const uint8_t* pkt, int pkt_size, timeval_t ts,
	      rx_ring_data_t* data) {
	// busy waiting
	while (NEXT(data->write) == data->read)
		;

	memcpy(&data->in_rbuf[data->write].pkt, pkt, pkt_size);
	data->in_rbuf[data->write].size = pkt_size;
	/* in_rbuf[write].ts = ts; */
	memcpy(&(data->in_rbuf[data->write].ts), &ts, sizeof(ts));

	/* etap_clock = ts; */
	memcpy(&etap_clock, &ts, sizeof(ts));

	data->write = NEXT(data->write);
}

int read_pkt_nonblock(uint8_t* pkt, int* size, timeval_t* ts, rx_ring_data_t* data) {
	// busy waiting
	if (data->read == data->write) return -1;

	memcpy(pkt, &data->in_rbuf[data->read].pkt,
	       data->in_rbuf[data->read].size);
	*size = data->in_rbuf[data->read].size;
	/* *ts = in_rbuf[read].ts; */
	memcpy(ts, &(data->in_rbuf[data->read].ts), sizeof(timeval_t));
	data->read = NEXT(data->read);
}

int write_pkt_nonblock(const uint8_t* pkt, int pkt_size, timeval_t ts,
	      rx_ring_data_t* data) {
	// busy waiting
	if (NEXT(data->write) == data->read)
		return -1;

	memcpy(&data->in_rbuf[data->write].pkt, pkt, pkt_size);
	data->in_rbuf[data->write].size = pkt_size;
	/* in_rbuf[write].ts = ts; */
	memcpy(&(data->in_rbuf[data->write].ts), &ts, sizeof(ts));

	/* etap_clock = ts; */
	memcpy(&etap_clock, &ts, sizeof(ts));

	data->write = NEXT(data->write);
}

#endif
#endif
