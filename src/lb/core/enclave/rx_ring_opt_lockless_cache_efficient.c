#ifdef LOCKLESS
#ifdef CACHE_EFFICIENT

#include "rx_ring_opt.h"

extern timeval_t etap_clock;

int read_pkt(uint8_t* pkt, int* size, timeval_t* ts,
				      rx_ring_data_t* data) {
	if (data->nextRead == data->localWrite) {
		while (data->nextRead == data->write)
			;
		data->localWrite = data->write;
	}
	memcpy(pkt, data->in_rbuf[data->nextRead].pkt,
	       data->in_rbuf[data->nextRead].size);
	*size = data->in_rbuf[data->nextRead].size;
	memcpy(ts, &data->in_rbuf[data->nextRead].ts, sizeof(timeval_t));
	/* *ts = in_rbuf[nextRead].ts; */

	data->nextRead = NEXT(data->nextRead);
	++(data->rBatch);
	if (data->rBatch > data->batchSize) {
		data->read = data->nextRead;
		data->rBatch = 0;
	}
}

int write_pkt(const uint8_t* pkt, int pkt_size,
				       timeval_t ts, rx_ring_data_t* data) {
	int afterNextWrite = NEXT(data->nextWrite);
	if (afterNextWrite == data->localRead) {
		while (afterNextWrite == data->read) {
			;
		}
		data->localRead = data->read;
	}

	memcpy(data->in_rbuf[data->nextWrite].pkt, pkt, pkt_size);
	data->in_rbuf[data->nextWrite].size = pkt_size;
	/* in_rbuf[nextWrite].ts = ts; */
	memcpy(&data->in_rbuf[data->nextWrite], &ts, sizeof(timeval_t));

	/* etap_clock = ts; */
	memcpy(&etap_clock, &ts, sizeof(ts));

	/* trace_clock.tv_sec = ts; // second only */
	// memcpy(&trace_clock, &ts, sizeof(ts));

	data->nextWrite = afterNextWrite;
	(data->wBatch)++;
	if (data->wBatch >= data->batchSize) {
		data->write = data->nextWrite;
		data->wBatch = 0;
	}
}

int read_pkt_nonblock(uint8_t* pkt, int* size,
					       timeval_t* ts,
					       rx_ring_data_t* data) {
	if (data->nextRead == data->localWrite) {
		if (data->nextRead == data->write) return -1;
		data->localWrite = data->write;
	}
	memcpy(pkt, data->in_rbuf[data->nextRead].pkt,
	       data->in_rbuf[data->nextRead].size);
	*size = data->in_rbuf[data->nextRead].size;
	memcpy(ts, &data->in_rbuf[data->nextRead].ts, sizeof(timeval_t));
	/* *ts = in_rbuf[nextRead].ts; */

	data->nextRead = NEXT(data->nextRead);
	++(data->rBatch);
	if (data->rBatch > data->batchSize) {
		data->read = data->nextRead;
		data->rBatch = 0;
	}
	return 0;
}

int write_pkt_nonblock(const uint8_t* pkt,
						int pkt_size, timeval_t ts,
						rx_ring_data_t* data) {
	int afterNextWrite = NEXT(data->nextWrite);
	if (afterNextWrite == data->localRead) {
		if (afterNextWrite == data->read) {
			return -1;
		}
		data->localRead = data->read;
	}

	memcpy(data->in_rbuf[data->nextWrite].pkt, pkt, pkt_size);
	data->in_rbuf[data->nextWrite].size = pkt_size;
	/* in_rbuf[nextWrite].ts = ts; */
	memcpy(&data->in_rbuf[data->nextWrite], &ts, sizeof(timeval_t));

	/* time_now = ts; */
	memcpy(&etap_clock, &ts, sizeof(ts));

	/* trace_clock.tv_sec = ts; // second only */
	/* memcpy(&trace_clock, &ts, sizeof(ts)); */

	data->nextWrite = afterNextWrite;
	(data->wBatch)++;
	if (data->wBatch >= data->batchSize) {
		data->write = data->nextWrite;
		data->wBatch = 0;
	}
	return 0;
}

#endif
#endif
