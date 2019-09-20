#include "rx_ring_opt.h"

extern timeval_t time_now;
extern timeval_t trace_clock;

void read_pkt_lockless_cache_efficient(uint8_t* pkt, int* size, timeval_t* ts,
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

	// eprintf("reader: read %d write %d size %d!\n", read, write, *size);
}

void write_pkt_lockless_cache_efficient(const uint8_t* pkt, int pkt_size,
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

	/* time_now = ts; */
	memcpy(&time_now, &ts, sizeof(ts));

	/* trace_clock.tv_sec = ts; // second only */
	memcpy(&trace_clock, &ts, sizeof(ts));

	data->nextWrite = afterNextWrite;
	(data->wBatch)++;
	if (data->wBatch >= data->batchSize) {
		data->write = data->nextWrite;
		data->wBatch = 0;
	}
}

void read_pkt_lockless(uint8_t* pkt, int* size, timeval_t* ts,
		       rx_ring_data_t* data) {
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

void write_pkt_lockless(const uint8_t* pkt, int pkt_size, timeval_t ts,
			rx_ring_data_t* data) {
	// busy waiting
	while (NEXT(data->write) == data->read)
		;

	memcpy(&data->in_rbuf[data->write].pkt, pkt, pkt_size);
	data->in_rbuf[data->write].size = pkt_size;
	/* in_rbuf[write].ts = ts; */
	memcpy(&(data->in_rbuf[data->write].ts), &ts, sizeof(ts));

	/* time_now = ts; */
	memcpy(&time_now, &ts, sizeof(ts));

	data->write = NEXT(data->write);
}
sgx_thread_mutex_t rbuf_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_cond_t empty_cond = SGX_THREAD_COND_INITIALIZER;
sgx_thread_cond_t full_cond = SGX_THREAD_COND_INITIALIZER;
void read_pkt_lock(uint8_t* pkt, int* size, timeval_t* ts,
		   rx_ring_data_t* data) {
#ifdef NON_SWITCHING
	while (sgx_thread_mutex_trylock(&rbuf_mutex) != 0)
		;
#else
	sgx_thread_mutex_lock(&rbuf_mutex);
#endif

	// wait on empty
	if (data->read == data->write)
		sgx_thread_cond_wait(&empty_cond, &rbuf_mutex);

	memcpy(pkt, data->in_rbuf[data->read].pkt,
	       data->in_rbuf[data->read].size);
	*size = data->in_rbuf[data->read].size;
	/* *ts = in_rbuf[read].ts; */
	memcpy(ts, &(data->in_rbuf[data->read].ts), sizeof(timeval_t));
	data->read = NEXT(data->read);

	sgx_thread_cond_signal(&full_cond);

	sgx_thread_mutex_unlock(&rbuf_mutex);
}

void write_pkt_lock(const uint8_t* pkt, int pkt_size, timeval_t ts,
		    rx_ring_data_t* data) {
#ifdef NON_SWITCHING
	while (sgx_thread_mutex_trylock(&rbuf_mutex) != 0)
		;
#else
	sgx_thread_mutex_lock(&rbuf_mutex);
#endif

	// wait on full
	if (NEXT(data->write) == data->read)
		sgx_thread_cond_wait(&full_cond, &rbuf_mutex);

	memcpy(data->in_rbuf[data->write].pkt, pkt, pkt_size);
	data->in_rbuf[data->write].size = pkt_size;
	/* in_rbuf[write].ts = ts; */
	memcpy(&(data->in_rbuf[data->write].ts), &ts, sizeof(timeval_t));
	data->write = NEXT(data->write);

	sgx_thread_cond_signal(&empty_cond);

	sgx_thread_mutex_unlock(&rbuf_mutex);
}


