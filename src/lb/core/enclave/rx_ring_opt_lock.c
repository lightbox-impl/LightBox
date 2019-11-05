#ifndef LOCKLESS
#include "rx_ring_opt.h"

extern timeval_t etap_clock;

sgx_thread_mutex_t rbuf_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_cond_t empty_cond = SGX_THREAD_COND_INITIALIZER;
sgx_thread_cond_t full_cond = SGX_THREAD_COND_INITIALIZER;
int read_pkt(uint8_t* pkt, int* size, timeval_t* ts,
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

int write_pkt(const uint8_t* pkt, int pkt_size, timeval_t ts,
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
int read_pkt_nonblock(uint8_t* pkt, int* size, timeval_t* ts,
		  rx_ring_data_t* data) {
#ifdef NON_SWITCHING
	while (sgx_thread_mutex_trylock(&rbuf_mutex) != 0)
		;
#else
	sgx_thread_mutex_lock(&rbuf_mutex);
#endif

	// wait on empty
	if (data->read == data->write)
			return -1;
		/* sgx_thread_cond_wait(&empty_cond, &rbuf_mutex); */

	memcpy(pkt, data->in_rbuf[data->read].pkt,
	       data->in_rbuf[data->read].size);
	*size = data->in_rbuf[data->read].size;
	/* *ts = in_rbuf[read].ts; */
	memcpy(ts, &(data->in_rbuf[data->read].ts), sizeof(timeval_t));
	data->read = NEXT(data->read);

	sgx_thread_cond_signal(&full_cond);

	sgx_thread_mutex_unlock(&rbuf_mutex);
}

int write_pkt_nonblock(const uint8_t* pkt, int pkt_size, timeval_t ts,
		   rx_ring_data_t* data) {
#ifdef NON_SWITCHING
	while (sgx_thread_mutex_trylock(&rbuf_mutex) != 0)
		;
#else
	sgx_thread_mutex_lock(&rbuf_mutex);
#endif

	// wait on full
	if (NEXT(data->write) == data->read)
			return -1;

		/* sgx_thread_cond_wait(&full_cond, &rbuf_mutex); */

	memcpy(data->in_rbuf[data->write].pkt, pkt, pkt_size);
	data->in_rbuf[data->write].size = pkt_size;
	/* in_rbuf[write].ts = ts; */
	memcpy(&(data->in_rbuf[data->write].ts), &ts, sizeof(timeval_t));
	data->write = NEXT(data->write);

	sgx_thread_cond_signal(&empty_cond);

	sgx_thread_mutex_unlock(&rbuf_mutex);
}

#endif
