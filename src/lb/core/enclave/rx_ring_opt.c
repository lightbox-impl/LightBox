#ifdef GLOBAL

#include "rx_ring_opt.h"

extern timeval_t etap_clock;

/* Variable definitions */
char cachePad0[CACHE_LINE] = {0};
/*shared control variables*/
volatile int read = 0;
volatile int write = 0;
char cachePad1[CACHE_LINE - 2 * sizeof(int)] = {0};
/*consumer local variables*/
int localWrite = 0;
int nextRead = 0;
int rBatch = 0;
char cachePad2[CACHE_LINE - 3 * sizeof(int)] = {0};
/*producer local variables*/
int localRead = 0;
int nextWrite = 0;
int wBatch = 0;
int try_before_sleep = 0;
char cachePad3[CACHE_LINE - 4 * sizeof(int)] = {0};
/*constants*/
const int batchSize = PKT_RINFBUF_CAP / 4;
char cachePad4[CACHE_LINE - 1 * sizeof(int)] = {0};
rbuf_pkt_t in_rbuf[PKT_RINFBUF_CAP];

int read_pkt(uint8_t* pkt, int* size, timeval_t* ts) {
    if (nextRead == localWrite) {
	while (nextRead == write)
	    ;
	localWrite = write;
    }
    memcpy(pkt, in_rbuf[nextRead].pkt, in_rbuf[nextRead].size);
    *size = in_rbuf[nextRead].size;
    memcpy(ts, &in_rbuf[nextRead].ts, sizeof(timeval_t));
    /* *ts = in_rbuf[nextRead].ts; */

    nextRead = NEXT(nextRead);
    ++rBatch;
    if (rBatch > batchSize) {
	read = nextRead;
	rBatch = 0;
    }
	return 0;
}

int write_pkt(const uint8_t* pkt, int pkt_size, timeval_t ts) {
    int afterNextWrite = NEXT(nextWrite);
    if (afterNextWrite == localRead) {
	while (afterNextWrite == read) {
	    ;
	}
	localRead = read;
    }

/* TODO: debuging this part.  */
	/* static int counter = 1; */
	/* eprintf("write pkt count %d\n", counter++); */
	// static uint8_t buffer[1514];
	/* eprintf("in wpkt, pkt size %d\n", pkt_size); */
	rbuf_pkt_t* cur_pkt = &(in_rbuf[nextWrite]);
	/* memcpy(cur_pkt->pkt, pkt, pkt_size); */
	cur_pkt->size = pkt_size;
	cur_pkt->ts.tv_sec = ts.tv_sec;
	cur_pkt->ts.tv_usec = ts.tv_usec;
	memcpy(cur_pkt->pkt, pkt, pkt_size);
	
    /* memcpy(in_rbuf[nextWrite].pkt, pkt, pkt_size); */
    /* in_rbuf[nextWrite].size = pkt_size; */
    /* in_rbuf[nextWrite].ts = ts; */
	/* memcpy(&(in_rbuf[nextWrite].ts), &ts, sizeof(ts)); */
	/* in_rbuf[nextWrite].ts.tv_sec = ts.tv_sec; */
	/* in_rbuf[nextWrite].ts.tv_usec = ts.tv_usec; */
	/* eprintf("copied ts\n"); */

    /* etap_clock = ts; */
	memcpy(&etap_clock, &ts, sizeof(ts));
	/* eprintf("copied clock\n"); */

    /* trace_clock.tv_sec = ts; // second only */
    // memcpy(&trace_clock, &ts, sizeof(ts));

    nextWrite = afterNextWrite;
    wBatch++;
    if (wBatch >= batchSize) {
	write = nextWrite;
	wBatch = 0;
    }
	return 0;
}

int read_pkt_nonblock(uint8_t* pkt, int* size, timeval_t* ts) {
    if (nextRead == localWrite) {
	if (nextRead == write) return -1;
	localWrite = write;
    }
    memcpy(pkt, in_rbuf[nextRead].pkt, in_rbuf[nextRead].size);
    *size = in_rbuf[nextRead].size;
    memcpy(ts, &in_rbuf[nextRead].ts, sizeof(timeval_t));
    /* *ts = in_rbuf[nextRead].ts; */

    nextRead = NEXT(nextRead);
    ++rBatch;
    if (rBatch > batchSize) {
	read = nextRead;
	rBatch = 0;
    }
    return 0;
}

int write_pkt_nonblock(const uint8_t* pkt, int pkt_size, timeval_t ts) {
    int afterNextWrite = NEXT(nextWrite);
    if (afterNextWrite == localRead) {
	if (afterNextWrite == read) {
	    return -1;
	}
	localRead = read;
    }

    memcpy(in_rbuf[nextWrite].pkt, pkt, pkt_size);
    in_rbuf[nextWrite].size = pkt_size;
    /* in_rbuf[nextWrite].ts = ts; */
    memcpy(&in_rbuf[nextWrite], &ts, sizeof(timeval_t));

    /* time_now = ts; */
    memcpy(&etap_clock, &ts, sizeof(ts));

    /* trace_clock.tv_sec = ts; // second only */
    /* memcpy(&trace_clock, &ts, sizeof(ts)); */

    nextWrite = afterNextWrite;
    wBatch++;
    if (wBatch >= batchSize) {
	write = nextWrite;
	wBatch = 0;
    }
    return 0;
}

#endif


#ifndef GLOBAL

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

#endif /* GLOBAL */
