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
}

int write_pkt(const uint8_t* pkt, int pkt_size, timeval_t ts) {
    int afterNextWrite = NEXT(nextWrite);
    if (afterNextWrite == localRead) {
	while (afterNextWrite == read) {
	    ;
	}
	localRead = read;
    }

    memcpy(in_rbuf[nextWrite].pkt, pkt, pkt_size);
    in_rbuf[nextWrite].size = pkt_size;
    /* in_rbuf[nextWrite].ts = ts; */
    memcpy(&in_rbuf[nextWrite], &ts, sizeof(timeval_t));

    /* etap_clock = ts; */
    memcpy(&etap_clock, &ts, sizeof(ts));

    /* trace_clock.tv_sec = ts; // second only */
    // memcpy(&trace_clock, &ts, sizeof(ts));

    nextWrite = afterNextWrite;
    wBatch++;
    if (wBatch >= batchSize) {
	write = nextWrite;
	wBatch = 0;
    }
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
