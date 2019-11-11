#ifdef GLOBAL

#include "rx_ring_opt.h"

extern timeval_t etap_clock;
/* extern global_rx_data; */
/* extern global_tx_data; */

/* Variable definitions */
char cachePad0_tx[CACHE_LINE] = {0};
/*shared control variables*/
volatile int read_tx = 0;
volatile int write_tx = 0;
char cachePad1_tx[CACHE_LINE - 2 * sizeof(int)] = {0};
/*consumer local variables*/
int localWrite_tx = 0;
int nextRead_tx = 0;
int rBatch_tx = 0;
char cachePad2_tx[CACHE_LINE - 3 * sizeof(int)] = {0};
/*producer local variables*/
int localRead_tx = 0;
int nextWrite_tx = 0;
int wBatch_tx = 0;
int try_before_sleep_tx = 0;
char cachePad3_tx[CACHE_LINE - 4 * sizeof(int)] = {0};
/*constants*/
const int batchSize_tx = PKT_RINFBUF_CAP / 4;
char cachePad4_tx[CACHE_LINE - 1 * sizeof(int)] = {0};
rbuf_pkt_t in_rbuf_tx[PKT_RINFBUF_CAP];

int read_pkt_tx(uint8_t* pkt, int* size, timeval_t* ts) {
    if (nextRead_tx == localWrite_tx) {
	while (nextRead_tx == write_tx)
	    ;
	localWrite_tx = write_tx;
    }
    memcpy(pkt, in_rbuf_tx[nextRead_tx].pkt, in_rbuf_tx[nextRead_tx].size);
    *size = in_rbuf_tx[nextRead_tx].size;
    memcpy(ts, &in_rbuf_tx[nextRead_tx].ts, sizeof(timeval_t));
    /* *ts = in_rbuf[nextRead].ts; */

    nextRead_tx = NEXT(nextRead_tx);
    ++rBatch_tx;
    if (rBatch_tx > batchSize_tx) {
	read_tx = nextRead_tx;
	rBatch_tx = 0;
    }
}

int write_pkt_tx(const uint8_t* pkt, int pkt_size, timeval_t ts) {
    int afterNextWrite_tx = NEXT(nextWrite_tx);
    if (afterNextWrite_tx == localRead_tx) {
	while (afterNextWrite_tx == read_tx) {
	    ;
	}
	localRead_tx = read_tx;
    }

    memcpy(in_rbuf_tx[nextWrite_tx].pkt, pkt, pkt_size);
    in_rbuf_tx[nextWrite_tx].size = pkt_size;
    memcpy(&in_rbuf_tx[nextWrite_tx], &ts, sizeof(timeval_t));

    memcpy(&etap_clock, &ts, sizeof(ts));

    nextWrite_tx = afterNextWrite_tx;
    wBatch_tx++;
    if (wBatch_tx >= batchSize_tx) {
	write_tx = nextWrite_tx;
	wBatch_tx = 0;
    }
}

int read_pkt_nonblock_tx(uint8_t* pkt, int* size, timeval_t* ts) {
    if (nextRead_tx == localWrite_tx) {
	if (nextRead_tx == write_tx) return -1;
	localWrite_tx = write_tx;
    }
    memcpy(pkt, in_rbuf_tx[nextRead_tx].pkt, in_rbuf_tx[nextRead_tx].size);
    *size = in_rbuf_tx[nextRead_tx].size;
    memcpy(ts, &in_rbuf_tx[nextRead_tx].ts, sizeof(timeval_t));
    /* *ts = in_rbuf[nextRead].ts; */

    nextRead_tx = NEXT(nextRead_tx);
    ++rBatch_tx;
    if (rBatch_tx > batchSize_tx) {
	read_tx = nextRead_tx;
	rBatch_tx = 0;
    }
}

int write_pkt_nonblock_tx(const uint8_t* pkt, int pkt_size, timeval_t ts) {
    int afterNextWrite_tx = NEXT(nextWrite_tx);
    if (afterNextWrite_tx == localRead_tx) {
	if (afterNextWrite_tx == read_tx) {
	    return -1;
	}
	localRead_tx = read_tx;
    }

    memcpy(in_rbuf_tx[nextWrite_tx].pkt, pkt, pkt_size);
    in_rbuf_tx[nextWrite_tx].size = pkt_size;
    memcpy(&in_rbuf_tx[nextWrite_tx], &ts, sizeof(timeval_t));

    memcpy(&etap_clock, &ts, sizeof(ts));

    nextWrite_tx = afterNextWrite_tx;
    wBatch_tx++;
    if (wBatch_tx >= batchSize_tx) {
	write_tx = nextWrite_tx;
	wBatch_tx = 0;
    }
}

#endif
