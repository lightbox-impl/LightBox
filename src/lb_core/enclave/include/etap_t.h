#ifndef LB_NET_T_H
#define LB_NET_T_H

#include <stdint.h>
#include <time.h>
#include "include/lb_type.h"
#include "include/lb_config.h"

#define PKT_RINFBUF_CAP 256
#define NEXT(n) (n + 1) % PKT_RINFBUF_CAP
#define CACHE_LINE 64

//#define MAX_PKT_SIZE 2036 // to align sizeof(rbuf_pkt_t) with cache line
// typedef struct timeval timeval_t;

typedef struct rbuf_pkt {
	uint8_t pkt[MAX_FRAME_SIZE];
	struct timeval ts;
	int size;
} rbuf_pkt_t;

typedef struct rx_ring_data {
	/* Cache line protection for variables */
	char cachePad0[CACHE_LINE];
	/* Shared control variables */
	volatile int read;
	volatile int write;
	char cachePad1[CACHE_LINE - 2 * sizeof(int)];
	/* Consumer local variables */
	int localWrite;
	int nextRead;
	int rBatch;
	char cachePad2[CACHE_LINE - 3 * sizeof(int)];
	/* Producer local variables */
	int localRead;
	int nextWrite;
	int wBatch;
	int try_before_sleep;
	char cachePad3[CACHE_LINE - 4 * sizeof(int)];
	/* Constants */
	int batchSize;
	char cachePad4[CACHE_LINE - 1 * sizeof(int)];
	/* End of cache line protection  */

	/* pkt ring buffer */
	rbuf_pkt_t in_rbuf[PKT_RINFBUF_CAP];

} rx_ring_data_t;

typedef struct rx_ring {
	rx_ring_data_t rData;
	void (*read_pkt)(uint8_t*, int*, timeval_t*, rx_ring_data_t*);
	void (*write_pkt)(const uint8_t*, int, timeval_t, rx_ring_data_t*);
	// double (*ecall_etap_start)(rx_ring_t*, int, int);

} rx_ring_t;

void etap_rx_init(rx_ring_t* r, const int mode);

void get_clock(timeval_t* ts);

void etap_set_flow(int crt_flow);

#endif
