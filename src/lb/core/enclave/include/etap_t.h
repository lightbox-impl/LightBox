#ifndef LB_NET_T_H
#define LB_NET_T_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>
#include <time.h>

#include "lb_config.h"
#include "lb_time.h"
#include "lb_type.h"
// #include "poll.h"
#include "sgx_thread.h"
#include "state_mgmt_t.h"
#include "utils_t.h"

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
	// rbuf_pkt_t in_rbuf[PKT_RINFBUF_CAP];
	rbuf_pkt_t* in_rbuf;

} rx_ring_data_t;

typedef struct rx_ring {
	rx_ring_data_t* rData;
	void (*read_pkt)(uint8_t*, int*, timeval_t*, rx_ring_data_t*);
	void (*write_pkt)(const uint8_t*, int, timeval_t, rx_ring_data_t*);
} rx_ring_t;

typedef struct etap_controller {
	rx_ring_t* rx_ring_instance;
	rx_ring_t* tx_ring_instance;
//	poll_driver_t* pd;
	double (*ecall_etap_start)(rx_ring_t*, int, int);
} etap_controller_t;

typedef struct poll_driver {
	etap_controller_t* etap;
	void (*read_pkt)(uint8_t*, int*, timeval_t*, etap_controller_t* etap);
	void (*write_pkt)(const uint8_t*, int, timeval_t, etap_controller_t* etap);
} poll_driver_t;

etap_controller_t* etap_controller_init(const int ring_mode,
					const int etap_db_mode);

rx_ring_t* etap_rx_init(const int mode);

void get_clock(timeval_t* ts);

void etap_set_flow(int crt_flow);

void ecall_etap_controller_init(int* ret, const int ring_mode,
				const int etap_db_mode);

double ecall_etap_start(int lbn_record_size, int lbn_record_per_batch);

double ecall_etap_start_live(int lbn_record_size,
			     int lbn_record_per_batch);

double ecall_etap_start_micro(int lbn_record_size,
			      int lbn_record_per_batch);

double ecall_etap_sendto_next_box(int lbn_record_size,
				  int lbn_record_per_batch);

poll_driver_t* poll_driver_init();

void prepare_batch(rx_ring_t* handle, int lbn_record_size, int lbn_record_per_batch);
#ifdef __cplusplus
}
#endif

#endif
