#include "etap_t.h"
#include "rx_ring_opt.h"

#include "crypto_t.h"
#include "lb_edge_t.h"
#include "state_mgmt_t.h"
#include "utils_t.h"

/* #include "../common/lb_config.h" */
#include "include/lb_config.h"

#include "sgx_thread.h"

#include <stdlib.h>
#include <string.h>

#define CROSS_RECORD

timeval_t time_now;
void get_clock(timeval_t* ts) { memcpy(ts, &time_now, sizeof(timeval_t)); }

timeval_t trace_clock = {0, 0};

/* test */
#include "cuckoo/cuckoo_hash.h"
extern struct cuckoo_hash cache_lkup_table;
extern struct cuckoo_hash store_lkup_table;
extern lb_state_stats_t lb_state_stats;
lb_state_stats_t last_state_stats = {0, 0, 0};

int mos_flow_cnt = 0;

void etap_set_flow(int crt_flow) { mos_flow_cnt = crt_flow; }

void etap_rx_init(rx_ring_t* r, const int mode) {
	rx_ring_t tmp;

	rx_ring_data_t* data = &(tmp.rData);
	memset(data->cachePad0, 0, CACHE_LINE);
	data->read = 0;
	data->write = 0;
	memset(data->cachePad1, 0, CACHE_LINE - 2 * sizeof(int));
	data->localWrite = 0;
	data->nextRead = 0;
	data->rBatch = 0;
	memset(data->cachePad2, 0, CACHE_LINE - 3 * sizeof(int));
	data->localRead = 0;
	data->nextWrite = 0;
	data->wBatch = 0;
	data->try_before_sleep = 0;
	memset(data->cachePad3, 0, CACHE_LINE - 4 * sizeof(int));
	data->batchSize = PKT_RINFBUF_CAP / 4;
	memset(data->cachePad4, 0, CACHE_LINE - 1 * sizeof(int));

	r = (rx_ring_t*)malloc(sizeof(rx_ring_t));
	memcpy(r, &tmp, sizeof(rx_ring_t));

	/* r->ecall_etap_start = &ecall_etap_start_caida; */

	switch (mode) {
		case 0:
			r->read_pkt = &read_pkt_lockless_cache_efficient;
			r->write_pkt = &write_pkt_lockless_cache_efficient;
			break;

		case 1:
			r->read_pkt = &read_pkt_lockless;
			r->write_pkt = &write_pkt_lockless;
			break;

		case 2:
			r->read_pkt = &read_pkt_lock;
			r->write_pkt = &write_pkt_lock;
			break;

		default:
			r->read_pkt = &read_pkt_lockless_cache_efficient;
			r->write_pkt = &write_pkt_lockless_cache_efficient;
			break;
	}
}
