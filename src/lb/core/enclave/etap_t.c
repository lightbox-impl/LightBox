#include "etap_t.h"
#include <stdlib.h>
#include <string.h>
#include "crypto_t.h"
#include "rx_ring_opt.h"
#include "state_mgmt_t.h"
#include "utils_t.h"

#define CROSS_RECORD
#define ETAP_RING_MODE 0  // for experiment purpose only at current stage

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
uint64_t rtt;

etap_controller_t* etap_controller_instance;

void etap_set_flow(int crt_flow) { mos_flow_cnt = crt_flow; }

rx_ring_t* etap_rx_init(const int mode) {
	rx_ring_data_t* pData;
	pData = (rx_ring_data_t*)malloc(sizeof(rx_ring_data_t));
	memset(pData->cachePad0, 0, CACHE_LINE);
	pData->read = 0;
	pData->write = 0;
	memset(pData->cachePad1, 0, CACHE_LINE - 2 * sizeof(int));
	pData->localWrite = 0;
	pData->nextRead = 0;
	pData->rBatch = 0;
	memset(pData->cachePad2, 0, CACHE_LINE - 3 * sizeof(int));
	pData->localRead = 0;
	pData->nextWrite = 0;
	pData->wBatch = 0;
	pData->try_before_sleep = 0;
	memset(pData->cachePad3, 0, CACHE_LINE - 4 * sizeof(int));
	pData->batchSize = PKT_RINFBUF_CAP / 4;
	memset(pData->cachePad4, 0, CACHE_LINE - 1 * sizeof(int));

	pData->in_rbuf = malloc(sizeof(rbuf_pkt_t) * PKT_RINFBUF_CAP);

	rx_ring_t* r = (rx_ring_t*)malloc(sizeof(rx_ring_t));
	r->rData = pData;

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

	return r;
}

void etap_rx_deinit(rx_ring_t* p) {
		free(p->rData->in_rbuf);
		free(p->rData);
		free(p);
}

etap_controller_t* etap_controller_init(const int ring_mode,
				    const int etap_db_mode) {
	etap_controller_t* p =
	    (etap_controller_t*)malloc(sizeof(etap_controller_t));
	p->rx_ring_instance = etap_rx_init(ring_mode);
	p->tx_ring_instance = etap_rx_init(ring_mode);
	// poll_driver_init();

	/* switch (etap_db_mode) { */
		/* case 0: */
			/* p->ecall_etap_start = &ecall_etap_start_caida; */
			/* break; */
		/* case 1: */
			/* p->ecall_etap_start = &ecall_etap_start_live; */
			/* break; */
		/* case 2: */
			/* p->ecall_etap_start = &ecall_etap_start_micro; */
			/* break; */

		/* default: */
			/* p->ecall_etap_start = &ecall_etap_start_caida; */
			/* break; */
	/* } */

	return p;
}

void etap_controller_deinit(etap_controller_t* p) {
		etap_rx_deinit(p->rx_ring_instance);
		etap_rx_deinit(p->tx_ring_instance);
		free(p)
}

// This function will be called in the untrusted call "etap_init()". 
void ecall_etap_controller_init(int* ret, const int ring_mode,
				const int etap_db_mode) {
	*ret = 2;
	if (etap_controller_instance == NULL) {
		etap_controller_instance =
		    etap_controller_init(ring_mode, etap_db_mode);
		*ret = 0;
	} else {
		*ret = 1;
	}
}

int cnt_timeouted;
int DoCallTimes;
int DoDfcTimes;
long long DoDfcSize;
int cnt_ip;
int cnt_tcp;
int cnt_icmp;
int cnt_other;
int err_drop_4;
int err_drop_3;
int err_drop_2;
int err_drop_1;
int client_new_stream;
int server_new_stream;


static inline void rx_data_init(rx_ring_t* handle) {
	rx_ring_data_t* dataPtr = handle->rData;
	/*shared control variables*/
	dataPtr->read = 0;
	dataPtr->write = 0;
	/*consumers local variables*/
	dataPtr->localWrite = 0;
	dataPtr->nextRead = 0;
	dataPtr->rBatch = 0;
	/*producers local variables*/
	dataPtr->localRead = 0;
	dataPtr->nextWrite = 0;
	dataPtr->wBatch = 0;
}



double ecall_etap_start(int lbn_record_size,
			      int lbn_record_per_batch) {
	rx_ring_t* handle = etap_controller_instance->rx_ring_instance;
	rx_data_init(handle);
	
	static uint8_t dec_record[1024 * 16];  // 64KB

	// The pointers are from outside
	uint8_t* batch;
	// static uint64_t batch_ts = 0;

	// pending packet buffer
	uint16_t pending_partial_size = 0;
	uint16_t pending_ts_pkt_size = 0;  // read from sized packet stream
	static uint8_t pending_ts_pkt[2048] = {0};
	timeval_t pending_pkt_ts = {0, 0};

	double total_byte = 0;
	long long start_s, start_ns, end_s, end_ns;

	// record tracking
	int rec_idx = 0;
	uint8_t* crt_record = 0;
	uint8_t* crt_mac = 0;
	// in-record tracking
	uint8_t* crt_pos = 0;

	static int pkt_count = 0;
	static int round_idx = 0;
	ocall_get_time(&start_s, &start_ns);
	while (1) {
		// ocall_lb_etap_in_memory(&batch);
		// fixed
		/* eprintf("ocall etap in \n"); */
		ocall_lb_etap_in(&batch);
		ocall_get_rtt(&rtt);

		crt_record = batch;
		crt_mac = crt_record + lbn_record_size;

		// test done
		if (unlikely(batch == 0)) {
			ocall_get_time(&end_s, &end_ns);
			double elapsed_us = (end_s - start_s) * 1000000.0 +
					    (end_ns - start_ns) / 1000.0;

			eprintf(
			    "Round %d - pkt %d - delay %f - tput %f \
					\nflow %d dfc %d dfc effective %d dfc size %lld timeouted %d, \
					\nip %d, tcp %d, icmp %d, other %d, \
					\nerr_drop_1 %d, err_drop_2 %d, err_drop_3 %d, err_drop_4 %d\
					\nsum %d, client %d, server %d, all %d \n\n",
			    ++round_idx, pkt_count, elapsed_us / pkt_count,
			    total_byte * 8.0 / elapsed_us, mos_flow_cnt,
			    DoCallTimes, DoDfcTimes, DoDfcSize, cnt_timeouted,
			    cnt_ip, cnt_tcp, cnt_icmp, cnt_other, err_drop_1,
			    err_drop_2, err_drop_3, err_drop_4,
			    cnt_tcp + cnt_icmp + cnt_other + err_drop_1 +
				err_drop_2 + err_drop_3 + err_drop_4,
			    client_new_stream, server_new_stream,
			    client_new_stream + server_new_stream);

			int cache_hit = lb_state_stats.cache_hit -
					last_state_stats.cache_hit;
			int store_hit = lb_state_stats.store_hit -
					last_state_stats.store_hit;
			int miss =
			    last_state_stats.miss - last_state_stats.miss;
			int total = cache_hit + store_hit + miss;
			eprintf("Miss rate %f \n\n",
				1 - cache_hit * 1.0 / total);
			last_state_stats = lb_state_stats;
			pkt_count = 0;

			// etap_stopping = 1;

			return total_byte * 8.0 / elapsed_us;
		} 
		else {
			for (rec_idx = 0; rec_idx < lbn_record_per_batch;
			     ++rec_idx) {
				/* decrypt and verify */
				if (!veri_dec(crt_record, lbn_record_size,
					      dec_record, crt_mac)) {
					eprintf("veri_dec() fail!\n");
					abort();
				}

				// eprintf("rec %d\n", rec_idx);

				// eprintf("rec %d\n", rec_idx);
				// memcpy(dec_record, crt_record,
				// lbn_record_size);
				crt_pos = dec_record;
				int free = lbn_record_size;

				/* handle pending packet that is only partially
				 * received */
				if (pending_ts_pkt_size != 0) {
					// partial_size could be 0, in which
					// case only the "size" part was read
					int remaining = pending_ts_pkt_size -
							pending_partial_size;
					memcpy(pending_ts_pkt +
						   pending_partial_size,
					       crt_pos, remaining);
					crt_pos += remaining;
					free -= remaining;

					// extract timestamp
					memcpy(&pending_pkt_ts, pending_ts_pkt,
					       sizeof(pending_pkt_ts));
					// add rtt to pkt ts
					
					pending_pkt_ts.tv_usec += rtt % (uint64_t)1e6;
					pending_pkt_ts.tv_sec += rtt / (uint64_t) 1e6;
					// write to etap ring
					handle->write_pkt(
					    pending_ts_pkt +
						sizeof(pending_pkt_ts),
					    pending_ts_pkt_size -
						sizeof(pending_pkt_ts),
					    pending_pkt_ts, handle->rData);
					// TODO tx write pkt?
					total_byte += pending_ts_pkt_size;
					++pkt_count;
				}

				/* recover more packets from the record */
				while (1) {
					if (free >=
					    (int)sizeof(pending_ts_pkt_size)) {
						/* read size */
						memcpy(
						    &pending_ts_pkt_size,
						    crt_pos,
						    sizeof(
							pending_ts_pkt_size));
						crt_pos +=
						    sizeof(pending_ts_pkt_size);
						free -=
						    sizeof(pending_ts_pkt_size);

						/* write full packet to etap */
						if (free >=
						    pending_ts_pkt_size) {
							// extract timestamp
							memcpy(
							    &pending_pkt_ts,
							    crt_pos,
							    sizeof(
								pending_pkt_ts));

							// add rtt to timestamp
							pending_pkt_ts.tv_usec += rtt % (uint64_t)1e6;
							pending_pkt_ts.tv_sec += rtt / (uint64_t) 1e6;

							// write to etap ring
							handle->write_pkt(
							    crt_pos +
								sizeof(
								    pending_pkt_ts),
							    pending_ts_pkt_size -
								sizeof(
								    pending_pkt_ts),
							    pending_pkt_ts, handle->rData);

							// legacy : ts bytes are
							// counted
							total_byte +=
							    pending_ts_pkt_size;
							++pkt_count;

							// eprintf("pkt %d : %d
							// %d\n",
							// pkt_count,
							// pending_ts_pkt_size -
							// sizeof(pending_pkt_ts),
							// free);

							crt_pos +=
							    pending_ts_pkt_size;
							free -=
							    pending_ts_pkt_size;
						}
						/* buffer partial packet until
						   next record */
						else {

							pending_partial_size =
							    free;
							memcpy(
							    pending_ts_pkt,
							    crt_pos,
							    pending_partial_size);

							// no need to update the
							// tracking data
							// crt_pos +=
							// pending_partial_size;
							// free = 0;

							break;
						}
					} else {
						/* unlikely - discard the left 0
						 * or 1 byte */
						pending_ts_pkt_size = 0;
						break;
					}
				}

				crt_record += lbn_record_size + MAC_SIZE;
				crt_mac = crt_record + lbn_record_size;
			}
		}
	}
}
// this should be called only once
double ecall_etap_start_live(int lbn_record_size,
			     int lbn_record_per_batch) {
	eprintf("etapn started record %d rec_per_bat %d!\n", lbn_record_size,
		lbn_record_per_batch);
	rx_ring_t* handle = etap_controller_instance->rx_ring_instance;

	rx_data_init(handle);

	static uint8_t dec_record[1024 * 16];  // 64KB

	// The pointers are from outside
	uint8_t* batch;

	// pending packet buffer
	uint16_t pending_partial_size = 0;

	uint16_t pending_ts_pkt_size = 0;  // read from sized packet stream
	static uint8_t pending_ts_pkt[2048] = {0};
	/* time_t pending_pkt_ts = 0; */
	timeval_t pending_pkt_ts = {0, 0};

	double total_byte = 0;
	long long start_s, start_ns, end_s, end_ns;

	int pkt_count = 0;
	int round_idx = 0;
	ocall_get_time(&start_s, &start_ns);
	while (1) {
		// fixed
		ocall_lb_etap_in(&batch);

		uint8_t* crt_record = batch;
		uint8_t* crt_mac = crt_record + lbn_record_size;

		if (unlikely(batch == 0)) {
			eprintf("empty batch!\n");
			abort();
		}

		int rec_idx = 0;
		for (rec_idx = 0; rec_idx < lbn_record_per_batch; ++rec_idx) {
			/* decrypt and verify */
			if (!veri_dec(crt_record, lbn_record_size, dec_record,
				      crt_mac)) {
				eprintf("veri_dec() fail, dec mac offset %d!\n",
					crt_mac - crt_record);
				abort();
			}

			// in-record tracking
			uint8_t* crt_pos = dec_record;
			int free = lbn_record_size;

			/* handle pending packet that is only partially received
			 */
			if (pending_ts_pkt_size != 0) {
				// partial_size could be 0, in which case only
				// the "size" part was read
				int remaining =
				    pending_ts_pkt_size - pending_partial_size;
				memcpy(pending_ts_pkt + pending_partial_size,
				       crt_pos, remaining);
				crt_pos += remaining;
				free -= remaining;

				// extract timestamp
				memcpy(&pending_pkt_ts, pending_ts_pkt,
				       sizeof(pending_pkt_ts));
				// write to etap ring
				handle->write_pkt(
				    pending_ts_pkt + sizeof(pending_pkt_ts),
				    pending_ts_pkt_size -
					sizeof(pending_pkt_ts),
				    pending_pkt_ts, handle->rData);
				// TODO tx write pkt?
				total_byte += pending_ts_pkt_size;
				++pkt_count;
			}

			/* recover more packets from the record */
			while (1) {
				if (free >=(int) sizeof(pending_ts_pkt_size)) {
					/* read size */
					memcpy(&pending_ts_pkt_size, crt_pos,
					       sizeof(pending_ts_pkt_size));
					crt_pos += sizeof(pending_ts_pkt_size);
					free -= sizeof(pending_ts_pkt_size);

					/* write full packet to etap */
					if (free >= pending_ts_pkt_size) {
						// extract timestamp
						memcpy(&pending_pkt_ts, crt_pos,
						       sizeof(pending_pkt_ts));

						// write to etap ring
						handle->write_pkt(
						    crt_pos +
							sizeof(pending_pkt_ts),
						    pending_ts_pkt_size -
							sizeof(pending_pkt_ts),
						    pending_pkt_ts, handle->rData);

						// legacy : ts bytes are counted
						total_byte +=
						    pending_ts_pkt_size;
						++pkt_count;

						crt_pos += pending_ts_pkt_size;
						free -= pending_ts_pkt_size;
					}
					/* buffer partial packet until next
					   record */
					else {

						pending_partial_size = free;
						memcpy(pending_ts_pkt, crt_pos,
						       pending_partial_size);

						// no need to update the
						// tracking data
						// crt_pos +=
						// pending_partial_size; free =
						// 0;

						break;
					}
				} else {
					/* unlikely - discard the left 0 or 1
					 * byte */
					pending_ts_pkt_size = 0;
					break;
				}
			}

			crt_record += lbn_record_size + MAC_SIZE;
			crt_mac = crt_record + lbn_record_size;

			/* extern int cacheMissFlow; */
			/* extern int cacheHitFlow; */
			/* extern int DoCallTimes; */

			/* // print round stats */
			/* if (unlikely(pkt_count >= TEST_ITVL)) { */
				/* ocall_get_time(&end_s, &end_ns); */
				/* double elapsed_us = */
					/* (end_s - start_s) * 1000000.0 + */
					/* (end_ns - start_ns) / 1000.0; */

				/* eprintf( */
					/* "Round %d - delay %f - tput %f, Miss Rate " */
					/* "%lf%%, #dfc:%d, flow_cache:%d, " */
					/* "flow_store:%d, mos_flow:%d\n", */
					/* ++round_idx, elapsed_us / pkt_count, */
					/* total_byte * 8.0 / elapsed_us, */
					/* (cacheMissFlow)*100.0 / */
					/* (cacheHitFlow + cacheMissFlow), */
					/* DoCallTimes, cache_lkup_table.count, */
					/* store_lkup_table.count, mos_flow_cnt); */
				/* pkt_count = 0; */
				/* total_byte = 0; */
				/* cacheMissFlow = 0; */
				/* cacheHitFlow = 0; */
				/* DoCallTimes = 0; */
				/* ocall_get_time(&start_s, &start_ns); */
			/* } */
		}
	}

	// never executed
	return 0.0;
}
double ecall_etap_start_micro(int lbn_record_size,
			      int lbn_record_per_batch) {
	return 0.0;
}

