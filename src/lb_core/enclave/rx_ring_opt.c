#include "rx_ring_opt.h"
#include "etap_t.h"

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

double ecall_etap_start_caida(rx_ring_t* handle, int lbn_record_size,
			      int lbn_record_per_batch) {
	rx_ring_data_t* dataPtr = &handle->rData;
	/*shared control variables*/
	dataPtr->read = 0;
	dataPtr->write = 0;
	/*consumers local variables*/
	dataPtr->localWrite = 0;
	dataPtr->nextRead = 0;
	dataPtr->rBatch = 0;
	/*producer local variables*/
	dataPtr->localRead = 0;
	dataPtr->nextWrite = 0;
	dataPtr->wBatch = 0;

	static uint8_t dec_record[1024 * 16];  // 64KB

	// The pointers are from outside
	uint8_t* batch;
	// static uint64_t batch_ts = 0;

	// pending packet buffer
#ifdef CROSS_RECORD
	uint16_t pending_partial_size = 0;
#endif
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
		ocall_lb_etap_in(&batch);

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
#if LightBox == 1
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
#endif
			pkt_count = 0;

			// etap_stopping = 1;

			return total_byte * 8.0 / elapsed_us;
		} else {
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
#ifdef CROSS_RECORD
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
					// write to etap ring
					handle->write_pkt(
					    pending_ts_pkt +
						sizeof(pending_pkt_ts),
					    pending_ts_pkt_size -
						sizeof(pending_pkt_ts),
					    pending_pkt_ts);
					total_byte += pending_ts_pkt_size;
					++pkt_count;
				}
#endif
				/* recover more packets from the record */
				while (1) {
					if (free >=
					    sizeof(pending_ts_pkt_size)) {
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

							// write to etap ring
							handle->write_pkt(
							    crt_pos +
								sizeof(
								    pending_pkt_ts),
							    pending_ts_pkt_size -
								sizeof(
								    pending_pkt_ts),
							    pending_pkt_ts);

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
#ifdef CROSS_RECORD
							pending_partial_size =
							    free;
							memcpy(
							    pending_ts_pkt,
							    crt_pos,
							    pending_partial_size);
#endif
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
#ifdef CROSS_RECORD
						pending_ts_pkt_size = 0;
#endif
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
double ecall_etap_start_live(rx_ring_t* handle, int lbn_record_size,
			     int lbn_record_per_batch) {
	eprintf("etapn started record %d rec_per_bat %d!\n", lbn_record_size,
		lbn_record_per_batch);

	rx_ring_data_t* dataPtr = &handle->rData;
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

	static uint8_t dec_record[1024 * 16];  // 64KB

	// The pointers are from outside
	uint8_t* batch;

	// pending packet buffer
#ifdef CROSS_RECORD
	uint16_t pending_partial_size = 0;
#endif
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
		// ocall_lb_etap_in_memory(&batch);
		// fixed
		ocall_lb_etap_in(&batch);

		uint8_t* crt_record = batch;
		uint8_t* crt_mac = crt_record + lbn_record_size;

		if (unlikely(batch == 0)) {
			eprintf("empty batch!\n");
			abort();
		}

		// eprintf("%s\n", batch);

		int rec_idx = 0;
		for (rec_idx = 0; rec_idx < lbn_record_per_batch; ++rec_idx) {
			/* decrypt and verify */
			if (!veri_dec(crt_record, lbn_record_size, dec_record,
				      crt_mac)) {
				eprintf("veri_dec() fail, dec mac offset %d!\n",
					crt_mac - crt_record);
				abort();
			}

			// eprintf("rec %d\n", rec_idx);

			// memcpy(dec_record, crt_record, lbn_record_size);
			// in-record tracking
			uint8_t* crt_pos = dec_record;
			int free = lbn_record_size;
#ifdef CROSS_RECORD
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
				    pending_pkt_ts);
				total_byte += pending_ts_pkt_size;
				++pkt_count;
			}
#endif
			/* recover more packets from the record */
			while (1) {
				if (free >= sizeof(pending_ts_pkt_size)) {
					/* read size */
					memcpy(&pending_ts_pkt_size, crt_pos,
					       sizeof(pending_ts_pkt_size));
					crt_pos += sizeof(pending_ts_pkt_size);
					free -= sizeof(pending_ts_pkt_size);

					/*eprintf("%d %d %d\n",
					   pending_ts_pkt_size,
					   pending_partial_size, free); if
					   (pending_ts_pkt_size > MAX_FRAME_SIZE
					   || pending_ts_pkt_size < 0)
							    {
							    eprintf("eeerror
					   %d\n", pending_ts_pkt_size); abort();
							    }*/
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
						    pending_pkt_ts);

						// legacy : ts bytes are counted
						total_byte +=
						    pending_ts_pkt_size;
						++pkt_count;

						// eprintf("pkt %d : %d %d\n",
						//	pkt_count,
						// pending_ts_pkt_size -
						// sizeof(pending_pkt_ts),
						// free);

						crt_pos += pending_ts_pkt_size;
						free -= pending_ts_pkt_size;
					}
					/* buffer partial packet until next
					   record */
					else {
#ifdef CROSS_RECORD
						pending_partial_size = free;
						memcpy(pending_ts_pkt, crt_pos,
						       pending_partial_size);
#endif
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
#ifdef CROSS_RECORD
					pending_ts_pkt_size = 0;
#endif
					break;
				}
			}

			crt_record += lbn_record_size + MAC_SIZE;
			crt_mac = crt_record + lbn_record_size;

			extern int cacheMissFlow;
			extern int cacheHitFlow;
			extern int DoCallTimes;

			// print round stats
			if (unlikely(pkt_count >= TEST_ITVL)) {
				ocall_get_time(&end_s, &end_ns);
				double elapsed_us =
				    (end_s - start_s) * 1000000.0 +
				    (end_ns - start_ns) / 1000.0;

				eprintf(
				    "Round %d - delay %f - tput %f, Miss Rate "
				    "%lf%%, #dfc:%d, flow_cache:%d, "
				    "flow_store:%d, mos_flow:%d\n",
				    ++round_idx, elapsed_us / pkt_count,
				    total_byte * 8.0 / elapsed_us,
				    (cacheMissFlow)*100.0 /
					(cacheHitFlow + cacheMissFlow),
				    DoCallTimes, cache_lkup_table.count,
				    store_lkup_table.count, mos_flow_cnt);
				pkt_count = 0;
				total_byte = 0;
				cacheMissFlow = 0;
				cacheHitFlow = 0;
				DoCallTimes = 0;
				ocall_get_time(&start_s, &start_ns);
			}
		}
	}

	// never executed
	return 0.0;
}
double ecall_etap_start_micro(rx_ring_t* handle, int lbn_record_size,
			      int lbn_record_per_batch) {
	return 0.0;
}

