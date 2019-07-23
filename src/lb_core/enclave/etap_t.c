#include "etap_t.h"

#include "crypto_t.h"
#include "state_mgmt_t.h"
#include "utils_t.h"
#include "lb_edge_t.h"

#include "../common/lb_config.h"

#include "sgx_thread.h"

#include <string.h>
#include <stdlib.h>

#define CROSS_RECORD

//#define NON_SWITCHING

#define LOCKLESS
#define CACHE_EFFICIENT

#define PKT_RINFBUF_CAP 256

#define CACHE_LINE 64
/* Variable definitions */
char cachePad0[CACHE_LINE] = { 0 };
/*shared control variables*/
volatile int read = 0;
volatile int write = 0;
char cachePad1[CACHE_LINE - 2 * sizeof(int)] = { 0 };
/*consumer local variables*/
int localWrite = 0;
int nextRead = 0;
int rBatch = 0;
char cachePad2[CACHE_LINE - 3 * sizeof(int)] = { 0 };
/*producer local variables*/
int localRead = 0;
int nextWrite = 0;
int wBatch = 0;
int try_before_sleep = 0;
char cachePad3[CACHE_LINE - 4 * sizeof(int)] = { 0 };
/*constants*/
const int batchSize = PKT_RINFBUF_CAP/4;
char cachePad4[CACHE_LINE - 1 * sizeof(int)] = { 0 };

//#define MAX_PKT_SIZE 2036 // to align sizeof(rbuf_pkt_t) with cache line
typedef struct rbuf_pkt {
	uint8_t pkt[MAX_FRAME_SIZE];
	time_t ts;
	int size;
} rbuf_pkt_t;

rbuf_pkt_t in_rbuf[PKT_RINFBUF_CAP];

#define NEXT(n) (n + 1) % PKT_RINFBUF_CAP

//int read_cnt = 0;
//int write_cnt = 0;
//int test_done = 0;
//volatile int pkt_idx = 0;
//volatile int this_pkt_idx = 0;

/* control the termination of etap */
//int etap_stopping = 0;
//sgx_thread_mutex_t stop_mutex = SGX_THREAD_MUTEX_INITIALIZER;

time_t time_now;
void get_clock(time_t * ts)
{
	if (time_now)
		*ts = time_now;
	else
		*ts = 0;
}

struct timeval
{
	__time_t tv_sec;		/* Seconds.  */
	__time_t tv_usec;	/* Microseconds.  */
};

struct timeval trace_clock = {0, 0};

#ifdef LOCKLESS
#ifdef CACHE_EFFICIENT
void read_pkt(uint8_t *pkt, int *size, time_t *ts)
{
	if (nextRead == localWrite) {
		while (nextRead == write)
			;
		localWrite = write;
	}
	memcpy(pkt, in_rbuf[nextRead].pkt, in_rbuf[nextRead].size);
	*size = in_rbuf[nextRead].size;
	*ts = in_rbuf[nextRead].ts;

	nextRead = NEXT(nextRead);
	++rBatch;
	if (rBatch > batchSize) {
		read = nextRead;
		rBatch = 0;
	}

	//eprintf("reader: read %d write %d size %d!\n", read, write, *size);
}



void write_pkt(const uint8_t *pkt, int pkt_size, time_t ts)
{
	int afterNextWrite = NEXT(nextWrite);
	if (afterNextWrite == localRead) {
		while (afterNextWrite == read) {
//#define SLEEP_TRY 10000000
//#define SLEEP_NS 1
//			if (++try_before_sleep == SLEEP_TRY) {
//				ocall_sleep(SLEEP_NS);
			//	try_before_sleep = 0;
			//}
			;
		}
		localRead = read;
	}

	memcpy(in_rbuf[nextWrite].pkt, pkt, pkt_size);
	in_rbuf[nextWrite].size = pkt_size;
	in_rbuf[nextWrite].ts = ts;

	time_now = ts;

	trace_clock.tv_sec = ts; // second only

	nextWrite = afterNextWrite;
	wBatch++;
	if (wBatch >= batchSize) {
		write = nextWrite;
		wBatch = 0;
	}

	//++write_cnt;
	//eprintf("writer: read %d write %d size %d!\n", read, write, pkt_size);
	/*eprintf("%d\n", pkt_size);
	if (write_cnt++ == 5)
		abort();*/
}

#else
void read_pkt(uint8_t *pkt, int *size, time_t *ts)
{
    // busy waiting
	while(read == write)
		;

    memcpy(pkt, &in_rbuf[read].pkt, in_rbuf[read].size);
	*size = in_rbuf[read].size;
	*ts = in_rbuf[read].ts;
    read = NEXT(read);

	//memcpy(&this_pkt_idx, pkt, 4);
	////eprintf("this %d\n", this_pkt_idx);
	//if (this_pkt_idx != pkt_idx) {
	//	eprintf("what? %d %d\n", this_pkt_idx, pkt_idx);
	//	abort();
	//}
	//++pkt_idx;
	//eprintf("reader: read %d write %d %d!\n", read, write, *size);
}

void write_pkt(const uint8_t *pkt, int pkt_size, time_t ts)
{
	//eprintf("writer: read %d write %d!\n", read, write);
    // busy waiting
	while(NEXT(write) == read)
		;

    memcpy(&in_rbuf[write].pkt, pkt, pkt_size);
	in_rbuf[write].size = pkt_size;
	in_rbuf[write].ts = ts;

	time_now = ts;

    write = NEXT(write);

	//eprintf("writer: read %d write %d %d!\n", read, write, pkt_size);
}
#endif
#else
sgx_thread_mutex_t rbuf_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_cond_t empty_cond = SGX_THREAD_COND_INITIALIZER;
sgx_thread_cond_t full_cond = SGX_THREAD_COND_INITIALIZER;
void read_pkt(uint8_t *pkt, int *size, time_t *ts)
{
#ifdef NON_SWITCHING
    while (sgx_thread_mutex_trylock(&rbuf_mutex) != 0)
        ;
#else
    sgx_thread_mutex_lock(&rbuf_mutex);
#endif

    // wait on empty
	if(read == write)
        sgx_thread_cond_wait(&empty_cond, &rbuf_mutex);

	memcpy(pkt, in_rbuf[read].pkt, in_rbuf[read].size);
	*size = in_rbuf[read].size;
	*ts = in_rbuf[read].ts;
	read = NEXT(read);

	//++read_cnt;
	//memcpy(&this_pkt_idx, pkt, 4);
	////eprintf("before %d %d\n", this_pkt_idx, pkt_idx);
	//if (this_pkt_idx != pkt_idx) {
	//	eprintf("what? %d %d\n", this_pkt_idx, pkt_idx);
	//	//eprintf("Reader: read %d write %d!\n", read, write);
	//	abort();
	//}
	//++pkt_idx;
	//eprintf("after %d %d %d\n", this_pkt_idx, pkt_idx, *size);

    sgx_thread_cond_signal(&full_cond);

    sgx_thread_mutex_unlock(&rbuf_mutex);
}

void write_pkt(const uint8_t *pkt, int pkt_size, time_t ts)
{
#ifdef NON_SWITCHING
    while (sgx_thread_mutex_trylock(&rbuf_mutex) != 0)
        ;
#else
    sgx_thread_mutex_lock(&rbuf_mutex);
#endif

    // wait on full
    if (NEXT(write) == read)
        sgx_thread_cond_wait(&full_cond, &rbuf_mutex);

	memcpy(in_rbuf[write].pkt, pkt, pkt_size);
	in_rbuf[write].size = pkt_size;
	in_rbuf[write].ts = ts;
	write = NEXT(write);

    sgx_thread_cond_signal(&empty_cond);

    sgx_thread_mutex_unlock(&rbuf_mutex);
}
#endif

/* test */
#include "cuckoo/cuckoo_hash.h"
extern struct cuckoo_hash cache_lkup_table;
extern struct cuckoo_hash store_lkup_table;
extern lb_state_stats_t lb_state_stats;
lb_state_stats_t last_state_stats = { 0,0,0 };
//#include "../common/lwids_type.h"
//extern exp_data_t *exp_stats;

//int sgx_deleted_flow = 0;
//int lb_deleted_flow = 0;

int mos_flow_cnt = 0;

void etap_set_flow(int crt_flow)
{
    mos_flow_cnt = crt_flow;
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

#if CAIDA == 1
double ecall_etap_start(int lbn_record_size, int lbn_record_per_batch)
{
	//eprintf("etapn started record %d rec_per_bat %d!\n", lbn_record_size, lbn_record_per_batch);
	/*etap_rx_queue.read = 0;
	etap_rx_queue.write = 0;*/

	/*write = 0;
	read = 0;*/
	//test_done = 0;

	//pkt_idx = 0;
	//this_pkt_idx = 0;

	/*shared control variables*/
	read = 0;
	write = 0;
	/*consumer’s local variables*/
	localWrite = 0;
	nextRead = 0;
	rBatch = 0;
	/*producer local variables*/
	localRead = 0;
	nextWrite = 0;
	wBatch = 0;

    static uint8_t dec_record[1024 * 16]; // 64KB
    
    // The pointers are from outside
    uint8_t *batch;
	//static uint64_t batch_ts = 0;

    // pending packet buffer
#ifdef CROSS_RECORD
	uint16_t pending_partial_size = 0;
#endif
	uint16_t pending_ts_pkt_size = 0; // read from sized packet stream
    static uint8_t pending_ts_pkt[2048] = { 0 };
	time_t pending_pkt_ts = 0;
    
    double total_byte = 0;
    long long start_s, start_ns, end_s, end_ns;

	// record tracking
	int rec_idx = 0;
	uint8_t *crt_record = 0;
	uint8_t *crt_mac = 0;
	// in-record tracking
	uint8_t *crt_pos = 0;
	
	static int pkt_count = 0;
	static int round_idx = 0;
    ocall_get_time(&start_s, &start_ns);
    while (1) {
		//ocall_lb_etap_in_memory(&batch);
		// fixed
		ocall_lb_etap_in(&batch);

		crt_record = batch;
		crt_mac = crt_record + lbn_record_size;

        // test done
        if (unlikely(batch == 0)) {
            ocall_get_time(&end_s, &end_ns);
            double elapsed_us = (end_s - start_s)*1000000.0 + (end_ns - start_ns) / 1000.0;

// #if LightBox==1
//             int cache_hit = lb_state_stats.cache_hit - last_state_stats.cache_hit;
//             int store_hit = lb_state_stats.store_hit - last_state_stats.store_hit;
//             int miss = last_state_stats.miss - last_state_stats.miss;
//             int total = cache_hit + store_hit + miss;
// 			eprintf("Round %d - pkt %d - delay %f - tput %f - flow %d - state %d %d %d %f\n", 
// 				++round_idx, pkt_count, elapsed_us/pkt_count, total_byte*8.0 / elapsed_us,mos_flow_cnt,
//                 cache_hit, store_hit, miss,
// 				1-cache_hit*1.0/total);
//             last_state_stats = lb_state_stats;
// #else
			eprintf("Round %d - pkt %d - delay %f - tput %f \
					\nflow %d dfc %d dfc effective %d dfc size %lld timeouted %d, \
					\nip %d, tcp %d, icmp %d, other %d, \
					\nerr_drop_1 %d, err_drop_2 %d, err_drop_3 %d, err_drop_4 %d\
					\nsum %d, client %d, server %d, all %d \n\n",
					++round_idx, pkt_count, elapsed_us / pkt_count, total_byte*8.0 / elapsed_us, 
					mos_flow_cnt, DoCallTimes, DoDfcTimes, DoDfcSize, cnt_timeouted,
					cnt_ip, cnt_tcp, cnt_icmp, cnt_other,
					err_drop_1, err_drop_2, err_drop_3, err_drop_4,
					cnt_tcp+cnt_icmp+cnt_other+err_drop_1+err_drop_2+err_drop_3+err_drop_4,
					client_new_stream, server_new_stream, client_new_stream+server_new_stream);
#if LightBox==1
            int cache_hit = lb_state_stats.cache_hit - last_state_stats.cache_hit;
            int store_hit = lb_state_stats.store_hit - last_state_stats.store_hit;
            int miss = last_state_stats.miss - last_state_stats.miss;
            int total = cache_hit + store_hit + miss;
			eprintf("Miss rate %f \n\n", 1-cache_hit*1.0/total);
			last_state_stats = lb_state_stats;
#endif
			pkt_count = 0;

			//etap_stopping = 1;

			return total_byte*8.0 / elapsed_us;
        }
        else {
			for (rec_idx = 0; rec_idx < lbn_record_per_batch; ++rec_idx) {
                /* decrypt and verify */
                if (!veri_dec(crt_record, lbn_record_size, dec_record, crt_mac)) {
                    eprintf("veri_dec() fail!\n");
                    abort();
                }
				
				//eprintf("rec %d\n", rec_idx);

				//eprintf("rec %d\n", rec_idx);
				//memcpy(dec_record, crt_record, lbn_record_size);
				crt_pos = dec_record;
                int free = lbn_record_size;
#ifdef CROSS_RECORD
                /* handle pending packet that is only partially received */
                if (pending_ts_pkt_size != 0) {
                    // partial_size could be 0, in which case only the "size" part was read
					int remaining = pending_ts_pkt_size - pending_partial_size;
                    memcpy(pending_ts_pkt + pending_partial_size, crt_pos, remaining);
                    crt_pos += remaining;
                    free -= remaining;
				
					// extract timestamp
					memcpy(&pending_pkt_ts, pending_ts_pkt,
						   sizeof(pending_pkt_ts));
					// write to etap ring
					write_pkt(pending_ts_pkt+sizeof(pending_pkt_ts), 
							  pending_ts_pkt_size-sizeof(pending_pkt_ts),
							  pending_pkt_ts);
                    total_byte += pending_ts_pkt_size;
					++pkt_count;
                }
#endif
                /* recover more packets from the record */
                while (1) {
                    if (free >= sizeof(pending_ts_pkt_size)) {
                        /* read size */
                        memcpy(&pending_ts_pkt_size, crt_pos, sizeof(pending_ts_pkt_size));
                        crt_pos += sizeof(pending_ts_pkt_size);
                        free -= sizeof(pending_ts_pkt_size);

						/*eprintf("%d %d %d\n", pending_ts_pkt_size, pending_partial_size, free);
						if (pending_ts_pkt_size > MAX_FRAME_SIZE || pending_ts_pkt_size < 0)
						{
							eprintf("eeerror %d\n", pending_ts_pkt_size);
							abort();
						}*/
                        /* write full packet to etap */
                        if (free >= pending_ts_pkt_size) {
							// extract timestamp
							memcpy(&pending_pkt_ts, crt_pos, sizeof(pending_pkt_ts));

							// write to etap ring
							write_pkt(crt_pos + sizeof(pending_pkt_ts),
									  pending_ts_pkt_size-sizeof(pending_pkt_ts), 
								      pending_pkt_ts);

							// legacy : ts bytes are counted
                            total_byte += pending_ts_pkt_size;
							++pkt_count;

							//eprintf("pkt %d : %d %d\n", 
							//	pkt_count, pending_ts_pkt_size - sizeof(pending_pkt_ts), free);
	
                            crt_pos += pending_ts_pkt_size;
                            free -= pending_ts_pkt_size;
                        }
                        /* buffer partial packet until next record */
                        else {
#ifdef CROSS_RECORD
                            pending_partial_size = free;
                            memcpy(pending_ts_pkt, crt_pos, pending_partial_size);
#endif
							// no need to update the tracking data
                            //crt_pos += pending_partial_size;
                            //free = 0;

                            break;
                        }
                    }
                    else {
                        /* unlikely - discard the left 0 or 1 byte */
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
#elif LIVE == 1
// this should be called only once
double ecall_etap_start(int lbn_record_size, int lbn_record_per_batch)
{
	eprintf("etapn started record %d rec_per_bat %d!\n", lbn_record_size, lbn_record_per_batch);
	/*etap_rx_queue.read = 0;
	etap_rx_queue.write = 0;*/

	/*write = 0;
	read = 0;*/
	//test_done = 0;

	//pkt_idx = 0;
	//this_pkt_idx = 0;

	/*shared control variables*/
	read = 0;
	write = 0;
	/*consumer’s local variables*/
	localWrite = 0;
	nextRead = 0;
	rBatch = 0;
	/*producer’s local variables*/
	localRead = 0;
	nextWrite = 0;
	wBatch = 0;

	static uint8_t dec_record[1024 * 16]; // 64KB

	// The pointers are from outside
	uint8_t *batch;

	// pending packet buffer
#ifdef CROSS_RECORD
	uint16_t pending_partial_size = 0;
#endif
	uint16_t pending_ts_pkt_size = 0; // read from sized packet stream
	static uint8_t pending_ts_pkt[2048] = { 0 };
	time_t pending_pkt_ts = 0;

	double total_byte = 0;
	long long  start_s, start_ns, end_s, end_ns;

	int pkt_count = 0;
	int round_idx = 0;
	ocall_get_time(&start_s, &start_ns);
	while (1) {
		//ocall_lb_etap_in_memory(&batch);
		// fixed
		ocall_lb_etap_in(&batch);

		uint8_t * crt_record = batch;
		uint8_t *crt_mac = crt_record + lbn_record_size;

		if (unlikely(batch == 0)) {
			eprintf("empty batch!\n");
			abort();
		}

		//eprintf("%s\n", batch);

		int rec_idx = 0;
		for (rec_idx = 0; rec_idx < lbn_record_per_batch; ++rec_idx) {
			/* decrypt and verify */
			if (!veri_dec(crt_record, lbn_record_size, dec_record, crt_mac)) {
				eprintf("veri_dec() fail, dec mac offset %d!\n", crt_mac- crt_record);
				abort();
			}

			//eprintf("rec %d\n", rec_idx);

			//memcpy(dec_record, crt_record, lbn_record_size);
			// in-record tracking
			uint8_t *crt_pos = dec_record;
			int free = lbn_record_size;
#ifdef CROSS_RECORD
			/* handle pending packet that is only partially received */
			if (pending_ts_pkt_size != 0) {
				// partial_size could be 0, in which case only the "size" part was read
				int remaining = pending_ts_pkt_size - pending_partial_size;
				memcpy(pending_ts_pkt + pending_partial_size, crt_pos, remaining);
				crt_pos += remaining;
				free -= remaining;

				// extract timestamp
				memcpy(&pending_pkt_ts, pending_ts_pkt,
					sizeof(pending_pkt_ts));
				// write to etap ring
				write_pkt(pending_ts_pkt + sizeof(pending_pkt_ts),
					pending_ts_pkt_size - sizeof(pending_pkt_ts),
					pending_pkt_ts);
				total_byte += pending_ts_pkt_size;
				++pkt_count;
			}
#endif
			/* recover more packets from the record */
			while (1) {
				if (free >= sizeof(pending_ts_pkt_size)) {
					/* read size */
					memcpy(&pending_ts_pkt_size, crt_pos, sizeof(pending_ts_pkt_size));
					crt_pos += sizeof(pending_ts_pkt_size);
					free -= sizeof(pending_ts_pkt_size);

					/*eprintf("%d %d %d\n", pending_ts_pkt_size, pending_partial_size, free);
					if (pending_ts_pkt_size > MAX_FRAME_SIZE || pending_ts_pkt_size < 0)
					{
					eprintf("eeerror %d\n", pending_ts_pkt_size);
					abort();
					}*/
					/* write full packet to etap */
					if (free >= pending_ts_pkt_size) {
						// extract timestamp
						memcpy(&pending_pkt_ts, crt_pos, sizeof(pending_pkt_ts));

						// write to etap ring
						write_pkt(crt_pos + sizeof(pending_pkt_ts),
							pending_ts_pkt_size - sizeof(pending_pkt_ts),
							pending_pkt_ts);

						// legacy : ts bytes are counted
						total_byte += pending_ts_pkt_size;
						++pkt_count;

						//eprintf("pkt %d : %d %d\n", 
						//	pkt_count, pending_ts_pkt_size - sizeof(pending_pkt_ts), free);

						crt_pos += pending_ts_pkt_size;
						free -= pending_ts_pkt_size;
					}
					/* buffer partial packet until next record */
					else {
#ifdef CROSS_RECORD
						pending_partial_size = free;
						memcpy(pending_ts_pkt, crt_pos, pending_partial_size);
#endif
						// no need to update the tracking data
						//crt_pos += pending_partial_size;
						//free = 0;

						break;
					}
				}
				else {
					/* unlikely - discard the left 0 or 1 byte */
#ifdef CROSS_RECORD
					pending_ts_pkt_size = 0;
#endif
					break;
				}
			}

			crt_record += lbn_record_size + MAC_SIZE;
			crt_mac = crt_record + lbn_record_size;

			extern int  cacheMissFlow;
			extern int  cacheHitFlow;
			extern int DoCallTimes;

			// print round stats
			if (unlikely(pkt_count >= TEST_ITVL)) {
				ocall_get_time(&end_s, &end_ns);
				double elapsed_us = (end_s - start_s)*1000000.0 + (end_ns - start_ns) / 1000.0;

					eprintf("Round %d - delay %f - tput %f, Miss Rate %lf%%, #dfc:%d, flow_cache:%d, flow_store:%d, mos_flow:%d\n",	++round_idx, elapsed_us / pkt_count, total_byte*8.0 / elapsed_us, (cacheMissFlow)*100.0 / (cacheHitFlow + cacheMissFlow), DoCallTimes, cache_lkup_table.count, store_lkup_table.count, mos_flow_cnt);
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
#elif MICRO == 1
#else
#endif
