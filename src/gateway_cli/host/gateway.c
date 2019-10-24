#include "../lightbox/lb_config.h"
#include "edge_u.h"
#include "sgx_urts.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define CROSS_RECORD

/* use a different enclave id for client */
extern sgx_enclave_id_t global_eid;

pcap_t* pcap_handle;

uint64_t get_microsecond_timestamp() {
		struct timeval current_time;
		gettimeofday(&current_time, NULL);
		return current_time.tv_sec * (int)1e6 + current_time.tv_usec ;
}

typedef struct rtt_checker {
	uint64_t current_time;
	uint64_t rtt;
} rtt_checker_t;

#if CAIDA == 1
//#define POOL_SIZE 700000000 // 2GB/3
#define POOL_SIZE 1000000000 // large enough for 1M packets
#else
#define POOL_SIZE 1024 * 1024 * 1024 * 2L // 2GB
#endif
//#define POOL_SIZE 1024*1024*512 // 256MB
uint8_t* raw_pool = 0;
uint8_t* crt_batch = 0;
int batch_size = 0;

int cli_fd;

void rand_byte(uint8_t* data, int length)
{
    int i;
    for (i = 0; i < length; ++i)
	data[i] = rand() % 256;
}

void send_crt_batch()
{
    int to_send = batch_size;
    while (to_send) {
	int ret = send(cli_fd, crt_batch + batch_size - to_send, to_send, 0);
	if (ret > 0) {
	    to_send -= ret;
	} else {
	    perror("send_batch");
	    exit(1);
	}
    }
}

#if MICRO == 1
int data_source_init(int rec_size, int rec_per_bat, int pkt_size)
{
    printf("MICRO!\n");

    batch_size = (rec_size + MAC_SIZE) * rec_per_bat;
    int max_num_batch = POOL_SIZE / batch_size;

    /*printf("Preparing pool for pkt_size %d record_size %d LBN_BATCH_SIZE %d...\n",
	pkt_size, record_size, LBN_BATCH_SIZE);*/
    if (!raw_pool)
	raw_pool = malloc(POOL_SIZE);
    else // only once for micro benchmark
	return 0;
    uint8_t* crt_pool_pos = raw_pool;

    // not static, so the last partial packet in last batch is discarded
    uint16_t sized_pkt_length = 0;
    uint8_t sized_pkt[2048];
    // track cross-record packet
    uint16_t sized_pkt_remain = 0;

    int pkt_idx = 0;
    int b_idx, r_idx;
    for (b_idx = 0; b_idx < max_num_batch; ++b_idx) {
	//printf("batch %d %d\n", num_batch, b_idx);
	for (r_idx = 0; r_idx < rec_per_bat; ++r_idx) {
	    /* Append record */
	    uint8_t* record = crt_pool_pos;
	    int record_free = rec_size;

	    // the remaining part of the pending sized_packet
	    if (sized_pkt_remain > 0) {
		//printf("old sized_pkt_length %d\n", sized_pkt_length);
		//exit(1);
		// a record is always larger than a packet, so no boundary checking
		memcpy(crt_pool_pos, sized_pkt + sized_pkt_length - sized_pkt_remain, sized_pkt_remain);
		crt_pool_pos += sized_pkt_remain;

		record_free -= sized_pkt_remain;
	    }

	    // new sized_packets
	    while (1) {
		static struct timeval ts = { 0, 0 }; // placeholder
		/* ++ts; */
		ts.tv_sec++;
		uint16_t pkt_ts_len = sizeof(ts) + pkt_size;
		sized_pkt_length = sizeof(pkt_ts_len) + pkt_ts_len;
		//printf("new sized_pkt_length %d\n", sized_pkt_length);
		// 1) add pkt and ts sizes
		memcpy(sized_pkt, &pkt_ts_len, sizeof(pkt_ts_len));
		// 2) pkt timestamp
		memcpy(sized_pkt + sizeof(pkt_ts_len), &ts, sizeof(ts));
		// 3) pkt itself
		rand_byte(sized_pkt + sizeof(pkt_ts_len) + sizeof(ts), pkt_size);

		/*if ((crt_pool_pos - record + record_free) != LBN_RECORD_SIZE)
				printf("aaa %d\n", crt_pool_pos - record + record_free - LBN_RECORD_SIZE);*/
		if (record_free > sized_pkt_length) {
		    // append to record
		    memcpy(crt_pool_pos, sized_pkt, sized_pkt_length);
		    crt_pool_pos += sized_pkt_length;

		    record_free -= sized_pkt_length;
		} else {
		    if (record_free >= sizeof(sized_pkt_length)) {
			// this could be 0
			sized_pkt_remain = sized_pkt_length - record_free;
			memcpy(crt_pool_pos, sized_pkt, record_free);
			crt_pool_pos += record_free;
			record_free = 0;
			//if ((crt_pool_pos - record + record_free) != LBN_RECORD_SIZE)
			//	printf("ccc %d\n", crt_pool_pos - record + record_free - LBN_RECORD_SIZE);
		    } else {
			/* disgard the poor 0 or 1 byte left */
			/* by doing so the current sized_packet is also discarded */
			sized_pkt_remain = 0;
			crt_pool_pos += record_free;
		    }
		    break;
		}
	    }

	    if ((record + rec_size) != crt_pool_pos) {
		printf("Fail to prepare record %d! %p %p %ld\n",
		    r_idx,
		    record + rec_size, crt_pool_pos,
		    record + rec_size - crt_pool_pos);
	    }

	    /* Append record MAC */
	    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	    int enc_rlt = 0;
	    ret = ecall_auth_enc(global_eid, &enc_rlt,
		record, rec_size, record,
		crt_pool_pos);
	    if (ret != SGX_SUCCESS || enc_rlt != 1) {
		printf("[*] ecall_auth_enc fails with error %x\n", ret);
		free(raw_pool);
		//free(mac_pool);
		exit(1);
	    }
	    crt_pool_pos += MAC_SIZE;
	}
    }

    //printf("prepared %d batch size %dB\n", pkt_idx, LBN_BATCH_SIZE);
    /*printf(" Pool prepared ---> ");
	fflush(stdout);*/

    return max_num_batch;
}
void data_source_deinit()
{
    free(raw_pool);
}
int data_source_send(int batch_to_send)
{
    /* test termination control trick */
    if (batch_to_send == 0) {
	int end;
	memcpy(&end, "end", sizeof(int));
	send_conf_to_peer(end);

	printf("All done!\n");
	return 1;
    } else {
	/* tell peer how many batches to send in this round for precise timing */
	send_conf_to_peer(batch_to_send);

	/* send test data */
	int i = 0;
	for (; i < batch_to_send; ++i) {
	    crt_batch = raw_pool + i * batch_size;
	    send_crt_batch();
	}
	sleep(1);
	return 0;
    }
}
#elif CAIDA == 1
int data_source_init(int rec_size, int rec_per_bat, int pkt_size)
{
    //printf("CAIDA!\n");

    batch_size = (rec_size + MAC_SIZE) * rec_per_bat;
    //int max_num_batch = POOL_SIZE / batch_size;

    static int pkt_cnt = 0;
    const char trace[] = "/home/conggroup/trace/CAIDA_100M.pcap";
    if (!pcap_handle) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_handle = pcap_open_offline(trace, errbuf);
	if (pcap_handle == NULL) {
	    printf("[!] Error pcap_open_*: %s \n", errbuf);
	    exit(1);
	}
	printf("Pcap file %s opened!\n", trace);
    }
    struct pcap_pkthdr pheader;
    const uint8_t* pkt;

    if (!raw_pool)
	raw_pool = malloc(POOL_SIZE);

    uint8_t* crt_pool_pos = raw_pool;

    // not static, so the last partial packet in last batch is discarded
    uint16_t sized_pkt_length = 0;
    uint8_t sized_pkt[2048];
    // track cross-record packet
#ifdef CROSS_RECORD
    uint16_t sized_pkt_remain = 0;
#endif
    int pkt_idx = 0;
    int b_idx = 0, r_idx;
    //for (b_idx = 0; b_idx < max_num_batch; ++b_idx) {
    //printf("batch %d %d\n", num_batch, b_idx);
    static int correction_rounds = 0, correction_pkt_num = 999800;
    // if(correction_rounds++ == 5) {
    // 	correction_rounds = 0;
    // 	correction_pkt_num = 999000;
    // }
    while (pkt_idx < correction_pkt_num) {
	// correction_pkt_num = 1000000;

	for (r_idx = 0; r_idx < rec_per_bat; ++r_idx) {
	    /* Append record */
	    uint8_t* record = crt_pool_pos;
	    int record_free = rec_size;

#ifdef CROSS_RECORD
	    // the remaining part of the pending sized_packet
	    if (sized_pkt_remain > 0) {
		//printf("old sized_pkt_length %d\n", sized_pkt_length);
		//exit(1);
		// a record is always larger than a packet, so no boundary checking
		memcpy(crt_pool_pos, sized_pkt + sized_pkt_length - sized_pkt_remain, sized_pkt_remain);
		crt_pool_pos += sized_pkt_remain;

		record_free -= sized_pkt_remain;
	    }
#endif

	    // new sized_packets
	    while (1) {
		pkt = pcap_next(pcap_handle, &pheader);

		// 0) insert eth_header
		static char new_pkt_buffer[4096];

		//printf("11 pkt cnt %d\n", pkt_cnt);
		if (!pkt) {
		    printf("pkt cnt %d\n", pkt_cnt);
		    // current partial batch is discarded
		    // if b_idx == 0, the test is done
		    return b_idx;
		}

		++pkt_idx;
		++pkt_cnt;

		/* time_t ts = pheader.ts.tv_sec; */
		struct timeval ts;
		memcpy(&ts, &(pheader.ts), sizeof(ts));
		uint16_t pkt_ts_len = sizeof(ts) + pheader.caplen;
		sized_pkt_length = sizeof(pkt_ts_len) + pkt_ts_len;
		//printf("new sized_pkt_length %d\n", sized_pkt_length);
		// 1) add pkt and ts sizes
		memcpy(sized_pkt, &pkt_ts_len, sizeof(pkt_ts_len));
		// 2) pkt timestamp
		memcpy(sized_pkt + sizeof(pkt_ts_len), &ts, sizeof(ts));
		// 3) pkt itself
		memcpy(sized_pkt + sizeof(pkt_ts_len) + sizeof(ts), pkt, pheader.caplen);

		/*if ((crt_pool_pos - record + record_free) != LBN_RECORD_SIZE)
				printf("aaa %d\n", crt_pool_pos - record + record_free - LBN_RECORD_SIZE);*/
#ifdef CROSS_RECORD
		if (record_free > sized_pkt_length) {
#else
		if (record_free >= sized_pkt_length) {
#endif
		    // append to record
		    memcpy(crt_pool_pos, sized_pkt, sized_pkt_length);
		    crt_pool_pos += sized_pkt_length;

		    record_free -= sized_pkt_length;
		} else {
		    if (record_free >= sizeof(sized_pkt_length)) {
			// sized_pkt_remain could be 0
#ifdef CROSS_RECORD
			sized_pkt_remain = sized_pkt_length - record_free;
			memcpy(crt_pool_pos, sized_pkt, record_free);
			crt_pool_pos += record_free;
			record_free = 0;
#else
			// only keep the record size to recognize space insufficiency
						memcpy(crt_pool_pos, &rand_pkt_size, sizeof(sized_pkt_length);
						crt_pool_pos += record_free;
#endif
			//if ((crt_pool_pos - record + record_free) != LBN_RECORD_SIZE)
			//	printf("ccc %d\n", crt_pool_pos - record + record_free - LBN_RECORD_SIZE);
		    } else {
			/* disgard the poor 0 or 1 byte left */
			/* by doing so the current sized_packet is also discarded */
#ifdef CROSS_RECORD
			sized_pkt_remain = 0;
#endif
			crt_pool_pos += record_free;
		    }
		    break;
		}
	    }
	    if ((record + rec_size) != crt_pool_pos) {
		printf("Fail to prepare record %d! %p %p %d\n",
		    r_idx,
		    record + rec_size, crt_pool_pos,
		    record + rec_size - crt_pool_pos);
	    }

	    /* Append record MAC */
	    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	    int enc_rlt = 0;
	    ret = ecall_auth_enc(global_eid, &enc_rlt,
		record, rec_size, record,
		crt_pool_pos);
	    if (ret != SGX_SUCCESS || enc_rlt != 1) {
		printf("[*] ecall_auth_enc fails with error %x\n", ret);
		free(raw_pool);
		//free(mac_pool);
		exit(1);
	    }
	    crt_pool_pos += MAC_SIZE;
	}

	b_idx++;
    }

    //printf("prepared %d batch size %dB\n", pkt_idx, LBN_BATCH_SIZE);
    /*printf(" Pool prepared ---> ");
	fflush(stdout);*/
    printf("pkt cnt %d\n", pkt_cnt);
    return b_idx;
}
void data_source_deinit()
{
    // do NOT free raw_pool
}
int data_source_send(int batch_to_send)
{
    /* test termination control trick */
    if (batch_to_send == 0) {
	int end;
	memcpy(&end, "end", sizeof(int));
	send_conf_to_peer(end);

	printf("All done!\n");
	return 1;
    } else {
	/* tell peer how many batches to send in this round for precise timing */
	send_conf_to_peer(batch_to_send);

	/* send test data */
	int i = 0;
	for (; i < batch_to_send; ++i) {
	    crt_batch = raw_pool + i * batch_size;
	    send_crt_batch();
	}
	sleep(1);
	return 0;
    }
}
#elif LIVE == 1
int record_size = 0;
int rec_per_bat = 0;
int data_source_init(int _rec_size, int _rec_per_bat, int pkt_size)
{
    printf("LIVE!\n");

    record_size = _rec_size;
    rec_per_bat = _rec_per_bat;
    batch_size = (record_size + MAC_SIZE) * rec_per_bat;
    //int max_num_batch = POOL_SIZE / batch_size;

    /* Prepare pcap */
    if (!pcap_handle) {
	//const char iter[] = "eth0";
	const char iter[] = "eth0";
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_handle = pcap_open_live(iter, MAX_FRAME_SIZE, 0, 500, errbuf);
	if (pcap_handle == NULL) {
	    printf("[!] Error pcap_open_*: %s \n", errbuf);
	    exit(1);
	}
	struct bpf_program cfilter;
	const char bpff[] = "tcp dst port 12345";
	if ((pcap_compile(pcap_handle, &cfilter, bpff, 1, 0)) == -1) {
	    printf("[*] Error pcap_compile user_filter: %s\n", pcap_geterr(pcap_handle));
	    exit(1);
	}

	if (pcap_setfilter(pcap_handle, &cfilter)) {
	    printf("[*] Unable to set pcap filter!  %s", pcap_geterr(pcap_handle));
	}
	pcap_freecode(&cfilter);

	printf("Sniffing on interface %s!\n", iter);
    }

    if (!crt_batch) {
	crt_batch = malloc(batch_size);
	if (!crt_batch) {
	    printf("Fail to allocate memory for crt_batch!\n");
	    exit(1);
	}
    }

    return -1;
}
void data_source_deinit()
{
}
void prepare_crt_batch()
{
    static int pkt_cnt = 0;
    struct pcap_pkthdr pheader;
    const uint8_t* pkt;

    static uint16_t sized_pkt_length = 0;
    static uint8_t sized_pkt[2048];
    // track cross-record packet
#ifdef CROSS_RECORD
    static uint16_t sized_pkt_remain = 0;
#endif
    int pkt_idx = 0;
    int r_idx;
    uint8_t* crt_batch_pos = crt_batch;

    for (r_idx = 0; r_idx < rec_per_bat; ++r_idx) {
	//printf("rec %d %ld\n", r_idx, crt_batch_pos-crt_batch);
	/* Append record */
	uint8_t* record = crt_batch_pos;
	int record_free = record_size;

#ifdef CROSS_RECORD
	// the remaining part of the pending sized_packet
	if (sized_pkt_remain > 0) {
	    //printf("old sized_pkt_length %d\n", sized_pkt_length);
	    //exit(1);
	    // a record is always larger than a packet, so no boundary checking
	    memcpy(crt_batch_pos, sized_pkt + sized_pkt_length - sized_pkt_remain, sized_pkt_remain);
	    crt_batch_pos += sized_pkt_remain;

	    record_free -= sized_pkt_remain;
	}
#endif

	// new sized_packets
	while (1) {
	    pkt = pcap_next(pcap_handle, &pheader);
	    if (!pkt) {
		//printf("pcap_next fail in live traffic!\n");
		continue;
	    } else {
		static unsigned long long pktCount = 0;
		static unsigned long long pktSize = 0;
		pktSize += pheader.caplen + 24;
		pktCount += 1;

		int now = time(0);
		static int printTime = 0;
		if (!printTime) {
		    printTime = now;
		}

		if (printTime != now) {
		    printf("mOs pcap_next throuthput is %lf Mbps/s. #pkt:%lld.\n", pktSize * 8.0 / 1000 / 1000, pktCount);

		    pktSize = pktCount = 0;
		    printTime = now;
		}
	    }

	    ++pkt_cnt;

	    /* time_t ts = pheader.ts.tv_sec; */
	    struct timeval ts;
	    memcpy(&ts, &(pheader.ts), sizeof(ts));
	    uint16_t pkt_ts_len = sizeof(ts) + pheader.caplen;
	    sized_pkt_length = sizeof(pkt_ts_len) + pkt_ts_len;
	    //printf("new sized_pkt_length %d\n", sized_pkt_length);
	    // 1) add pkt and ts sizes
	    memcpy(sized_pkt, &pkt_ts_len, sizeof(pkt_ts_len));
	    // 2) pkt timestamp
	    memcpy(sized_pkt + sizeof(pkt_ts_len), &ts, sizeof(ts));
	    // 3) pkt itself
	    memcpy(sized_pkt + sizeof(pkt_ts_len) + sizeof(ts), pkt, pheader.caplen);

	    /*if ((crt_pool_pos - record + record_free) != LBN_RECORD_SIZE)
			printf("aaa %d\n", crt_pool_pos - record + record_free - LBN_RECORD_SIZE);*/
#ifdef CROSS_RECORD
	    if (record_free > sized_pkt_length) {
#else
	    if (record_free >= sized_pkt_length) {
#endif
		// append to record
		memcpy(crt_batch_pos, sized_pkt, sized_pkt_length);
		crt_batch_pos += sized_pkt_length;

		record_free -= sized_pkt_length;
	    } else {
		if (record_free >= sizeof(sized_pkt_length)) {
		    // sized_pkt_remain could be 0
#ifdef CROSS_RECORD
		    sized_pkt_remain = sized_pkt_length - record_free;
		    memcpy(crt_batch_pos, sized_pkt, record_free);
		    crt_batch_pos += record_free;
		    record_free = 0;
#else
		    // only keep the record size to recognize space insufficiency
					memcpy(crt_pool_pos, &rand_pkt_size, sizeof(sized_pkt_length);
					crt_pool_pos += record_free;
#endif
		    //if ((crt_pool_pos - record + record_free) != LBN_RECORD_SIZE)
		    //	printf("ccc %d\n", crt_pool_pos - record + record_free - LBN_RECORD_SIZE);
		} else {
		    /* disgard the poor 0 or 1 byte left */
		    /* by doing so the current sized_packet is also discarded */
#ifdef CROSS_RECORD
		    sized_pkt_remain = 0;
#endif
		    crt_batch_pos += record_free;
		}
		break;
	    }
	}
	if ((record + record_size) != crt_batch_pos) {
	    printf("Fail to prepare record %d! %p %p %d\n",
		r_idx,
		record + record_size, crt_batch_pos,
		record + record_size - crt_batch_pos);
	}

	/* Append record MAC */
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int enc_rlt = 0;
	ret = ecall_auth_enc(global_eid, &enc_rlt,
	    record, record_size, record,
	    crt_batch_pos);
	if (ret != SGX_SUCCESS || enc_rlt != 1) {
	    printf("[*] ecall_auth_enc fails with error %x\n", ret);
	    free(raw_pool);
	    //free(mac_pool);
	    exit(1);
	} else {
	    //printf("auth_enc_succeed, mac offset is %d\n", crt_batch_pos - record);
	}
	crt_batch_pos += MAC_SIZE;
    }

    if ((crt_batch + batch_size) != crt_batch_pos) {
	printf("batch preparation error : %p %p %ld\n",
	    (crt_batch + batch_size), crt_batch_pos, crt_batch_pos - (crt_batch + batch_size));
	exit(1);
    }

    //printf("%s\n", crt_batch);
}
void send_conf_to_peer(int conf);
int data_source_send(int batch_to_send)
{
    // let's rock it!
    send_conf_to_peer(batch_to_send);

    while (1) {
	prepare_crt_batch();
	send_crt_batch();
    }
    // TODO : never executed
    return 1;
}
#else
/* stubs */
void data_source_init()
{
}
void data_source_deinit()
{
}
#endif

void send_conf_to_peer(int conf)
{
    int ret = send(cli_fd, &conf, sizeof(conf), 0);
    if (ret != sizeof(conf)) {
	printf("%s : no excuse for failing to sending such small piece of data!\n", __func__);
	exit(1);
    }
}

void* get_in_addr(struct sockaddr* sa)
{
    if (sa->sa_family == AF_INET) {
	return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void gateway_init(int rec_size, int rec_per_bat)
{
    /* Sample code modified from
	Beej's guide http://beej.us/guide/bgnet/html/single/bgnet.html
	*/

    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(SERV_ADDR, SERV_PORT, &hints, &servinfo)) != 0) {
	fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
	return;
    }

    // loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
	if ((cli_fd = socket(p->ai_family, p->ai_socktype,
		 p->ai_protocol))
	    == -1) {
	    perror("client: socket");
	    continue;
	}

	if (connect(cli_fd, p->ai_addr, p->ai_addrlen) == -1) {
	    close(cli_fd);
	    perror("client: connect");
	    continue;
	}

	break;
    }

    if (p == NULL) {
	fprintf(stderr, "client: failed to connect\n");
	exit(1);
	return;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr),
	s, sizeof s);
    printf("client: connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure

    /* send configurations to peer */
    printf("record_size %d\n", rec_size);
    printf("record_per_batch %d\n", rec_per_bat);

    send_conf_to_peer(rec_size);
    send_conf_to_peer(rec_per_bat);
}

void gateway_deinit()
{
    if (close(cli_fd) != 0)
	perror("gateway");
    else
	printf("gateway closed!\n");
}

void gateway(int rec_size, int rec_per_bat, int pkt_size)
{
    gateway_init(rec_size, rec_per_bat);

	static uint64_t rtt_flag_1 = 0xFFFFFFFFFFFFFFFF; // current timestamp in microsecond
	static uint64_t rtt_flag_2 = 0xFFFFFFFFFFFFFFFE; // rtt value
	rtt_checker_t rtt_checker;
	rtt_checker.current_time = get_microsecond_timestamp();
	rtt_checker.rtt = 0;
	uint8_t *buffer;
	static uint8_t rtt_size = sizeof(rtt_flag_1);
	buffer = malloc(rtt_size);
	//memcpy(buffer, &rtt_flag, sizeof(rtt_flag));
	static uint8_t dummy_rtt_buffer[100];

    while (1) {

			if(unlikely(get_microsecond_timestamp() - rtt_checker.current_time >= 1e6)) {
				// start calculating new rtt value
				rtt_checker.current_time = get_microsecond_timestamp();
				memcpy(buffer, &rtt_flag_1, sizeof(rtt_flag_1));
				int expect = rtt_size;
				while (expect) {
					expect -= send(cli_fd, buffer + rtt_size - expect, expect, 0);
				}

				recv(cli_fd, dummy_rtt_buffer, sizeof(uint64_t), 0);
				int tmp_current_time = get_microsecond_timestamp();
				rtt_checker.rtt = tmp_current_time - rtt_checker.current_time;
				rtt_checker.current_time = tmp_current_time;


				/* memcpy(buffer, &rtt_flag_2, sizeof(rtt_flag_2)); */
				memcpy(buffer, &rtt_checker.rtt, sizeof(rtt_checker.rtt));
				expect = rtt_size;
				while (expect) {
					expect -= send(cli_fd, buffer + rtt_size - expect, expect, 0);
				}

			} else {
					// send rtt_flag_2
					memcpy(buffer, &rtt_flag_2, sizeof(rtt_flag_2));
					int expect = rtt_size;
					while (expect) {
							expect -= send(cli_fd, buffer + rtt_size - expect, expect, 0);
					}
			}


	int batch_to_send = data_source_init(rec_size, rec_per_bat, pkt_size);

	int done = data_source_send(batch_to_send);

	if (done) {
	    data_source_deinit();
	    break;
	}
    }

    gateway_deinit();
}
