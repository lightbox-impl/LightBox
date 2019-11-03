#include "pattern_matching.h"
#include "../common/lwids_type.h"

#include <enclave/lb_edge_t.h>
#include <lb_type.h>
#include <enclave/include/utils_t.h>
#include <enclave/include/etap_t.h>
#include <enclave/include/state_mgmt_t.h>
#include <networking/libntoh/include/libntoh.h>
#include <linux_type_ports.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif

/* G L O B A L */
lwids_param_t *lwids_args;
pcre_t pcre_engine;
struct timeval wall_clock;
exp_data_t *exp_stats;

void print_exp_data(exp_data_t* pdata);

#define RECV_CLIENT	1
#define RECV_SERVER	2

/* capture handle */
pntoh_tcp_session_t		tcp_session = 0;
//pntoh_ipv4_session_t	ipv4_session = 0;
unsigned short		receive = 0;

/**
 * @brief Exit function (closes the capture handle and releases all resource from libntoh)
 */
void shandler(int sign)
{
	print_exp_data(exp_stats);

    // too slow in enclave
	//ntoh_exit();

	eprintf("\n\n[+] Capture finished!\n");
}

/**
 * @brief Returns a struct which stores some peer information
 */
ppeer_info_t get_peer_info(pntoh_tcp_stream_t pstream, unsigned char *payload, size_t payload_len, pntoh_tcp_tuple5_t tuple)
{
	ppeer_info_t ret = 0;
	size_t len = 0;
	char path[1024] = { 0 };

	exp_stats->payload_total_size += payload_len;

	if (payload_len == 0)
	{
		exp_stats->empty_package += 1;
		return ret;
	}

	if (payload_len > 4096)
	{
		exp_stats->huge_package += 1;
		return ret;
	}

	/* gets peer information */
	ret = (ppeer_info_t)calloc(1, sizeof(peer_info_t));
	ret->data_len = payload_len;
	ret->data = (unsigned char*)calloc(ret->data_len, sizeof(unsigned char));
	memcpy(ret->data, payload, ret->data_len);    

	//snprintf(path, sizeof(path), "%s:%d-", inet_ntoa(*(struct in_addr*)&(tuple->source)), ntohs(tuple->sport));
	//len = strlen(path);
	//snprintf(&path[len], sizeof(path) - len, "%s:%d", inet_ntoa(*(struct in_addr*)&(tuple->destination)), ntohs(tuple->dport));

	//ret->path = strndup(path, sizeof(path));

	return ret;
}

/**
 * @brief Frees the ppeer_info_t struct
 */
void free_peer_info(ppeer_info_t pinfo)
{
	/* free peer info data */
	if (!pinfo)
		return;

	free(pinfo->data);
	//free(pinfo->path);
	free(pinfo);

	return;
}

/**
 * @brief Returns the name of a protocol
 */
inline char *get_proto_description(unsigned short proto)
{
	switch (proto)
	{
	case IPPROTO_ICMP:
		return "ICMP";

	case IPPROTO_TCP:
		return "TCP";

	case IPPROTO_UDP:
		return "UDP";

	case IPPROTO_IGMP:
		return "IGMP";

	case IPPROTO_IPV6:
		return "IPv6";

	//case IPPROTO_FRAGMENT:
	//	return "IPv6 Fragment";

	default:
		return "Undefined";
	}
}


 /**
  * @brief Send a TCP segment to libntoh
  */
void send_tcp_segment(struct ip *iphdr, pntoh_tcp_callback_t callback)
{
	ppeer_info_t		pinfo;
	ntoh_tcp_tuple5_t	tcpt5;
	pntoh_tcp_stream_t	stream;
	struct tcphdr 		*tcp;
	size_t 			size_ip;
	size_t			total_len;
	size_t			size_tcp;
	size_t			size_payload;
	unsigned char		*payload;
	int			ret;
	unsigned int		error;

	size_ip = iphdr->ip_hl * 4;
	total_len = ntohs(iphdr->ip_len);

	if (total_len >= 2000)
	{
		//printf("error total_len size %d\n", total_len);
		exp_stats->drop_package += 1;
		return;
	}
		

	tcp = (struct tcphdr*)((unsigned char*)iphdr + size_ip);
	if ((size_tcp = tcp->th_off * 4) < sizeof(struct tcphdr))
		return;

	payload = (unsigned char *)iphdr + size_ip + size_tcp;
	size_payload = total_len - (size_ip + size_tcp);



	if (size_payload >= 2000 || size_payload<0)
	{
		//printf("error size_payload size %d\n", size_payload);
		exp_stats->drop_package += 1;
		return;
	}

	ntoh_tcp_get_tuple5((void*)iphdr, tcp, &tcpt5);

	/*if (aim_port)
	{
		if (ntohs(tcpt5.sport) == aim_port)
		{
			exp_stats->drop_by_port_filter += 1;
			return;
		}
	}*/

	exp_stats->package_total_size += total_len;

#if LightBox==0
	/* find the stream or creates a new one */
	if (!(stream = ntoh_tcp_find_stream(tcp_session, &tcpt5)))
	{
		//printf("new stream\n");
		stream = (pntoh_tcp_stream_t)calloc(1, sizeof(ntoh_tcp_stream_t));
		exp_stats->total_stream += 1;
		exp_stats->current_stream += 1;
		if (!(stream = ntoh_tcp_new_stream(stream, tcp_session, &tcpt5, callback, 0, &error, 1, 0)))
		{
			if (error != 5)
				eprintf("[e] Error %d creating new stream: %s\n", error, ntoh_get_errdesc(error));
			exp_stats->current_stream -= 1;
			free(stream);
			return;
		}
	}
	else
	{
		//printf("\nfind stream from%d,to%d\n",tcpt5.sport,tcpt5.dport);
	}
#else
    fid_t *fid = lb_get_fid(iphdr, tcp);
    state_entry_t *state_entry;
    flow_tracking_status rlt = flow_tracking(fid, &state_entry, wall_clock.tv_sec, 0);
    stream = (pntoh_tcp_stream_t)&state_entry->state;
    switch (rlt) {
    // new flow
    case ft_miss:
        exp_stats->total_stream += 1;
        exp_stats->current_stream += 1;
        memset(stream, 0, sizeof(*stream));
        if (!(stream = ntoh_tcp_new_stream(stream, tcp_session, &tcpt5, callback, 0, &error, 1, 0)))
        {
            if (error != 5)
                eprintf("[e] Error %d creating new stream: %s\n", error, ntoh_get_errdesc(error));
            exp_stats->current_stream -= 1;
            //free(stream);
            return;
        }
        break;
    case ft_cache_hit:
        break;
    case ft_store_hit:
        break;
    default:
        eprintf("flow_tracking error %d\n", rlt);
        abort();
    }
#endif

    //static int cc = 0;
    //if (cc++ <= 10) {
    //    eprintf("%u %u %u %u %u\n",
    //        iphdr->ip_src.s_addr, iphdr->ip_dst.s_addr,
    //        tcp->th_sport, tcp->th_dport, iphdr->ip_v);
    //}
    //else {
    //    abort();
    //}

	pinfo = get_peer_info(stream, payload, size_payload, &tcpt5);

	/* add this segment to the stream */
	ret = ntoh_tcp_add_segment(tcp_session, stream, (void*)iphdr, total_len, (void*)pinfo);
	if (ret < 0 && ret != NTOH_SYNCHRONIZING)
	{
		eprintf("[e] Error %d adding segment: %s\n", ret, ntoh_get_retval_desc(ret));
	}
	free_peer_info(pinfo);

	return;
}

// time stamp of this program to compute throughput
struct timeval t_start, t_end;
// time stamp in package to deside to check timeout
struct timeval t_timeout_start, t_timeout_end;

//rt.
unsigned long last_package_count;
unsigned long last_package_size;

// print current exp_data to std out
void print_exp_data(exp_data_t* pdata)
{
	unsigned long pass_ms;

#define BYTES_TO_MB (1024*1024)

	pdata->package_total_size_in_mb += pdata->package_total_size / BYTES_TO_MB;
	pdata->package_total_size %= BYTES_TO_MB;
	pdata->payload_total_size_in_mb += pdata->payload_total_size / BYTES_TO_MB;
	pdata->payload_total_size %= BYTES_TO_MB;
	pdata->pm_total_size_in_mb += pdata->pm_total_size / BYTES_TO_MB;
	pdata->pm_total_size %= BYTES_TO_MB;

	eprintf("\n");
	eprintf("Pattern Matching count is %lu, ret sum is %lu\n", pdata->pm_count, pdata->pm_ret_sum);
	eprintf("  buffer full %lu, segment full %lu, fin&ret %lu, timeout %lu\n", pdata->pm_buffer_overflow, pdata->pm_segment_count_overflow, pdata->pm_in_fin, pdata->pm_time_out);
	eprintf("Total flow is %lu, current flow is %lu\n", pdata->total_stream, pdata->current_stream);
	eprintf("  package count is %lu, drop is %lu, empty is %lu, huge is %lu\n", pdata->recv_package, pdata->drop_package, pdata->empty_package, pdata->huge_package);
	//if (aim_port)
	//	printf("\n  package port filter is %d, drop package %lu", aim_port, pdata->drop_by_port_filter);
	eprintf("  package size is %lu MB, data size is %lu MB, pm size is %lu MB\n", pdata->package_total_size_in_mb, pdata->payload_total_size_in_mb, pdata->pm_total_size_in_mb);

	pdata->package_time = t_timeout_end.tv_sec;
	if (t_start.tv_sec != 0)
	{
		pass_ms = (t_end.tv_sec - t_start.tv_sec) * 1000 + (t_end.tv_usec - t_start.tv_usec) / 1000;
		pdata->time_gap = pass_ms;
		pdata->throuthput = (unsigned long)((pdata->payload_total_size_in_mb - last_package_size + .0) * 8 / (pass_ms / 1000.0));
		
		eprintf("Pass %lu ms\n", pass_ms);
		eprintf("   throughput package %lu /s, package size %lf Mbits/s\n",
			(unsigned long)((pdata->recv_package - last_package_count + .0) / (pass_ms / 1000.0)),
			(pdata->payload_total_size_in_mb - last_package_size + .0) * 8 / (pass_ms / 1000.0));
	}
	eprintf("\n");

	last_package_count = pdata->recv_package;
	last_package_size = pdata->payload_total_size_in_mb;

	//t_start = t_end;
}

/* TCP Callback */
// ntoh call this func to run pattern matching
void tcp_callback(pntoh_tcp_stream_t stream, pntoh_tcp_peer_t orig, pntoh_tcp_peer_t dest, pntoh_tcp_segment_t seg, int reason, int extra)
{
	exp_stats->pm_count += 1;

	ppeer_info_t info = (ppeer_info_t)seg->user_data;



	if (info->data_len != 0)
	{
		exp_stats->pm_total_size += info->data_len;
		int rc = pcre_process(&pcre_engine, info->data, info->data_len);
	}

	return;
}

void ecall_lwids_init(void *param, void *exp_data)
{
    eprintf("Initializing lwIDS enclave counterpart ... \n");
    lwids_args = param;
    exp_stats = exp_data;

    pcre_engine.pattern_count = lwids_args->pattern_count;
    pcre_init(&pcre_engine, TEST_REGEX);

    ntoh_init();
    
    unsigned int error;
    if (!(tcp_session = ntoh_tcp_new_session(0, 0, &error)))
    {
        eprintf("[e] Error %d creating TCP session: %s\n", error, ntoh_get_errdesc(error));
        abort();
    }

    //eprintf("[i] Max. TCP streams allowed: %d\n", ntoh_tcp_get_size(tcp_session));

#if LightBox==1
    init_state_mgmt();

    eprintf("state_entry_t %d flow_state_t %d connection %d\n",
        sizeof(state_entry_t), sizeof(flow_state_t), sizeof(ntoh_tcp_stream_t));
#endif
}

void ecall_lwids_deinit()
{
    shandler(0);
}

void ecall_lb_lwids_run()
{

	poll_driver_t *pd = poll_driver_init();
    eprintf("LightBox %d CONNECTION %d CAIDA %d\n", LightBox, CONNECTION, CAIDA);

    uint8_t pkt[MAX_FRAME_SIZE];
    int pkt_len;
    wall_clock.tv_usec = 0;

    time_t last_checking_time = 0;

    struct ip	*ip;
    while (1) {
        pd->read_pkt(pkt, &pkt_len, &wall_clock, pd->etap);

#if CAIDA==1
        ip = (struct ip*)pkt;
#else
        ip = (struct ip*) (pkt + sizeof(struct ether_header));
#endif
        if (ip->ip_p == IPPROTO_TCP && ip->ip_v == 4)
        {
            send_tcp_segment(ip, &tcp_callback);
            /*eprintf("tcp packet %u %d %d\n", ip->ip_dst.s_addr, ip->ip_p, pkt_len);
            abort();*/
        }
        else
        {
            //eprintf("buffer format error.\n");
            ++exp_stats->non_tcp_pkt;
        }

        //eprintf("pkt %d %d: %d %d %d\n", ++c, pkt_len, stats_cache_hit, stats_store_hit, stats_miss);

        if (unlikely(last_checking_time == 0)) {
            last_checking_time = wall_clock.tv_sec;
        }

        if ((wall_clock.tv_sec - last_checking_time) >= DEFAULT_TCP_CHECK_TIMEOUT_PERIOD) {
            //eprintf("expiration checking!\n");
            tcp_check_timeouts(tcp_session);
            last_checking_time = wall_clock.tv_sec;
        }
    }
}

/* Test */
void ecall_process_test_round(void *_pkt_buffer, void *_pkt_hdr)
{
    //eprintf("LightBox %d CONNECTION %d CAIDA %d\n", LightBox, CONNECTION, CAIDA);
    static int round_idx = 0;

    packet_t *pkt_list = (packet_t *)_pkt_buffer;
    pcap_pkthdr *hdr_list = (pcap_pkthdr *)_pkt_hdr;

    long long  start_s, start_ns, end_s, end_ns;
    int i = 0;

    wall_clock.tv_usec = 0;

    time_t last_checking_time = 0;

    struct ip	*ip;

    unsigned long long total_byte = 0;
    ocall_get_time(&start_s, &start_ns);
    for (; i < TEST_ITVL; ++i) {
        if (unlikely(last_checking_time == 0)) {
            last_checking_time = hdr_list[i].ts.tv_sec;
        }

#if CAIDA==1
        ip = (struct ip*)&pkt_list[i];
#else
        ip = (struct ip*) ((uint8_t *)&pkt_list[i] + sizeof(struct ether_header));
#endif
        /*eprintf("%s \n", &pkt_list[i]);
        abort();*/
        if (ip->ip_p == IPPROTO_TCP)
        {
            send_tcp_segment(ip, &tcp_callback);
            //eprintf("tcp pkt %d\n", hdr_list[i].caplen);
        }
        else
        {
            //eprintf("other packet %d : %u %d %d %s\n", i, ip->ip_dst.s_addr, ip->ip_p, hdr_list[i].caplen, ip);
            ++exp_stats->non_tcp_pkt;
        }

        total_byte += hdr_list[i].caplen;

        //eprintf("pkt %d %d: %d %d %d\n", ++c, pkt_len, stats_cache_hit, stats_store_hit, stats_miss);

        if (unlikely(last_checking_time == 0)) {
            last_checking_time = wall_clock.tv_sec;
        }

        if ((wall_clock.tv_sec - last_checking_time) >= DEFAULT_TCP_CHECK_TIMEOUT_PERIOD) {
            eprintf("expiration checking!\n");
            tcp_check_timeouts(tcp_session);
            last_checking_time = wall_clock.tv_sec;
        }
    }
    ocall_get_time(&end_s, &end_ns);
    double elapsed_us = (end_s - start_s)*1000000.0 + (end_ns - start_ns) / 1000.0;

    eprintf("Round %d - delay %f - tput %f - flow %d\n",
            ++round_idx, elapsed_us / TEST_ITVL, total_byte*8.0 / elapsed_us,
            exp_stats->current_stream);
}
