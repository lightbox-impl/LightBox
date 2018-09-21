#include "include/sgx/sgxFunc.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include "debug.h"
#include "tcp_in.h"
#include "logger.h"
#include "ip_in.h"

#ifdef SGX_DEBUG_TIME

#define TIMERCOUNT 16
static long long  debugTime[TIMERCOUNT];
static long long  debugCount[TIMERCOUNT];
static struct etime debugTimers[TIMERCOUNT];
static long long  totalTime;
static struct etime timeBegin;
static struct etime timeEnd;

void timeStart()
{
#define DEBUG_TIME_LOOP 1
	static int showCounter = 0;
	int printLoop = DEBUG_TIME_LOOP;
	int i;
	getTime(&timeEnd);
	totalTime += diffTime(&timeBegin, &timeEnd);

	if (++showCounter == printLoop)
	{
		printf("\nTotal time is %lld in %d pkt us\n", totalTime/ printLoop, printLoop);
		for (i = 0; i < TIMERCOUNT; i++)
		{
			if (debugCount[i])
				printf("time%d: %d use %lld\n", i, debugCount[i], debugTime[i] / debugCount[i]);
		}
		printf("\n");
		memset(debugTime, 0, sizeof(debugTime));
		memset(debugCount, 0, sizeof(debugCount));
		totalTime = 0;
		showCounter = 0;
	}

	getTime(&timeBegin);
	debugTimers[0] = timeBegin;
}

void timePin(int n)
{
	if (n >= 0 && n < TIMERCOUNT)
	{
		getTime(debugTimers+n);
		getTime(&timeEnd);

		if (1)
		{
			if (debugTimers[n - 1].s != 0)
				debugTime[n] += diffTime(&debugTimers[n - 1], &debugTimers[n]);
		}
		else
		{
			debugTime[n] += diffTime(&timeBegin, &timeEnd);
		}

		debugCount[n] += 1;
	}
}





#endif

#ifdef SGX_DEBUG_PIN

#define PINCOUNT 32
static long long  pinCounter[PINCOUNT];
static char pinStr[PINCOUNT][64];
void debugPinShow()
{
#define DEBUG_PIN_SHOW 100000
	static int showCounter = 0;
	const int printLoop = DEBUG_PIN_SHOW;
	int i;
	if (++showCounter == printLoop)
	{
		printf("\nTotal after %lld loop\n",  printLoop);
		for (i = 0; i < PINCOUNT; i++)
		{
			if (pinCounter[i])
				printf("pin%d: arrive %lld times.\n", i, pinCounter[i]);
		}
		memset(pinCounter, 0, sizeof(pinCounter));
		showCounter = 0;
	}
}
void debugPin(int n)
{
	++pinCounter[n];
}
#else

void debugPinShow() {};
void debugPin(int n) {};

#endif

/*----------------------------------------------------------------------------*/
void flush_log_data(mtcp_manager_t mtcp)
{
	//int ret = 0;
	//if (mtcp->w_buffer) {
	//	EnqueueJobBuffer(mtcp->logger, mtcp->w_buffer);
	//	ret = write(mtcp->sp_fd, "A", 1);
	//	if (ret != 1) {
	//		TRACE_INFO("Failed to flush logs in the buffer.\n");
	//		perror("write() for pipe");
	//	}
	//}
}
/*----------------------------------------------------------------------------*/
void
thread_printf(mtcp_manager_t mtcp, FILE* f_idx, const char* _Format, ...) 
{
	//va_list argptr;
	//va_start(argptr, _Format);

	//#define PRINT_LIMIT 4096
	//int len;
	//log_buff *wbuf;

	//assert(f_idx != NULL);

	//pthread_mutex_lock(&mtcp->logger->mutex);
	//wbuf = mtcp->w_buffer;
	//if (wbuf && (wbuf->buff_len + PRINT_LIMIT > LOG_BUFF_SIZE)) {
	//	flush_log_data(mtcp);
	//	wbuf = NULL;
	//}

	//if (!wbuf) {
	//	do { // out of free buffers!!
	//		wbuf = DequeueFreeBuffer(mtcp->logger);
	//		assert(wbuf);
	//	} while (!wbuf);
	//	wbuf->buff_len = 0;
	//	wbuf->tid = mtcp->ctx->cpu;
	//	wbuf->fid = f_idx;
	//	mtcp->w_buffer = wbuf;
	//}
	//
	//len = vsnprintf(wbuf->buff + wbuf->buff_len, PRINT_LIMIT, _Format, argptr);
	//wbuf->buff_len += len;
	//pthread_mutex_unlock(&mtcp->logger->mutex);

	//va_end(argptr);

}
/*----------------------------------------------------------------------------*/
void
DumpPacket(mtcp_manager_t mtcp, char *buf, int len, char *step, int ifindex)
{
//	struct ethhdr *ethh;
//	struct iphdr *iph;
//	struct udphdr *udph;
//	struct tcphdr *tcph;
//	uint8_t *t;
//
//	if (ifindex >= 0)
//		thread_printf(mtcp, mtcp->log_fp, "%s %d %u", step, ifindex, mtcp->cur_ts);
//	else
//		thread_printf(mtcp, mtcp->log_fp, "%s ? %u", step, mtcp->cur_ts);
//
//	ethh = (struct ethhdr *)buf;
//	if (ntohs(ethh->h_proto) != ETH_P_IP) {
//		thread_printf(mtcp, mtcp->log_fp, "%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X ",
//				ethh->h_source[0],
//				ethh->h_source[1],
//				ethh->h_source[2],
//				ethh->h_source[3],
//				ethh->h_source[4],
//				ethh->h_source[5],
//				ethh->h_dest[0],
//				ethh->h_dest[1],
//				ethh->h_dest[2],
//				ethh->h_dest[3],
//				ethh->h_dest[4],
//				ethh->h_dest[5]);
//
//		thread_printf(mtcp, mtcp->log_fp, "protocol %04hx  ", ntohs(ethh->h_proto));
//		goto done;
//	}
//
//	thread_printf(mtcp, mtcp->log_fp, " ");
//
//	iph = (struct iphdr *)(ethh + 1);
//	udph = (struct udphdr *)((uint32_t *)iph + iph->ihl);
//	tcph = (struct tcphdr *)((uint32_t *)iph + iph->ihl);
//
//	t = (uint8_t *)&iph->saddr;
//	thread_printf(mtcp, mtcp->log_fp, "%u.%u.%u.%u", t[0], t[1], t[2], t[3]);
//	if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
//		thread_printf(mtcp, mtcp->log_fp, "(%d)", ntohs(udph->source));
//
//	thread_printf(mtcp, mtcp->log_fp, " -> ");
//
//	t = (uint8_t *)&iph->daddr;
//	thread_printf(mtcp, mtcp->log_fp, "%u.%u.%u.%u", t[0], t[1], t[2], t[3]);
//	if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
//		thread_printf(mtcp, mtcp->log_fp, "(%d)", ntohs(udph->dest));
//
//	thread_printf(mtcp, mtcp->log_fp, " IP_ID=%d", ntohs(iph->id));
//	thread_printf(mtcp, mtcp->log_fp, " TTL=%d ", iph->ttl);
//
//	if (ip_fast_csum(iph, iph->ihl)) {
//		__sum16 org_csum, correct_csum;
//		
//		org_csum = iph->check;
//		iph->check = 0;
//		correct_csum = ip_fast_csum(iph, iph->ihl);
//		thread_printf(mtcp, mtcp->log_fp, "(bad checksum %04x should be %04x) ",
//				ntohs(org_csum), ntohs(correct_csum));
//		iph->check = org_csum;
//	}
//
//	switch (iph->protocol) {
//	case IPPROTO_TCP:
//		thread_printf(mtcp, mtcp->log_fp, "TCP ");
//		
//		if (tcph->syn)
//			thread_printf(mtcp, mtcp->log_fp, "S ");
//		if (tcph->fin)
//			thread_printf(mtcp, mtcp->log_fp, "F ");
//		if (tcph->ack)
//			thread_printf(mtcp, mtcp->log_fp, "A ");
//		if (tcph->rst)
//			thread_printf(mtcp, mtcp->log_fp, "R ");
//
//		thread_printf(mtcp, mtcp->log_fp, "seq %u ", ntohl(tcph->seq));
//		if (tcph->ack)
//			thread_printf(mtcp, mtcp->log_fp, "ack %u ", ntohl(tcph->ack_seq));
//		thread_printf(mtcp, mtcp->log_fp, "WDW=%u ", ntohs(tcph->window));
//		break;
//	case IPPROTO_UDP:
//		thread_printf(mtcp, mtcp->log_fp, "UDP ");
//		break;
//	default:
//		thread_printf(mtcp, mtcp->log_fp, "protocol %d ", iph->protocol);
//		goto done;
//	}
//done:
//	thread_printf(mtcp, mtcp->log_fp, "len=%d\n", len);
}
/*----------------------------------------------------------------------------*/
void
DumpIPPacket(mtcp_manager_t mtcp, const struct iphdr *iph, int len)
{
//	struct udphdr *udph;
//	struct tcphdr *tcph;
//	uint8_t *t;
//
//	udph = (struct udphdr *)((uint32_t *)iph + iph->ihl);
//	tcph = (struct tcphdr *)((uint32_t *)iph + iph->ihl);
//
//	t = (uint8_t *)&iph->saddr;
//	thread_printf(mtcp, mtcp->log_fp, "%u.%u.%u.%u", t[0], t[1], t[2], t[3]);
//	if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
//		thread_printf(mtcp, mtcp->log_fp, "(%d)", ntohs(udph->source));
//
//	thread_printf(mtcp, mtcp->log_fp, " -> ");
//
//	t = (uint8_t *)&iph->daddr;
//	thread_printf(mtcp, mtcp->log_fp, "%u.%u.%u.%u", t[0], t[1], t[2], t[3]);
//	if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
//		thread_printf(mtcp, mtcp->log_fp, "(%d)", ntohs(udph->dest));
//
//	thread_printf(mtcp, mtcp->log_fp, " IP_ID=%d", ntohs(iph->id));
//	thread_printf(mtcp, mtcp->log_fp, " TTL=%d ", iph->ttl);
//
//	if (ip_fast_csum(iph, iph->ihl)) {
//		thread_printf(mtcp, mtcp->log_fp, "(bad checksum) ");
//	}
//
//	switch (iph->protocol) {
//	case IPPROTO_TCP:
//		thread_printf(mtcp, mtcp->log_fp, "TCP ");
//		
//		if (tcph->syn)
//			thread_printf(mtcp, mtcp->log_fp, "S ");
//		if (tcph->fin)
//			thread_printf(mtcp, mtcp->log_fp, "F ");
//		if (tcph->ack)
//			thread_printf(mtcp, mtcp->log_fp, "A ");
//		if (tcph->rst)
//			thread_printf(mtcp, mtcp->log_fp, "R ");
//
//		thread_printf(mtcp, mtcp->log_fp, "seq %u ", ntohl(tcph->seq));
//		if (tcph->ack)
//			thread_printf(mtcp, mtcp->log_fp, "ack %u ", ntohl(tcph->ack_seq));
//		thread_printf(mtcp, mtcp->log_fp, "WDW=%u ", ntohs(tcph->window));
//		break;
//	case IPPROTO_UDP:
//		thread_printf(mtcp, mtcp->log_fp, "UDP ");
//		break;
//	default:
//		thread_printf(mtcp, mtcp->log_fp, "protocol %d ", iph->protocol);
//		goto done;
//	}
//done:
//	thread_printf(mtcp, mtcp->log_fp, "len=%d\n", len);
}
/*----------------------------------------------------------------------------*/
void
DumpIPPacketToFile(FILE *fout, const struct iphdr *iph, int len)
{
//	struct udphdr *udph;
//	struct tcphdr *tcph;
//	uint8_t *t;
//
//	udph = (struct udphdr *)((uint32_t *)iph + iph->ihl);
//	tcph = (struct tcphdr *)((uint32_t *)iph + iph->ihl);
//
//	t = (uint8_t *)&iph->saddr;
//	fprintf(fout, "%u.%u.%u.%u", t[0], t[1], t[2], t[3]);
//	if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
//		fprintf(fout, "(%d)", ntohs(udph->source));
//
//	fprintf(fout, " -> ");
//
//	t = (uint8_t *)&iph->daddr;
//	fprintf(fout, "%u.%u.%u.%u", t[0], t[1], t[2], t[3]);
//	if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
//		fprintf(fout, "(%d)", ntohs(udph->dest));
//
//	fprintf(fout, " IP_ID=%d", ntohs(iph->id));
//	fprintf(fout, " TTL=%d ", iph->ttl);
//
//	if (ip_fast_csum(iph, iph->ihl)) {
//		fprintf(fout, "(bad checksum) ");
//	}
//
//	switch (iph->protocol) {
//	case IPPROTO_TCP:
//		fprintf(fout, "TCP ");
//		
//		if (tcph->syn)
//			fprintf(fout, "S ");
//		if (tcph->fin)
//			fprintf(fout, "F ");
//		if (tcph->ack)
//			fprintf(fout, "A ");
//		if (tcph->rst)
//			fprintf(fout, "R ");
//
//		fprintf(fout, "seq %u ", ntohl(tcph->seq));
//		if (tcph->ack)
//			fprintf(fout, "ack %u ", ntohl(tcph->ack_seq));
//		fprintf(fout, "WDW=%u ", ntohs(tcph->window));
//		break;
//	case IPPROTO_UDP:
//		fprintf(fout, "UDP ");
//		break;
//	default:
//		fprintf(fout, "protocol %d ", iph->protocol);
//		goto done;
//	}
//done:
//	fprintf(fout, "len=%d\n", len);
}
