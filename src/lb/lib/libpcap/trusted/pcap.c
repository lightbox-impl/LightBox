
#include "pcap.h"
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "../../../core/enclave/include/etap_t.h"
#include "bpf/sfbpf.h"
#include "bpf/sfbpf_dlt.h"
#include "stdio.h"

extern etap_controller_t* etap_controller_instance;

void pcap_print(const char* fmt, ...) {
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_p(buf);
}

int pkt_len = 0;
/* pcap_t handle; */

const uint8_t* pcap_next(pcap_t* handle, struct pcap_pkthdr* header) {
#ifdef USE_ETAP
	static uint8_t pktData[8192];
	etap_controller_instance->rx_ring_instance->read_pkt(
	    pktData, &header->len, (timeval_t*)&header->ts,
	    etap_controller_instance->rx_ring_instance->rData);
	header->caplen = header->len;
	if (header->len > 0 && header->caplen < 8192) {
		if (handle->hasFcode) {
			/* ocall_p("line 20\n"); */
			int ret =
			    sfbpf_filter(&(handle->fcode.bf_insns), pktData,
					 header->len, header->caplen);
			if (ret == 0) return 0;
		}
		return (uint8_t*)pktData;
	} else {
		return 0;
	}

#else
	char* pktData = 0;
	ocall_pcap_next(&pktData, (char*)header);
	return (uint8_t*)pktData;
#endif
}

int pcap_loop(pcap_t* p, int cnt, pcap_handler callback, u_char* user) {
	// We only support live capture instead of reading saved file option
	// We also do not accept -1, 0 value for cnt to represent infinity
	// pcap_loop may ignore timeout as stated offically.
	// TODO pktData is type of uint8_t, need to change to u_char perhaps?
	static uint8_t pktData[8192];
	struct pcap_pkthdr* pktHeader;
	for (int i = 0; i < cnt; i++) {
		etap_controller_instance->rx_ring_instance->read_pkt(
		    pktData, &pktHeader->len, (timeval_t*)&pktHeader->ts,
		    etap_controller_instance->rx_ring_instance->rData);
		pkt_len = pktHeader->len;
		pktHeader->caplen = pktHeader->len;
		// Run the packet filter before applying callback function
		int ret = 0;
		ret = sfbpf_filter(&(p->fcode.bf_insns), pktData,
				   pktHeader->len, pktHeader->caplen);
		if (ret == 0) {
			continue;
		}
		callback(NULL, pktHeader, pktData);
	}
	return 0;
}

int pcap_compile(pcap_t* handle, struct sfbpf_program* fp, const char* str,
		 int optimize, bpf_u_int32 netmask) {
	ocall_pcap_sfbpf_compile(pkt_len, fp, str, optimize);
	return 0;
}

int pcap_setfilter(pcap_t* handle, struct sfbpf_program* filter) {
	if (!handle) return -1;
	if (!filter) return -2;

	memcpy(&(handle->fcode), filter, sizeof(struct sfbpf_program));
	handle->hasFcode = 1;

	return 0;
}

int pcap_inject(pcap_t* handle, const void* data, unsigned long len) {
	// TODO: send one packet
	return len;
}

int pcap_set_buffer_size(pcap_t* handle, int size) { return 0; }

pcap_t* pcap_create(const char* dev_name, char* error_buffer) {
#ifdef USE_ETAP
#else
	ocall_pcap_init((char*)dev_name);
#endif
	// return (pcap_t*)1;
	/* pcap_t handle; */
	// handle = struct pcap p;
	handle.hasFcode = 0;
	return &handle;
}

int pcap_activate(pcap_t* handle) { return 0; }

// Clean up a "struct bpf_program" by freeing all the memory allocated in it.
void pcap_freecode(struct sfbpf_program* program) {
	program->bf_len = 0;
	if (program->bf_insns != NULL) {
		free((char*)program->bf_insns);
		program->bf_insns = NULL;
	}
}

void pcap_close(pcap_t* handle) { pcap_freecode(&(handle->fcode)); }

void dummy_func(int d) { d++; }
