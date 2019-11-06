
#include "pcap_t.h"

#include "lb_pcap_edge_t.h"
// #include "bpf/sfbpf.h"

#include <etap_t.h>
#include "rx_ring_opt.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <lb_utils_t.h>

// TODO : fix the conversion ...
// from sf_bpf_filter.h
uint bpf_filter(const struct bpf_insn* pc, const u_char* p, uint wirelen,
		uint buflen);
#define sfbpf_filter bpf_filter

// TODO: this logic device should mimic physical device
extern etap_controller_t* etap_controller_instance;

// TODO: complete internal handle management
pcap_t singular_handle;

const uint8_t* pcap_next(pcap_t* handle, struct pcap_pkthdr* header) {
    static uint8_t pktData[8192];
    // read_pkt needs to be defined, currently a bit ugly ...
    read_pkt(pktData, &header->caplen, (timeval_t*)&header->ts);
    header->len = header->caplen;
	/* eprintf("header len is %d, caplen is %d\n", header->len, header->caplen); */
	/* eprintf("pkt content is %s\n", pktData); */
    if (header->len > 0 && header->caplen < 8192) {
	if (handle->hasFcode) {
	    /* ocall_p("line 20\n"); */
	    int ret = sfbpf_filter(handle->fcode.bf_insns, pktData, header->len,
				   header->caplen);
	    if (ret == 0) return 0;
	}
	return (uint8_t*)pktData;
    } else {
	return 0;
    }
}

int pcap_loop(pcap_t* p, int cnt, pcap_handler callback, u_char* useless) {
    // eprintf("%s started \n", __func__);

    static uint8_t pktData[8192];
    static struct pcap_pkthdr pktHeader;

    if (cnt <= 0) {
	while (1) {
	    read_pkt(pktData, &(pktHeader.caplen), &(pktHeader.ts));
	    pktHeader.len = pktHeader.caplen;
	    // filtering to be added
	    callback(NULL, &pktHeader, pktData);
	}
    } else {
	for (int i = 0; i < cnt; i++) {
	    read_pkt(pktData, &(pktHeader.len), &(pktHeader.ts));
	    pktHeader.len = pktHeader.caplen;
	    // Run the packet filter before applying callback function
	    // int ret = 0;
	    // ret = sfbpf_filter(&(p->fcode.bf_insns), pktData,
	    // 		   pktHeader->len, pktHeader->caplen);
	    // if (ret == 0) {
	    // 	continue;
	    // }
	    callback(NULL, &pktHeader, pktData);
	}
    }
    return 0;
}

// TODO: fix memory issue
int pcap_compile(pcap_t* handle, struct sfbpf_program* fp, const char* str,
		 int optimize, bpf_u_int32 netmask) {
#define DUMMY_PKT_HDR_LEN 0
    struct sfbpf_program** program;
    ocall_pcap_sfbpf_compile(DUMMY_PKT_HDR_LEN, program, str, optimize);

    struct sfbpf_program tmp_fcode;
    struct sfbpf_program* host_fcode = *program;
    memcpy(tmp_fcode.bf_insns, host_fcode->bf_insns, sizeof(struct sfbpf_insn));
    tmp_fcode.bf_len = host_fcode->bf_len;
    fp = &tmp_fcode;
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
    singular_handle.hasFcode = 0;
    return &singular_handle;
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

// dummy entry to suppress error message
void ecall_dummy_entry() {}
