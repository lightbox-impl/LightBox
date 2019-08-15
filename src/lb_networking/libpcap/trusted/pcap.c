#include "pcap.h"
#include "../../../lb_core/enclave/etap_t.h"
#include "bpf/sfbpf.h"
#include "bpf/sfbpf_dlt.h"
#include <stdlib.h>
#include <string.h>

/* struct sfbpf_program fcode; */
/* int ocall_sfbpf_compile(int snaplen_arg, int linktype_arg, char* program, */
/* const char* buf, int optimize, int mask) */
/* { */
/* int ret = sfbpf_compile(snaplen_arg, linktype_arg, &fcode, buf, optimize, mask); */
/* memcpy(program, &fcode, sizeof(fcode)); */
/* if (fcode.bf_insns) */
/* memcpy(program + sizeof(fcode), fcode.bf_insns, sizeof(struct sfbpf_insn)); */
/* return ret; */
/* } */

/* int etap_sfbpf_filter(const char* pc, const char* p, int wirelen, int buflen) */
/* { */
/* return sfbpf_filter((const struct sfbpf_insn*)pc, (const unsigned char*)p, wirelen, buflen); */
/* } */

/* void etap_sfbpf_freecode(char* program) */
/* { */
/* sfbpf_freecode(&fcode); */
/* } */

int pkt_len = 0;

const uint8_t* pcap_next(pcap_t* handle, struct pcap_pkthdr* header)
{
#ifdef USE_ETAP
    static uint8_t pktData[8192];
    read_pkt(pktData, &header->len, (time_t*)&header->ts);
    header->caplen = header->len;
    if (header->len > 0 && header->caplen < 8192) {
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

int pcap_loop(pcap_t* p, int cnt, pcap_handler callback, u_char* user)
{
    // We only support live capture instead of reading saved file option
    // We also do not accept -1, 0 value for cnt to represent infinity
    // pcap_loop may ignore timeout as stated offically.
    // TODO pktData is type of uint8_t, need to change to u_char perhaps?
    static uint8_t pktData[8192];
    struct pcap_pkthdr* pktHeader;
    for (int i = 0; i < cnt; i++) {
	read_pkt(pktData, &pktHeader->len, (time_t*)&pktHeader->ts);
	pkt_len = pktHeader->len;
	pktHeader->caplen = pktHeader->len;
	// Run the packet filter before applying callback function
	int ret;
	ret = sfbpf_filter(&(p->fcode.bf_insns), pktData, pktHeader->len, pktHeader->caplen);
	if (ret == 0) {
	    continue;
	}
	callback(NULL, pktHeader, pktData);
    }
    return 0;
}

int pcap_compile(pcap_t* handle, struct sfbpf_program* fp,
    const char* str, int optimize, bpf_u_int32 netmask)
{
    ocall_sfbpf_compile(pkt_len, fp, str, optimize);
    return 0;
}

int pcap_setfilter(pcap_t* handle, struct sfbpf_program* filter)
{
    if (!handle)
	return -1;
    if (!filter)
	return -2;
    // install the bpf program (filter) to handle
    // TODO handle now is a pure int, need to change to a singleton later
    // if (install_bfp_program(handle, filter) < 0) return -3;

    /* size_t prog_size; */

    // TODO validate the filter program

    /* prog_size = sizeof(*filter->bf_insns) * filter->bf_len; */
    /* handle->fcode.bf_len = filter->bf_len; */
    /* handle->fcode.bf_insns = (struct bfp_insn*)malloc(prog_size); */
    /* if (handle->fcode.bf_insns == NULL) { */
    /* // Error occurred */
    /* return -3; */
    /* } */
    /* memcpy(handle->fcode.bf_insns, filter->bf_insns, prog_size); */

    memcpy(&(handle->fcode), filter, sizeof(struct sfbpf_program));

    return 0;
}

int pcap_inject(pcap_t* handle, const void* data, unsigned long len)
{
    // TODO: send one packet
    return len;
}

int pcap_set_buffer_size(pcap_t* handle, int size)
{
    return 0;
}

pcap_t* pcap_create(const char* dev_name, char* error_buffer)
{
#ifdef USE_ETAP
#else
    ocall_pcap_init((char*)dev_name);
#endif
    // return (pcap_t*)1;
    pcap_t* handle;
    // handle = struct pcap p;
    return handle;
}

int pcap_activate(pcap_t* handle)
{
    return 0;
}

// Clean up a "struct bpf_program" by freeing all the memory allocated in it.
void pcap_freecode(struct sfbpf_program* program)
{
    program->bf_len = 0;
    if (program->bf_insns != NULL) {
	free((char*)program->bf_insns);
	program->bf_insns = NULL;
    }
}

void pcap_close(pcap_t* handle)
{
    pcap_freecode(&(handle->fcode));
}

void dummy_func(int d) {}
