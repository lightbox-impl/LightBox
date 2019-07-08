#include "pcap.h"
#include <stdlib.h>
#include "../../lb_core/enclave/etap_t.h"

const uint8_t * pcap_next(pcap_t * handle, struct pcap_pkthdr * header)
{
#ifdef USE_ETAP
	static uint8_t pktData[8192];
	read_pkt(pktData, &header->len, (time_t*)&header->ts);
	header->caplen = header->len;
	if (header->len>0 && header->caplen<8192)
	{
		return (uint8_t *)pktData;
	}
	else
	{
		return 0;
	}

#else
	char * pktData = 0;
	ocall_pcap_next(&pktData, (char*)header);
	return (uint8_t *)pktData;
#endif
}

int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) 
{
		// We only support live capture instead of reading saved file option
		// We also do not accept -1, 0 value for cnt to represent infinity
		// pcap_loop may ignore timeout as stated offically. 
		// TODO pktData is type of uint8_t, need to change to u_char perhaps?
		static uint8_t pktData[8192];
		struct pcap_pkthdr * pktHeader;
		for (int i = 0; i < cnt; i++){
				read_pkt(pktData, &pktHeader->len, (time_t*)&pktHeader->ts);
				pktHeader->caplen = pktHeader->len;
				// Run the packet filter before applying callback function
				if (bpf_filter(p->fcode.bf_insns,pktData, pktHeader->len,
										pktHeader->caplen) == 0) {
						continue;
				}
				callback(NULL, pktHeader, pktData);
		}
		return 0;
}

/*
int pcap_compile(pcap_t *p, struct bpf_program *program, const char *buf,
				int optimize, bpf_u_int32 mask)
{
		// TODO not sure whether I should move to pcap_setfilter or 
		// keep writing this function. 
		// Both API envolve bpf program and other code gen stuff
		
		compiler_state_t cstate;
		const char* volatile xbuf = buf;
		yyscan_t scanner NULL;
		YY_BUFFER_STATE in_buffer = NULL;
		u_int len;
		int rc;

		initchunks(&cstate);
		cstate.no_optimize = 0;

		
}

*/

int pcap_setfilter(pcap_t * handle, struct bpf_program *filter) 
{
		if (!handle) return -1;
		if (!filter) return -2;
		// install the bpf program (filter) to handle
		// TODO handle now is a pure int, need to change to a singleton later
		// if (install_bfp_program(handle, filter) < 0) return -3;
		
		size_t prog_size;

		// TODO validate the filter program 
		
		// TODO free up any already installed program
		// Do it after refactored the handle struct (pcap_t)
		
		prog_size = sizeof(*filter->bf_insns) * filter->bf_len;
		handle->fcode.bf_len = filter->bf_len;
		handle->fcode.bf_insns = (struct bfp_insn *)malloc(prog_size);
		if (handle->fcode.bf_insns == NULL) {
				// Error occurred
				return -3;
		}
		memcpy(handle->fcode.bf_insns, filter->bf_insns, prog_size);
		return 0;
}

int pcap_inject(pcap_t * handle, const void * data, unsigned long len)
{
	// TODO: send one packet
	return len;
}

int pcap_set_buffer_size(pcap_t * handle, int size)
{
	return 0;
}

void pcap_close(pcap_t * handle)
{
	pcap_freecode(handle->fcode);
}

pcap_t * pcap_create(const char * dev_name, char * error_buffer)
{
#ifdef USE_ETAP
#else
	ocall_pcap_init((char*)dev_name);
#endif
	// return (pcap_t*)1;
	pcap_t * handle;
	handle = struct pcap_t p;
	return handle;
}

int pcap_activate(pcap_t * handle)
{
	return 0;
}

// Clean up a "struct bpf_program" by freeing all the memory allocated in it.
void pcap_freecode(struct bpf_program *program) 
{
	program->bf_len = 0;
	if (program->bf_insns != NULL) {
			free ((char *)program->bf_insns);
			program->bf_insns = NULL;
	}
}

