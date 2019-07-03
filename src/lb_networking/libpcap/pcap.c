#include "pcap.h"
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
		static uint8_t pktData[8192];
		struct pcap_pkthdr * pktHeader;
		for (int i = 0; i < cnt; i++){
				read_pkt(pktData, &pktHeader->len, (time_t*)&pktHeader->ts);
				pktHeader->caplen = pktHeader->len;
				callback(NULL, pktHeader, pktData);
		}
		return 0;
}


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
	//nothing to do
}

pcap_t * pcap_create(const char * dev_name, char * error_buffer)
{
#ifdef USE_ETAP
#else
	ocall_pcap_init((char*)dev_name);
#endif
	return (pcap_t*)1;
}

int pcap_activate(pcap_t * handle)
{
	return 0;
}
