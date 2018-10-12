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

int pcap_inject(pcap_t * handle, const void * data, size_t len)
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
