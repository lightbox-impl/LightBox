#include "bpf/sfbpf.h"
#include "bpf/sfbpf_dlt.h"
#include <stdio.h>

/* void ocall_pcap_compile(struct bpf_program* fp, char* str, int optimize) */
/* { */
/* pcap_t* handle; */
/* char dev[] = "lo"; // Dummy Device to sniff on; */
/* char errbuf[50]; */

/* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); */
/* if (handle == NULL) { */
/* fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf); */
/* return; */
/* } */

/* if (pcap_compile(handle, fp, str, optimize, PCAP_NETMASK_UNKNOWN) == -1) { */
/* fprintf(stderr, "Couldn't parse filter %s: %s\n", str, pcap_geterr(handle)); */
/* return; */
/* } */
/* } */

/* int PKT_HEADER_LEN = 1514; */

void ocall_sfbpf_compile(int pkt_hdr_len, struct sfbpf_program* fcode, const char* filter, int optimize)
{
    if (sfbpf_compile(pkt_hdr_len, DLT_EN10MB, fcode, filter, 1, 0) < 0) {
	fprintf(stderr, "%s: BPF state machine compilation failed!", __FUNCTION__);
	return;
    }
}

/* void ocall_sfbpf_filter(struct sfbpf_program* fcode, const char* p, unsigned int wirelen, unsigned int buflen, int* ret) */
/* { */
/* *ret = sfbpf_filter(fcode->bf_insns, p, wirelen, buflen); */

/* return; */
/* } */
/* int main() */
/* { */
/* return 0; */
/* } */
