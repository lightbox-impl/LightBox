#include "bpf/sfbpf.h"
#include "bpf/sfbpf_dlt.h"
#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#include <stdlib.h>

void ocall_p(const char* str)
{
    printf("%s", str);
}

// TODO: fix the compilation
void ocall_pcap_sfbpf_compile(int pkt_hdr_len, struct sfbpf_program** f, const char* filter, int optimize)
{
    /* struct sfbpf_program f; */
    /* const char* str = "tcp"; */
    /* if (sfbpf_compile(1514, DLT_EN10MB, fcode, filter, 1, 0) < 0) { */
	struct sfbpf_program fcode ;
    if (sfbpf_compile(2036, DLT_EN10MB, &fcode, filter, 1, 0) < 0) {
	fprintf(stderr, "%s: BPF state machine compilation failed!\n", __FUNCTION__);
	return;
    }

	*f = &fcode;

    /* pcap_t* handle; */
    /* char dev[] = "lo"; // Dummy device to sniff on; */
    /* char errbuf[50]; */

    /* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); */
    /* if (handle == NULL) */
    /* return; // Couldn't open device */

    /* pcap_compile(handle, (struct bpf_program*)fcode, filter, optimize, PCAP_NETMASK_UNKNOWN); */
}
#ifdef __cplusplus
}
#endif
