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

void ocall_pcap_sfbpf_compile(int pkt_hdr_len, struct sfbpf_program** f, const char* filter, int optimize)
{
	struct sfbpf_program fcode ;
    if (sfbpf_compile(2036, DLT_EN10MB, &fcode, filter, 1, 0) < 0) {
	fprintf(stderr, "%s: BPF state machine compilation failed!\n", __FUNCTION__);
	return;
    }

	*f = &fcode;
}
#ifdef __cplusplus
}
#endif
