
extern "C" {
#include "../../../../lb_core/enclave/etap_t.h"
#include "../../../../lb_core/enclave/state_mgmt_t.h"
#include "../../../../lb_networking/libpcap/trusted/bpf/sfbpf.h"
#include "../../../../lb_networking/libpcap/trusted/pcap.h"
}
//#include "Enclave.h"
#include "Enclave_t.h"

#include <stdarg.h>
#include <stdio.h> // vsnprintf

void eprintf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
}

void ecall_text()
{
    // begin test ocall printf
    init_state_mgmt();

    struct pcap_pkthdr hdr;
    struct pcap_pkthdr* pkthdr = &hdr;
    char* device;
    char error[200];
    pcap_t* p = pcap_create(NULL, error);
    // read_pkt(pktData, &pkthdr->len, (struct timeval*)&pkthdr->ts);
    // uint8_t pkt[8192];
    const uint8_t* pkt;
    struct sfbpf_program fp;
    const char* filter_str = "tcp";
    // pcap_compile(p, &fp, filter_str, 0, 0);

    // pcap_setfilter(p, &fp);

    eprintf("Entered pcap loop\n");
    while (1) {
	// read_pkt(pkt, &pkthdr->len, (struct timeval*)&pkthdr->ts);
	pkt = pcap_next(p, pkthdr);
	//	eprintf("%s\n", pkt);
    }
    return;
}
