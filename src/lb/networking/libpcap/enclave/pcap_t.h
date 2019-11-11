#ifndef LB_PCAP_H
#define LB_PCAP_H

#include "stdint.h"

#include "bpf/sfbpf.h"
#include "bpf/sf-redefines.h"
#include <linux_type_ports.h>

#define PCAP_ERRBUF_SIZE 256

struct pcap_pkthdr {
   timeval_t ts; /* time stamp */
   int32_t caplen;   /* length of portion present */
   int32_t len;      //   [> length this packet (off wire) <]
};

typedef struct pcap {
    struct bpf_program fcode;
    int hasFcode;
} pcap_t;

typedef void (*pcap_handler)(u_char*, const struct pcap_pkthdr*, const u_char*);

const uint8_t* pcap_next(pcap_t* handle, struct pcap_pkthdr* header);
int pcap_inject(pcap_t* handle, const void* data, unsigned long len);

int pcap_set_buffer_size(pcap_t* handle, int size);
void pcap_close(pcap_t* handle);

pcap_t* pcap_create(const char* dev_name, char* error_buffer);
int pcap_activate(pcap_t* handle);

int pcap_loop(pcap_t*, int, pcap_handler, u_char*);
int pcap_compile(pcap_t*, struct sfbpf_program*, const char*, int, bpf_u_int32);
int pcap_setfilter(pcap_t* handle, struct sfbpf_program* filter);
#endif
