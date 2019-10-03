#ifndef SGX_PCAP_H
#define SGX_PCAP_H

#include "bpf/sfbpf.h"
#include "stdint.h"
#include "../../../../include/lb_time.h"
#include <sys/types.h> /* u_int, u_char etc. */
//#include "time.h"
// You need use your time port instead of this.
// struct timeval {
    // __time_t tv_sec;
    // __time_t tv_usec;
// };

#ifndef USE_ETAP
#define USE_ETAP
#endif

// pcap.h
// typedef int pcap_t;
typedef void (*pcap_handler)(u_char*, const struct pcap_pkthdr*, const u_char*);
// typedef u_int bpf_u_int32;
typedef uint bpf_u_int32;

#define PCAP_ERRBUF_SIZE 256

// struct bpf_insn {
// ushort code;
// uint jt;
// uint jf;
// uint k;
// };

// struct bpf_program {
// uint bf_len;
// struct bpf_insn* bf_insns;
// };

struct pcap {
    struct sfbpf_program fcode;
    int hasFcode;
};

typedef struct pcap pcap_t;
pcap_t handle;

struct pcap_pkthdr {
    struct timeval ts; /* time stamp */
    int32_t caplen;   /* length of portion present */
    int32_t len;      //   [> length this packet (off wire) <]
    // int len;
};

// TODO: might include a bpf.h header file later
// struct bpf_program {
// u_int bf_len;
// struct bpf_insn *bf_insns;
// };

// The instruction data structure
// struct bpf_insn {
// u_short code;
// u_char jt;
// u_char jf;
// bpf_u_int32 k;
// };

const uint8_t* pcap_next(pcap_t* handle, struct pcap_pkthdr* header);
int pcap_inject(pcap_t* handle, const void* data, unsigned long len);

int pcap_set_buffer_size(pcap_t* handle, int size);
void pcap_close(pcap_t* handle);

pcap_t* pcap_create(const char* dev_name, char* error_buffer);
int pcap_activate(pcap_t* handle);

int pcap_loop(pcap_t*, int, pcap_handler, u_char*);
int pcap_compile(pcap_t*, struct sfbpf_program*, const char*, int, bpf_u_int32);
int pcap_setfilter(pcap_t* handle, struct sfbpf_program* filter);

uint bpf_filter(const struct bpf_insn* pc, const u_char* p, uint wirelen, uint buflen);

void dummy_func(int i);
#endif // !SGX_PCAP_H
