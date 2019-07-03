#ifndef SGX_PCAP_H
#define SGX_PCAP_H

#include "stdint.h"
#include <sys/types.h>	/* u_int, u_char etc. */

//#include "time.h"
// You need use your time port instead of this.
#ifdef PCAP_SELF_TIME
struct timeval
{
	__time_t tv_sec;		/* Seconds.  */
	__time_t tv_usec;	/* Microseconds.  */
};
#endif // !timeval


#ifndef USE_ETAP
#define USE_ETAP
#endif

// pcap.h
typedef int pcap_t;
typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr*, const u_char *);

#define PCAP_ERRBUF_SIZE 256

struct pcap_pkthdr {
	struct timeval ts;	/* time stamp */
	uint32_t caplen;	/* length of portion present */
	uint32_t len;	/* length this packet (off wire) */
};

const uint8_t *pcap_next(pcap_t * handle, struct pcap_pkthdr *header);
int	pcap_inject(pcap_t *handle, const void * data, unsigned long len);

int	pcap_set_buffer_size(pcap_t *handle, int size);
void	pcap_close(pcap_t * handle);

pcap_t	*pcap_create(const char *dev_name, char * error_buffer);
int	pcap_activate(pcap_t * handle);

int pcap_loop(pcap_t *, int, pcap_handler, u_char *);
int pcap_compile(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32);



#endif // !SGX_PCAP_H
