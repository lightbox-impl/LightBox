#ifndef SGX_PCAP_H
#define SGX_PCAP_H

#include "stdint.h"

//#include "time.h"
#include "../libmOS/trusted/src/include/sgx/sgxFunc.h"

#ifndef USE_ETAP
#define USE_ETAP
#endif

// pcap.h
typedef int pcap_t;

#define PCAP_ERRBUF_SIZE 256

struct pcap_pkthdr {
	struct timeval ts;	/* time stamp */
	uint32_t caplen;	/* length of portion present */
	uint32_t len;	/* length this packet (off wire) */
};

const uint8_t *pcap_next(pcap_t * handle, struct pcap_pkthdr *header);
int	pcap_inject(pcap_t *handle, const void * data, size_t len);

int	pcap_set_buffer_size(pcap_t *handle, int size);
void	pcap_close(pcap_t * handle);

pcap_t	*pcap_create(const char *dev_name, char * error_buffer);
int	pcap_activate(pcap_t * handle);




#endif // !SGX_PCAP_H
