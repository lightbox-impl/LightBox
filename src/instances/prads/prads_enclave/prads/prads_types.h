#ifndef PRADS_TYPE_H
#define PRADS_TYPE_H

#include <stdint.h>
#include <time.h>
#include <sys/types.h>

/* Internet address.  */
typedef uint32_t in_addr_t;
struct in_addr
{
  in_addr_t s_addr;
};

#ifndef __USE_KERNEL_IPV6_DEFS
/* IPv6 address */
struct in6_addr
{
  union
  {
    uint8_t	__u6_addr8[16];
#if defined __USE_MISC || defined __USE_GNU
    uint16_t __u6_addr16[8];
    uint32_t __u6_addr32[4];
#endif
  } __in6_u;
#define s6_addr			__in6_u.__u6_addr8
#if defined __USE_MISC || defined __USE_GNU
# define s6_addr16		__in6_u.__u6_addr16
# define s6_addr32		__in6_u.__u6_addr32
#endif
};
#endif /* !__USE_KERNEL_IPV6_DEFS */

#ifdef MSDOS /* must be 32-bit */
typedef long          bpf_int32;
typedef unsigned long bpf_u_int32;
#else
typedef	int bpf_int32;
typedef	u_int bpf_u_int32;
#endif

/* From <bits/types.h> */
typedef long int __suseconds_t;
/* A time value that is accurate to the nearest
microsecond but also has a range of years.  */
typedef struct _timeval
{
  __time_t tv_sec;		/* Seconds.  */
  __suseconds_t tv_usec;	/* Microseconds.  */
} timeval;

/*
* Generic per-packet information, as supplied by libpcap.
*
* The time stamp can and should be a "struct timeval", regardless of
* whether your system supports 32-bit tv_sec in "struct timeval",
* 64-bit tv_sec in "struct timeval", or both if it supports both 32-bit
* and 64-bit applications.  The on-disk format of savefiles uses 32-bit
* tv_sec (and tv_usec); this structure is irrelevant to that.  32-bit
* and 64-bit versions of libpcap, even if they're on the same platform,
* should supply the appropriate version of "struct timeval", even if
* that's not what the underlying packet capture mechanism supplies.
*/
typedef struct _pcap_pkthdr {
  timeval ts;	/* time stamp */
  bpf_u_int32 caplen;	/* length of portion present */
  bpf_u_int32 len;	/* length this packet (off wire) */
} pcap_pkthdr;

#define PCAP_ERRBUF_SIZE              256

/*
* As returned by the pcap_stats()
*/
struct pcap_stat {
  u_int ps_recv;		/* number of packets received */
  u_int ps_drop;		/* number of packets dropped */
  u_int ps_ifdrop;	/* drops by interface -- only supported on some platforms */
#ifdef WIN32
  u_int bs_capt;		/* number of packets that reach the application */
#endif /* WIN32 */
};

/* From socket.h */
#define	PF_INET		2	/* IP protocol family.  */
#define	AF_INET		PF_INET
#define	PF_INET6	10	/* IP version 6.  */
#define	AF_INET6	PF_INET6

/* From in.h */
#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46
#endif