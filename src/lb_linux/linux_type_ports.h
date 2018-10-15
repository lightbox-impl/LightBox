#ifndef LB_TYPE_PORTS_H
#define LB_TYPE_PORTS_H

#include <time.h>
#include <sys/types.h>
#include <stdint.h>

/*** Start <bits/time.h> ***/
typedef long long __suseconds_t;
/* A time value that is accurate to the nearest
microsecond but also has a range of years.  */
struct timeval
{
    __time_t tv_sec;		/* Seconds.  */
    __suseconds_t tv_usec;	/* Microseconds.  */
};
/*** End <bits/time.h> ***/

/*** Start <netinet/tcp.h> ***/
typedef	u_int32_t tcp_seq;
/*
* TCP header.
* Per RFC 793, September, 1981.
*/
struct tcphdr
{
    __extension__ union
    {
        struct
        {
            u_int16_t th_sport;		/* source port */
            u_int16_t th_dport;		/* destination port */
            tcp_seq th_seq;		/* sequence number */
            tcp_seq th_ack;		/* acknowledgement number */
# if __BYTE_ORDER == __LITTLE_ENDIAN
            u_int8_t th_x2 : 4;		/* (unused) */
            u_int8_t th_off : 4;		/* data offset */
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
            u_int8_t th_off : 4;		/* data offset */
            u_int8_t th_x2 : 4;		/* (unused) */
# endif
            u_int8_t th_flags;
# define TH_FIN	0x01
# define TH_SYN	0x02
# define TH_RST	0x04
# define TH_PUSH	0x08
# define TH_ACK	0x10
# define TH_URG	0x20
            u_int16_t th_win;		/* window */
            u_int16_t th_sum;		/* checksum */
            u_int16_t th_urp;		/* urgent pointer */
        };
        struct
        {
            u_int16_t source;
            u_int16_t dest;
            u_int32_t seq;
            u_int32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN
            u_int16_t res1 : 4;
            u_int16_t doff : 4;
            u_int16_t fin : 1;
            u_int16_t syn : 1;
            u_int16_t rst : 1;
            u_int16_t psh : 1;
            u_int16_t ack : 1;
            u_int16_t urg : 1;
            u_int16_t res2 : 2;
# elif __BYTE_ORDER == __BIG_ENDIAN
            u_int16_t doff : 4;
            u_int16_t res1 : 4;
            u_int16_t res2 : 2;
            u_int16_t urg : 1;
            u_int16_t ack : 1;
            u_int16_t psh : 1;
            u_int16_t rst : 1;
            u_int16_t syn : 1;
            u_int16_t fin : 1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
            u_int16_t window;
            u_int16_t check;
            u_int16_t urg_ptr;
        };
    };
};

# define TCPOPT_EOL		0
# define TCPOPT_NOP		1
# define TCPOPT_MAXSEG		2
# define TCPOLEN_MAXSEG		4
# define TCPOPT_WINDOW		3
# define TCPOLEN_WINDOW		3
# define TCPOPT_SACK_PERMITTED	4		/* Experimental */
# define TCPOLEN_SACK_PERMITTED	2
# define TCPOPT_SACK		5		/* Experimental */
# define TCPOPT_TIMESTAMP	8
# define TCPOLEN_TIMESTAMP	10
# define TCPOLEN_TSTAMP_APPA	(TCPOLEN_TIMESTAMP+2) /* appendix A */

# define TCPOPT_TSTAMP_HDR	\
    (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)

# define TCPI_OPT_TIMESTAMPS	1
# define TCPI_OPT_SACK		2
# define TCPI_OPT_WSCALE	4
# define TCPI_OPT_ECN		8  /* ECN was negociated at TCP session init */
# define TCPI_OPT_ECN_SEEN	16 /* we received at least one packet with ECT */
# define TCPI_OPT_SYN_DATA	32 /* SYN-ACK acked data in SYN sent or rcvd */
/*** End <netinet/tcp.h> ***/

/*** Start <netinet/in.h> ***/
/* Standard well-defined IP protocols.  */
enum
{
    IPPROTO_IP = 0,	   /* Dummy protocol for TCP.  */
#define IPPROTO_IP		IPPROTO_IP
    IPPROTO_ICMP = 1,	   /* Internet Control Message Protocol.  */
#define IPPROTO_ICMP		IPPROTO_ICMP
    IPPROTO_IGMP = 2,	   /* Internet Group Management Protocol. */
#define IPPROTO_IGMP		IPPROTO_IGMP
    IPPROTO_IPIP = 4,	   /* IPIP tunnels (older KA9Q tunnels use 94).  */
#define IPPROTO_IPIP		IPPROTO_IPIP
    IPPROTO_TCP = 6,	   /* Transmission Control Protocol.  */
#define IPPROTO_TCP		IPPROTO_TCP
    IPPROTO_EGP = 8,	   /* Exterior Gateway Protocol.  */
#define IPPROTO_EGP		IPPROTO_EGP
    IPPROTO_PUP = 12,	   /* PUP protocol.  */
#define IPPROTO_PUP		IPPROTO_PUP
    IPPROTO_UDP = 17,	   /* User Datagram Protocol.  */
#define IPPROTO_UDP		IPPROTO_UDP
    IPPROTO_IDP = 22,	   /* XNS IDP protocol.  */
#define IPPROTO_IDP		IPPROTO_IDP
    IPPROTO_TP = 29,	   /* SO Transport Protocol Class 4.  */
#define IPPROTO_TP		IPPROTO_TP
    IPPROTO_DCCP = 33,	   /* Datagram Congestion Control Protocol.  */
#define IPPROTO_DCCP		IPPROTO_DCCP
    IPPROTO_IPV6 = 41,     /* IPv6 header.  */
#define IPPROTO_IPV6		IPPROTO_IPV6
    IPPROTO_RSVP = 46,	   /* Reservation Protocol.  */
#define IPPROTO_RSVP		IPPROTO_RSVP
    IPPROTO_GRE = 47,	   /* General Routing Encapsulation.  */
#define IPPROTO_GRE		IPPROTO_GRE
    IPPROTO_ESP = 50,      /* encapsulating security payload.  */
#define IPPROTO_ESP		IPPROTO_ESP
    IPPROTO_AH = 51,       /* authentication header.  */
#define IPPROTO_AH		IPPROTO_AH
    IPPROTO_MTP = 92,	   /* Multicast Transport Protocol.  */
#define IPPROTO_MTP		IPPROTO_MTP
    IPPROTO_BEETPH = 94,   /* IP option pseudo header for BEET.  */
#define IPPROTO_BEETPH		IPPROTO_BEETPH
    IPPROTO_ENCAP = 98,	   /* Encapsulation Header.  */
#define IPPROTO_ENCAP		IPPROTO_ENCAP
    IPPROTO_PIM = 103,	   /* Protocol Independent Multicast.  */
#define IPPROTO_PIM		IPPROTO_PIM
    IPPROTO_COMP = 108,	   /* Compression Header Protocol.  */
#define IPPROTO_COMP		IPPROTO_COMP
    IPPROTO_SCTP = 132,	   /* Stream Control Transmission Protocol.  */
#define IPPROTO_SCTP		IPPROTO_SCTP
    IPPROTO_UDPLITE = 136, /* UDP-Lite protocol.  */
#define IPPROTO_UDPLITE		IPPROTO_UDPLITE
    IPPROTO_MPLS = 137,    /* MPLS in IP.  */
#define IPPROTO_MPLS		IPPROTO_MPLS
    IPPROTO_RAW = 255,	   /* Raw IP packets.  */
#define IPPROTO_RAW		IPPROTO_RAW
    IPPROTO_MAX
};

/* Internet address.  */
typedef uint32_t in_addr_t;
struct in_addr
{
    in_addr_t s_addr;
};

/* IPv6 address */
struct in6_addr
{
    union
    {
        uint8_t	__u6_addr8[16];
#ifdef __USE_MISC
        uint16_t __u6_addr16[8];
        uint32_t __u6_addr32[4];
#endif
    } __in6_u;
#define s6_addr			__in6_u.__u6_addr8
#ifdef __USE_MISC
# define s6_addr16		__in6_u.__u6_addr16
# define s6_addr32		__in6_u.__u6_addr32
#endif
};

/*
* Structure of an internet header, naked of options.
*/
struct ip
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl : 4;		/* header length */
    unsigned int ip_v : 4;		/* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v : 4;		/* version */
    unsigned int ip_hl : 4;		/* header length */
#endif
    u_int8_t ip_tos;			/* type of service */
    u_short ip_len;			/* total length */
    u_short ip_id;			/* identification */
    u_short ip_off;			/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    u_int8_t ip_ttl;			/* time to live */
    u_int8_t ip_p;			/* protocol */
    u_short ip_sum;			/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
};

uint16_t ntohs(uint16_t n);
uint32_t ntohl(uint32_t n);
/*** End <netinet/in.h> ***/

/*** Start <netinet/ip6.h> ***/
struct ip6_hdr
{
    union
    {
        struct ip6_hdrctl
        {
            uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
                                     20 bits flow-ID */
            uint16_t ip6_un1_plen;   /* payload length */
            uint8_t  ip6_un1_nxt;    /* next header */
            uint8_t  ip6_un1_hlim;   /* hop limit */
        } ip6_un1;
        uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
    } ip6_ctlun;
    struct in6_addr ip6_src;      /* source address */
    struct in6_addr ip6_dst;      /* destination address */
};

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim
/*** End <netinet/ip6.h> ***/

/*** Start <net/ethernet.h> ***/
/** <linux/if_ether.h> **/
#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
/* 10Mb/s ethernet header */
struct ether_header
{
    u_int8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
    u_int8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
    u_int16_t ether_type;		        /* packet type ID field	*/
} __attribute__((__packed__));
/*** End <net/ethernet.h> ***/

#endif
