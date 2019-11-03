#ifndef SGX_FUNC_H
#define SGX_FUNC_H


# define __WORDSIZE	64

#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include "../../../Enclave.h"

#include "sgxdef.h"

/*unistd.h*/
int geteuid();
int usleep(int __useconds);

/* Internet address.  */
typedef uint32_t in_addr_t;
struct in_addr
{
	in_addr_t s_addr;
};

typedef uint32_t socklen_t;



/* POSIX.1g specifies this type name for the `sa_family' member.  */
typedef unsigned short int sa_family_t;

/* This macro is used to declare the initial common members
of the data types used for socket addresses, `struct sockaddr',
`struct sockaddr_in', `struct sockaddr_un', etc.  */

#define	__SOCKADDR_COMMON(sa_prefix) \
  sa_family_t sa_prefix##family

#define __SOCKADDR_COMMON_SIZE	(sizeof (unsigned short int))

struct sockaddr
{
	__SOCKADDR_COMMON(sa_);	/* Common data: address family and length.  */
	char sa_data[14];		/* Address data.  */
};

struct iovec
{
	void *iov_base;	/* Pointer to data.  */
	size_t iov_len;	/* Length of data.  */
};


//#include "sys/time.h"
// struct timeval
// {
	// __time_t tv_sec;		[> Seconds.  <]
	// __time_t tv_usec;	[> Microseconds.  <]
// };

struct timespec
{
	__time_t tv_sec;		/* Seconds.  */
	__time_t tv_nsec;	/* Nanoseconds.  */
};

void gettimeofday(struct timeval*, void*);

int clock_gettime(int n, struct timespec* time);


# define timercmp(a, b, CMP) 						      \
  (((a)->tv_sec == (b)->tv_sec) ? 					      \
   ((a)->tv_usec CMP (b)->tv_usec) : 					      \
   ((a)->tv_sec CMP (b)->tv_sec))

#define TIMEVAL_LT(a, b)			\
	timercmp(a, b, <)


//#include <netinet/in.h>


/* Type to represent a port.  */
typedef uint16_t in_port_t;

typedef uint16_t __sum16;

struct sockaddr_in
{
	__SOCKADDR_COMMON(sin_);
	in_port_t sin_port;			/* Port number.  */
	struct in_addr sin_addr;		/* Internet address.  */

									/* Pad to size of `struct sockaddr'.  */
	unsigned char sin_zero[sizeof(struct sockaddr) -
		__SOCKADDR_COMMON_SIZE -
		sizeof(in_port_t) -
		sizeof(struct in_addr)];
};



typedef int FILE; 

extern FILE * stderr;

typedef char *__caddr_t;

struct ifmap
{
	unsigned long int mem_start;
	unsigned long int mem_end;
	unsigned short int base_addr;
	unsigned char irq;
	unsigned char dma;
	unsigned char port;
	/* 3 bytes spare */
};

struct ifreq
{
# define IFHWADDRLEN	6
# define IFNAMSIZ	IF_NAMESIZE
	union
	{
		char ifrn_name[IFNAMSIZ];	/* Interface name, e.g. "en0".  */
	} ifr_ifrn;

	union
	{
		struct sockaddr ifru_addr;
		struct sockaddr ifru_dstaddr;
		struct sockaddr ifru_broadaddr;
		struct sockaddr ifru_netmask;
		struct sockaddr ifru_hwaddr;
		short int ifru_flags;
		int ifru_ivalue;
		int ifru_mtu;
		struct ifmap ifru_map;
		char ifru_slave[IFNAMSIZ];	/* Just fits the size */
		char ifru_newname[IFNAMSIZ];
		__caddr_t ifru_data;
	} ifr_ifru;
};

struct iphdr
{
	unsigned int ihl : 4;
	unsigned int version : 4;
	u_int8_t tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t check;
	u_int32_t saddr;
	u_int32_t daddr;
	/*The options start here. */
};


struct tcphdr {
	u_int16_t	source;
	u_int16_t	dest;
	u_int32_t	seq;
	u_int32_t	ack_seq;
	u_int16_t	res1 : 4,
		doff : 4,
		fin : 1,
		syn : 1,
		rst : 1,
		psh : 1,
		ack : 1,
		urg : 1,
		ece : 1,
		cwr : 1;
	u_int16_t	window;
	u_int16_t	check;
	u_int16_t	urg_ptr;
};



#define BigLittleSwap16(A)  ((((unsigned short)(A) & 0xff00) >> 8) | \
                            (((unsigned short)(A) & 0x00ff) << 8))
#define BigLittleSwap32(A)  ((((unsigned long )(A) & 0xff000000) >> 24) | \
                            (((unsigned long )(A) & 0x00ff0000) >> 8) | \
                            (((unsigned long )(A) & 0x0000ff00) << 8) | \
                            (((unsigned long )(A) & 0x000000ff) << 24))
unsigned long htonl(unsigned long int h);
unsigned long ntohl(unsigned long int n);
unsigned short htons(unsigned short int h);
unsigned short ntohs(unsigned short int n);


struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	unsigned short		h_proto;		/* packet type ID field	*/
} __attribute__((packed));

//netdb.h
struct hostent
{
	char *h_name;			/* Official name of host.  */
	char **h_aliases;		/* Alias list.  */
	int h_addrtype;		/* Host address type.  */
	int h_length;			/* Length of address.  */
	char **h_addr_list;		/* List of addresses from name server.  */
# define	h_addr	h_addr_list[0] /* Address, for backward compatibility.*/
};

struct netent
{
	char *n_name;			/* Official name of network.  */
	char **n_aliases;		/* Alias list.  */
	int n_addrtype;		/* Net address type.  */
	uint32_t n_net;		/* Network number.  */
};

/* Description of data base entry for a single service.  */
struct servent
{
	char *s_name;			/* Official service name.  */
	char **s_aliases;		/* Alias list.  */
	int s_port;			/* Port number.  */
	char *s_proto;		/* Protocol to use.  */
};


/* Description of data base entry for a single service.  */
struct protoent
{
	char *p_name;			/* Official protocol name.  */
	char **p_aliases;		/* Alias list.  */
	int p_proto;			/* Protocol number.  */
};






//#include <stdio.h>
//extern int stderr;
//int fprintf(int __stream, const char *__fmt, ...);
int perror(const char* msg);
int exit(int n);


//#include <pthread.h>
typedef int pthread_mutex_t;
typedef int pthread_cond_t;
typedef int pthread_t;
typedef int sem_t;
typedef int pthread_spinlock_t;

int pthread_cond_init(void*, void*);
int pthread_mutex_init(void* a, void* b);
int pthread_mutex_lock(void*__mutex);
int pthread_cond_wait(void* __cond, void* __mutex);
int pthread_mutex_unlock(void* mutex);
int pthread_cond_signal(void *__cond);
int pthread_cond_destroy(void* partial);
int pthread_mutex_destroy(void* partial);
int pthread_kill(int a, int b);
int pthread_cond_timedwait(void* p, void* p1, void* p2);




#if LightBox == 1 
// LightBox always need Etap
#ifndef DUSE_ETAP
#define DUSE_ETAP
#endif // !DUSE_ETAP
#endif




char *strcpy(char * __dest, const char * __src);
int sscanf(const char * __s,const char * __format, ...);


#include "../../include/config.h"
void ReadConf(const char *fname, struct config* g_configs);

#endif
