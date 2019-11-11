#include "../include/sgx/sgxFunc.h"
#include "../../lb_mos_edge_t.h"

// TODO etap_t.h may not need to include
// #include "../../../../../lb_core/enclave/include/etap_t.h"

FILE * stderr = 0;

int geteuid()
{
	return 0;
}

int usleep(int __useconds)
{
	return 1;
}

void gettimeofday(struct timeval *pTime, void *unused)
{
	struct etime t;
	getTime(&t);
	t.ns /= 1000;
	memcpy(pTime, &t, sizeof(struct timeval));

}

int clock_gettime(int n, struct timespec * pTime)
{
	struct etime t;
	getTime(&t);
	memcpy(pTime, &t, sizeof(struct timespec));
	return 0;
}


int perror(const char * msg)
{
	printf("perror [%10s:%4d]:%s", __FUNCTION__, __LINE__, msg);
	return 1;
}

int exit(int n)
{
	printf("perror [%10s:%4d]:%d", __FUNCTION__, __LINE__, n);
	return 1;
}

int pthread_cond_init(void *a, void *b)
{
	return 0;
}

int pthread_mutex_init(void * a, void * b)
{
	return 0;
}

int pthread_mutex_lock(void * __mutex)
{
	return 0;
}

int pthread_cond_wait(void * __cond, void * __mutex)
{
	return 0;
}


int pthread_mutex_unlock(void* mutex)
{
	return 0;
}

int pthread_cond_signal(void * __cond)
{
	return 0;
}

int pthread_cond_destroy(void * partial)
{
	return 0;
}

int pthread_mutex_destroy(void * partial)
{
	return 0;
}

int pthread_kill(int a, int b)
{
	return 0;
}

int pthread_cond_timedwait(void * p, void * p1, void * p2)
{
	return 0;
}

char * strcpy(char * __dest, const char * __src)
{
	return strncpy(__dest, __src, strlen(__src));
}

int sscanf(const char * __s, const char * __format, ...)
{
	return 1;
}

void ReadConf(const char * fname, struct config * g_configs)
{
	ocall_load_config(fname, (char*)g_configs);
}

pthread_t pthread_self(void)
{
	return 1;
}

unsigned long htonl(unsigned long int h)
{
	return BigLittleSwap32(h);
}

/* unsigned long ntohl(unsigned long int n) */
/* { */
	/* return BigLittleSwap32(n); */
/* } */

unsigned short htons(unsigned short int h)
{
	return BigLittleSwap16(h);
}

/* unsigned short ntohs(unsigned short int n) */
/* { */
	/* return BigLittleSwap16(n); */
/* } */


// bpf.h
#include "../include/bpf/sfbpf.h"
int sfbpf_compile(int snaplen_arg, int linktype_arg, struct sfbpf_program *program, const char *buf, int optimize, sfbpf_u_int32 mask)
{
	char buffer[24];
	int ret;
	ocall_sfbpf_compile(&ret, snaplen_arg, linktype_arg, buffer, buf, optimize, (int)mask);
	memcpy(&program->bf_len, buffer, sizeof(program->bf_len));
	program->bf_insns = malloc(sizeof(struct sfbpf_insn));
	memcpy(program->bf_insns, buffer + sizeof(program->bf_len), sizeof(struct sfbpf_insn));

	return ret;
}
/* u_int sfbpf_filter(const struct sfbpf_insn *pc, const u_char *p, u_int wirelen, u_int buflen) */
/* { */
	/* u_int ret; */
	/* ocall_sfbpf_filter((int*)&ret, (const char*)pc, (const char*)p, wirelen, buflen); */
	/* return ret; */
/* } */
void sfbpf_freecode(struct sfbpf_program *program)
{
	return;
}
void sfbpf_print(struct sfbpf_program *fp, int verbose)
{
	return;
}
