#include "utils_u.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void high_res_time(long *sec, long *nsec)
{
	struct timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
	*sec = time.tv_sec;
	*nsec = time.tv_nsec;
}

double time_elapsed_in_us(long s_sec, long s_ns, long e_sec, long e_ns)
{
	return (e_sec-s_sec)*1000000.0 + (e_ns-s_ns)/1000.0;
}

double time_elapsed_in_ns(long s_sec, long s_ns, long e_sec, long e_ns)
{
	return (e_sec - s_sec)*1000000000.0 + (e_ns - s_ns)*1.0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
    * the input string to prevent buffer overflow.
    */
    printf("%s", str);
}

void ocall_get_time(int *second, int *nanosecond)
{
    struct timespec wall_clock;
    clock_gettime(CLOCK_REALTIME, &wall_clock);
    *second = wall_clock.tv_sec;
    *nanosecond = wall_clock.tv_nsec;
}

void ocall_sleep(long time_ns)
{
    static struct timespec ts = { 0, 0 };
    static struct timespec rem;
    ts.tv_nsec = time_ns;
    nanosleep(&ts, &rem);
}

void ocall_random(uint32_t *r)
{
    uint32_t rlt = rand() % UINT32_MAX;
    *r = rlt;
}