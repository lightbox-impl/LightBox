#ifndef UTILS_U_H
#define UTILS_U_H

void high_res_time(long *sec, long *nsec);

double time_elapsed_in_us(long s_sec, long s_ns, long e_sec, long e_ns);

double time_elapsed_in_ns(long s_sec, long s_ns, long e_sec, long e_ns);

#endif
