
#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

#if defined(__cplusplus)
extern "C" {
#endif

struct etime
{
	unsigned long long s;
	unsigned long long ns;
};


void getTime(struct etime* time);

int diffTime(const struct etime* start, const struct etime* end);

void printf(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
