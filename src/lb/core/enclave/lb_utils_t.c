//#include "sgx_trts.h"

#include "lb_utils_t.h"
#include "lb_core_edge_t.h"

#include <stdio.h>      /* vsnprintf */

/*
* printf:
*   Invokes OCALL to display the enclave buffer to the terminal.
*/
void eprintf(const char *fmt, ...)
{
  char buf[BUFSIZ] = { '\0' };
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  ocall_print_string(buf);
}
