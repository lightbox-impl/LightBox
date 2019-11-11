/* Generic wrapper for LightBox instances */

#ifndef LIGHTBOX_H
#define LIGHTBOX_H

#include "lb_config.h"
#include "etap_u.h"

void lb_init();

typedef void* (*mb_fun_t) (void *);

void lb_run(mb_fun_t);

void lb_deinit();

#endif
