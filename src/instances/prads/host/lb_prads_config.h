#ifndef LB_PRADS_CONFIG_H
#define LB_PRADS_CONFIG_H

#ifndef CONFDIR
#define CONFDIR "./config/"
#endif

// /* Logging agency */
// #define LOG_BUFFER_CAPACITY 1048576 // 1M
// #define LOG_FLUSH_TIMEOUT 50 // in ms

/* PRADS */
#define GARBAGE_SIZE 296

#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif
#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif

#endif