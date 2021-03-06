#ifndef LB_CONFIG_H
#define LB_CONFIG_H

#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif
#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)

#endif
#define MAC_SIZE 16

/* Lightbox simulation mode */
#define LB_SIM

/* Test environment */
#define MAX_FRAME_SIZE 1514

/* etap */
#define SERV_ADDR "10.0.1.11"
//#define SERV_ADDR "127.0.0.1"
#define SERV_PORT "8888" // the port users will be connecting to
#define BACKLOG 10       // how many pending connections queue will hold

#define DUMMY_KEY "This is a dummy key!"

#endif
