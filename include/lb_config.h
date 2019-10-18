#ifndef LB_CONFIG_H
#define LB_CONFIG_H

#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif
#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif

#define MAC_SIZE 16

/* Config for LightBox State Management */
//#define FLOW_STATE_SIZE 5872//432
#define FLOW_STATE_SIZE 7656//11848//104

/* Lightbox simulation mode */
#define LB_SIM

/* Test environment */
#define MAX_FRAME_SIZE 1514

/* etap */
#define SERV_ADDR "10.0.1.11"
#define SERV_PORT "8888"  // the port users will be connecting to
#define BACKLOG 10     // how many pending connections queue will hold

// For etap to send pkt to the next middlebox
#define SEND_ADDR "10.0.1.33"
#define SEND_PORT "8888"

#define DUMMY_KEY "This is a dummy key!"

#define TEST_ITVL 100000

#endif
