#ifndef SGBOX_CONFIG_H
#define SGBOX_CONFIG_H

/* common */
#define MAC_LEN 16

#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif
#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif

/* secure ferry config */
#define FERRY_UNIT 1000 //
#define PHEADER_LEN 24// sizeof(pcap_pkthdr);
#define MAX_PACKET_LEN 1604 // SNAPLENGTH;

/* state orchestrator */
enum state_cache_status {
    state_cache_invalid = -1,
    state_cache_not_allocated = -2
};

#define STATE_ENTRY_SIZE 512
#define STATE_ENTRY_DATA_SIZE 432
#define STATE_ENTRY_ID_SIZE 16 // sizeof(flow_id)
#define STATE_CACHE_CAPACITY 16384

#define LKUP_BUCKET_SIZE 31337 //65535// 31337 // magic number from PRADS

#define BUNDLE_CAPACITY FERRY_UNIT // <= FERRY_UNIT

#define FLOW_TIMEOUT 300
#define EXPR_CHECK_TIMEOUT 60

/* Logging agency */
#define LOG_BUFFER_CAPACITY 1048576 // 1M
#define LOG_FLUSH_TIMEOUT 50 // in ms

/* memory pool */
#define MEM_POOL_CAPACITY 1000000

/* PRADS */
#define GARBAGE_SIZE 296

/* Test */
#define TEST_MAX_PKT_COUNT 50000000
#define TEST_MAX_STATE_COUNT 10000000
#endif