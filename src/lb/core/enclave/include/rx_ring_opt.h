#include "etap_t.h"

int read_pkt(uint8_t* pkt, int* size, timeval_t* ts);

int write_pkt(const uint8_t* pkt, int pkt_size, timeval_t ts);

int read_pkt_nonblock(uint8_t* pkt, int* size, timeval_t* ts);

int write_pkt_nonblock(const uint8_t* pkt, int pkt_size, timeval_t ts);

int read_pkt_tx(uint8_t* pkt, int* size, timeval_t* ts);

int write_pkt_tx(const uint8_t* pkt, int pkt_size, timeval_t ts);

int read_pkt_nonblock_tx(uint8_t* pkt, int* size, timeval_t* ts);

int write_pkt_nonblock_tx(const uint8_t* pkt, int pkt_size, timeval_t ts);
