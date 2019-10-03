#include "linux_type_ports.h"

uint16_t ntohs(uint16_t n) {
    return ((((unsigned short)(n) & 0xFF)) << 8) |
        ((((unsigned short)(n) & 0xFF00)) >> 8);
}

uint32_t ntohl(uint32_t n) {
    return  ((((unsigned long)(n) & 0xFF)) << 24) |
        ((((unsigned long)(n) & 0xFF00)) << 8) |
        ((((unsigned long)(n) & 0xFF0000)) >> 8) |
        ((((unsigned long)(n) & 0xFF000000)) >> 24);
}
