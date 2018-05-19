#include "log.h"
#include "../prads.h"
#include "../config.h"
#include "../sig.h"
#include "../sys_func.h"
#include "../sg-box/log_agency_t.h"

#define MAX_ENTRY_SIZE 1000
char log_entry[MAX_ENTRY_SIZE];
int log_entry_size;

#define log_char(x) { \
        memcpy(&log_entry[log_entry_size], &x, 1); \
        log_entry_size += 1; }

#define log_short(x) { \
        memcpy(&log_entry[log_entry_size], &x, 2); \
        log_entry_size += 2; }

#define log_int(x) { \
        memcpy(&log_entry[log_entry_size], &x, 4); \
        log_entry_size += 4 ;}

#define log_string(x) { \
        memcpy(&log_entry[log_entry_size], x, strlen(x)); \
        log_entry_size += strlen(x); }

#define log_raw(x, size) { \
        memcpy(&log_entry[log_entry_size], x, size); \
        log_entry_size += size; }

// placeholders
char log_entry_char;
uint16_t log_entry_short;
int log_entry_int;

void log_asset_arp(asset *main) {
    return;
}

void log_asset_os(asset *main, os_asset *os, connection *cxt) {
#if LOG_AGENCY==1
    log_entry_size = 0;

    static char ip_addr_s[INET6_ADDRSTRLEN];
    uint8_t tmp_ttl;

    u_ntop(main->ip_addr, main->af, ip_addr_s);

    /* ip,vlan,port,proto,OS-FP,FP,timstamp*/
    log_raw(ip_addr_s, INET6_ADDRSTRLEN)
    log_entry_short = main->vlan ? ntoh_short(main->vlan) : 0;
    log_short(log_entry_short)
    log_int(os->port)

    switch (os->detection) {
    case CO_SYN:
        log_string("6,SYN")
        break;
    case CO_SYNACK:
        log_string("6,SYNACK")
        break;
    case CO_ACK:
        log_string("6,ACK")
        break;
    case CO_RST:
        log_string("6,RST")
        break;
    case CO_FIN:
        log_string("6,FIN")
        break;
    case CO_UDP:
        log_string("17,UDP")
        break;
    case CO_ICMP:
        // 58 is ICMPv6
        log_string("1,ICMP")
        break;
    case CO_DHCP:
        log_string("17,DHCP")

    default:
        log_string("[!] error in detection type %d (isn't implemented!)\n")
    }

    if (os->raw_fp != NULL) {
        log_string(",[:")
        char *tmp = (char *)bdata(os->raw_fp);
        log_string(tmp)
    }
    else {
        //bstring b = gen_fp_tcp(&os->fp, os->fp.zero_stamp, 0);
        bstring b = gen_fp_tcp(&os->fp, os->uptime, 0);
        os->raw_fp = b;
        char *tmp = (char *)bdata(os->raw_fp);
        log_string(",[:")
        log_string(tmp)
    }
    if (os->fp.os != NULL) log_string(os->fp.os)
    else log_string(":unknown")
    if (os->fp.desc != NULL) log_string(os->fp.desc)
    else log_string(":unknown")

    if (os->fp.mss) log_string(lookup_link(os->fp.mss, 1))
    if (os->uptime) log_string(":uptime:%dhrs")

    tmp_ttl = normalize_ttl(os->ttl) - os->ttl;
    log_int(tmp_ttl)
    log_int(os->last_seen)

    log_to_buffer(log_entry, log_entry_size);
#endif
}

void log_asset_service(asset *main, serv_asset *service, connection *cxt) {
#if LOG_AGENCY==1
    log_entry_size = 0;

    uint8_t tmp_ttl;
    static char ip_addr_s[INET6_ADDRSTRLEN];
    u_ntop(main->ip_addr, main->af, ip_addr_s);
    /* ip,vlan,port,proto,SERVICE,application,timstamp*/
    log_raw(ip_addr_s, INET6_ADDRSTRLEN)

    log_entry_short = main->vlan ? ntoh_short(main->vlan) : 0;
    log_short(log_entry_short)

    log_entry_int = ntoh_short(service->port);
    log_int(log_entry_int)

    log_int(service->proto)

    if (service->role == SC_SERVER) {
        char direction[] = "SERVER,[:]";
        log_string(direction)
        char *tmp = (char*)bdata(service->service);
        log_string(tmp)
        tmp = (char *)bdata(service->application);
        log_string(tmp)
    }
    else {
        char direction[] = "CLIENT,[:]";
        log_string(direction)
        char *tmp = (char*)bdata(service->service);
        log_string(tmp)
        tmp = (char *)bdata(service->application);
        log_string(tmp)
    }

    log_entry_int = normalize_ttl(service->ttl) - service->ttl;
    log_int(log_entry_int)
    log_int(service->last_seen)
    log_entry_char = '\n';
    log_char(log_entry_char)

    log_to_buffer(log_entry, log_entry_size);
#endif
}

void log_rotate(time_t t) {
}

void log_connection(connection *cxt, int cxstatus) {
}