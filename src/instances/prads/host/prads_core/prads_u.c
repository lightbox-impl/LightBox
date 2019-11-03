/*
** This file is a part of PRADS.
**
** Copyright (C) 2009, Redpill Linpro
** Copyright (C) 2009, Edward Fjellskål <edward.fjellskaal@redpill-linpro.com>
** Copyright (C) 2009, Kacper Wysocki   <kacper.wysocki@redpill-linpro.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your opt
ion) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

/*  I N C L U D E S  *********************************************************/
#ifdef __APPLE__
#include <sys/malloc.h>
#elseif !defined(__FreeBSD__)
#include <malloc.h>
#endif

#include "prads.h"
#include "config.h"
#include "sys_func.h"
#include "servicefp/servicefp.h"
#include "sig.h"
#include "mac.h"
#include "dhcp.h"

// #if LOG_AGENCY==1
// #include "../sg-box/log_agency_u.h"
// #endif

#define ARGS "C:c:b:d:e:E:Dg:hi:p:r:u:va:l:L:f:qtxs:OXFRMSAKUTIZtHPB"

/*  G L O B A L S  *** (or candidates for refactoring, as we say)***********/
globalconfig config;
extern int optind, opterr, optopt; // getopt()
extern FILE *batch_latency_logger;

time_t tstamp;
servicelist *services[MAX_PORTS];
int inpacket, gameover, intr_flag;
int nets = 1;

fmask network[MAX_NETS];

// static strings for comparison
// - this is lame and should be a flag!
struct tagbstring tUNKNOWN = bsStatic("unknown");
bstring UNKNOWN = & tUNKNOWN;

/*  I N T E R N A L   P R O T O T Y P E S  ***********************************/
static void usage();
int  parse_network (char *net_s, struct in6_addr *network);
int  parse_netmask (char *f, int type, struct in6_addr *netmask);
void parse_nets(const char *s_net, fmask *network);

/* F U N C T I O N S  ********************************************************/
int parse_network (char *net_s, struct in6_addr *network)
{
    int type;
    char *t;
    if (NULL != (t = strchr(net_s, ':'))) {
        type = AF_INET6;
        if (!inet_pton(type, net_s, network)) {
            perror("parse_nets6");
            return -1;
        }
        dlog("Network6 %-36s \t -> %08x:%08x:%08x:%08x\n",
               net_s,
               IP6ADDR(network)
              );
    } else {
        type = AF_INET;
        if (!inet_pton(type, net_s, &IP4ADDR(network))) {
            perror("parse_nets");
            return -1;
        }
        dlog("Network4 %16s \t-> 0x%08x\n", net_s, IP4ADDR(network));
    }
    return type;
}

int parse_netmask (char *f, int type, struct in6_addr *netmask)
{
    char *t;
    uint32_t mask;
    char output[MAX_NETS];
    // parse netmask into host order
    if (type == AF_INET && (t = strchr(f, '.')) > f && t-f < 4) {
        // full ipv4 netmask : dotted quads
        inet_pton(type, f, &IP4ADDR(netmask));
        dlog("mask 4 %s \t-> 0x%08x\n", f, IP4ADDR(netmask));
    } else if (type == AF_INET6 && NULL != (t = strchr(f, ':'))) {
        // full ipv6 netmasĸ
        dlog("mask 6 %s\n", f);
        inet_pton(type, f, netmask);
    } else {
        // cidr form
        sscanf(f, "%u", &mask);
        dlog("cidr  %u \t-> ", mask);
        if (type == AF_INET) {
            uint32_t shift = 32 - mask;
            if (mask)
                IP4ADDR(netmask) = ntohl( ((unsigned int)-1 >> shift)<< shift);
            else
                IP4ADDR(netmask) = 0;

            dlog("0x%08x\n", IP4ADDR(netmask));
        } else if (type == AF_INET6) {
            //mask = 128 - mask;
            int j = 0;
            memset(netmask, 0, sizeof(struct in6_addr));

            while (mask > 8) {
                netmask->s6_addr[j++] = 0xff;
                mask -= 8;
            }
            if (mask > 0) {
                netmask->s6_addr[j] = -1 << (8 - mask);
            }
#ifdef DEBUG
            inet_ntop(type, &IP4ADDR(netmask), output, MAX_NETS);
            dlog("mask: %s\n", output);
#endif
            // pcap packets are in host order.
            IP6ADDR0(netmask) = ntohl(IP6ADDR0(netmask));
            IP6ADDR1(netmask) = ntohl(IP6ADDR1(netmask));
            IP6ADDR2(netmask) = ntohl(IP6ADDR2(netmask));
            IP6ADDR3(netmask) = ntohl(IP6ADDR3(netmask));

        }
    }
    return 0;
}

/* parse strings of the form ip/cidr or ip/mask like:
 * "10.10.10.10/255.255.255.128,10.10.10.10/25" and 
 * "dead:be:eef2:1aa::b5ff:fe96:37a2/64,..."
 *
 * an IPv6 address is 8 x 4 hex digits. missing digits are padded with zeroes.
 */
void parse_nets(const char *s_net, fmask *network)
{
    /* f -> for processing
     * p -> frob pointer
     * t -> to pointer */
    char *f, *p, *snet;
    int type, len, i = 0;
    struct in6_addr network6, netmask6;

    // snet is a mutable copy of the args,freed @ nets_end
    len = strlen(s_net);
    //snet = calloc(1, len);
    snet = calloc(1, (len + 1)); /* to have \0 too :-) */
    strncpy(snet, s_net, len);
    f = snet;
    while (f && 0 != (p = strchr(f, '/'))) {
        // convert network address
        *p = '\0';
        type = parse_network(f, &network6);
        if (type != AF_INET && type != AF_INET6) {
            perror("parse_network");
            goto nets_end;
        }
        // convert netmask
        f = p + 1;
        p = strchr(f, ',');
        if (p) {
            *p = '\0';
        }
        parse_netmask(f, type, &netmask6);

        // poke in the gathered information
        switch (type) {
            case AF_INET:
            case AF_INET6:
                network[i].addr = network6;
                network[i].mask = netmask6;
                network[i].type = type;
                break;

            default:
                fprintf(stderr, "parse_nets: invalid address family!\n");
                goto nets_end;
        }

        nets = ++i;

        if (i > MAX_NETS) {
            elog("Max networks reached, stopped parsing at %d nets.\n", i-1);
            goto nets_end;
        }


        // continue parsing at p, which might point to another network range
        f = p;
        if(p) f++;
    }
nets_end:
    free(snet);
    return;
}

void game_over(uint64_t cxtrackerid)
{
    if (inpacket == 0) {
        // handled within enclave
        //end_sessions(); /* Need to have correct human output when reading -r pcap */
        //clear_asset_list();
        // end_all_sessions();
        del_known_services();
        del_signature_lists();
        unload_tcp_sigs();
        //end_logging();
        if(!ISSET_CONFIG_QUIET(config)){
          print_prads_stats(cxtrackerid);
           // if(!config.pcap_file)
           //     print_pcap_stats();
        }
        // if (config.handle != NULL) {
        //   pcap_close(config.handle);
        // }
        if (ISSET_CONFIG_SYSLOG(config)) closelog();
        free_config();
        olog("[*] prads ended.\n");
        exit(0);
    }
    intr_flag = 1;
}

void print_prads_stats(uint64_t cxtrackerid)
{
    //extern uint64_t cxtrackerid; // cxt.c
    olog("-- prads:\n");
    olog("-- Total packets received from libpcap    :%12u\n",config.pr_s.got_packets);
    olog("-- Total Ethernet packets received        :%12u\n",config.pr_s.eth_recv);
    olog("-- Total VLAN packets received            :%12u\n",config.pr_s.vlan_recv);
    olog("-- Total ARP packets received             :%12u\n",config.pr_s.arp_recv);
    olog("-- Total IPv4 packets received            :%12u\n",config.pr_s.ip4_recv);
    olog("-- Total IPv6 packets received            :%12u\n",config.pr_s.ip6_recv);
    olog("-- Total Other link packets received      :%12u\n",config.pr_s.otherl_recv);
    olog("-- Total IPinIPv4 packets received        :%12u\n",config.pr_s.ip4ip_recv);
    olog("-- Total IPinIPv6 packets received        :%12u\n",config.pr_s.ip6ip_recv);
    olog("-- Total GRE packets received             :%12u\n",config.pr_s.gre_recv);
    olog("-- Total TCP packets received             :%12u\n",config.pr_s.tcp_recv);
    olog("-- Total UDP packets received             :%12u\n",config.pr_s.udp_recv);
    olog("-- Total ICMP packets received            :%12u\n",config.pr_s.icmp_recv);
    olog("-- Total Other transport packets received :%12u\n",config.pr_s.othert_recv);
    olog("--\n");
    olog("-- Total sessions tracked                 :%12lu\n", cxtrackerid);
    olog("-- Total assets detected                  :%12u\n",config.pr_s.assets);
    olog("-- Total TCP OS fingerprints detected     :%12u\n",config.pr_s.tcp_os_assets);
    olog("-- Total UDP OS fingerprints detected     :%12u\n",config.pr_s.udp_os_assets);
    olog("-- Total ICMP OS fingerprints detected    :%12u\n",config.pr_s.icmp_os_assets);
    olog("-- Total DHCP OS fingerprints detected    :%12u\n",config.pr_s.dhcp_os_assets);
    olog("-- Total TCP service assets detected      :%12u\n",config.pr_s.tcp_services);
    olog("-- Total TCP client assets detected       :%12u\n",config.pr_s.tcp_clients);
    olog("-- Total UDP service assets detected      :%12u\n",config.pr_s.udp_services);
    olog("-- Total UDP client assets detected       :%12u\n",config.pr_s.udp_clients);
}


static void usage()
{
    olog("USAGE:\n");
    olog(" $ prads [options]\n");
    olog("\n");
    olog(" OPTIONS:\n");
    olog("\n");
    olog(" -i <iface>      Network device <iface> (default: eth0).\n");
    olog(" -r <file>       Read pcap <file>.\n");
    olog(" -c <file>       Read config from <file>\n");
    olog(" -b <filter>     Apply Berkeley packet filter <filter>.\n");
    olog(" -u <user>       Run as user <user>   (Default: uid 1)\n");
    olog(" -g <group>      Run as group <group> (Default: gid 1)\n");
    olog(" -d              Do not drop privileges.\n");
    olog(" -a <nets>       Specify home nets (eg: '192.168.0.0/25,10.0.0.0/255.0.0.0').\n");
    olog(" -D              Daemonize.\n");
    olog(" -p <pidfile>    Name of pidfile - inside chroot\n");
    olog(" -l <file>       Log assets to <file> (default: '%s')\n", config.assetlog);
    olog(" -f <FIFO>       Log assets to <FIFO>\n");
    olog(" -B              Log connections to ringbuffer\n");
    olog(" -C <dir>        Chroot into <dir> before dropping privs.\n");
    olog(" -XFRMSAK        Flag picker: X - clear flags, F:FIN, R:RST, M:MAC, S:SYN, A:ACK, K:SYNACK\n");
    olog(" -UTtI           Service checks: U:UDP, T:TCP-server, I:ICMP, t:TCP-cLient\n");
    olog(" -P              DHCP fingerprinting.\n");
    olog(" -s <snaplen>    Dump <snaplen> bytes of each payload.\n");
    olog(" -v              Verbose output - repeat for more verbosity.\n");
    olog(" -q              Quiet - try harder not to produce output.\n");
    olog(" -L <dir>        log cxtracker type output to <dir> (will be owned by <uid>).\n");
    olog(" -O              Connection tracking [O]utput - per-packet!\n");
    olog(" -x              Conne[x]ion tracking output  - New, expired and ended.\n");
    olog(" -Z              Passive DNS (Experimental).\n");
    olog(" -H              DHCP fingerprinting (Expermiental).\n");
    olog(" -h              This help message.\n");
}

// int load_bpf(globalconfig* conf, const char* file)
// {
//     int sz, i;
//     FILE* fs;
//     char* lineptr;
//     struct stat statbuf;
//     fs = fopen(file, "r");
//     if(!fs){
//         perror("bpf file");
//         return 1;
//     }
//     if(fstat(fileno(fs), &statbuf)){
//         perror("oh god my eyes!");
//         fclose(fs);
//         return 2;
//     }
//     sz = statbuf.st_size; 
//     if(conf->bpff) free(conf->bpff);
//     if(!(conf->bpff = calloc(sz, 1))){
//         perror("mem alloc");
//         fclose(fs);
//         return 3;
//     }
//     lineptr = conf->bpff;
//     // read file but ignore comments and newlines
//     while(fgets(lineptr, sz-(conf->bpff-lineptr), fs)) {
//         // skip spaces
//         for(i=0;;i++) 
//             if(lineptr[i] != ' ')
//                break;
//         // scan ahead and kill comments
//         for(i=0;lineptr[i];i++)
//             switch(lineptr[i]){
//                 case '#':                // comment on the line
//                     lineptr[i] = '\n';   // end line here
//                     lineptr[i+1] = '\0'; // ends outer loop & string
//                 case '\n':               // end-of-line
//                 case '\0':               // end-of-string
//                     break;
//             }
//         if(i<=1) continue;               // empty line
//         lineptr = lineptr+strlen(lineptr);
//     }
//     fclose(fs);
//     olog("[*] BPF file\t\t %s (%d bytes read)\n", conf->bpf_file, sz);
//     if(config.verbose) olog("BPF: { %s}\n", conf->bpff);
//     return 0;
// }


int prads_initialize(globalconfig *conf)
{
    /* Do this before privilege drops */
    //batch_latency_logger = fopen(conf->batch_latency_file, "wb");
    //if (batch_latency_logger == NULL) {
    //    printf("Fail to open batch latency log file: %s \n", conf->batch_latency_file);
    //    abort();
    //}

    //if (conf->bpf_file) {
    //    if(load_bpf(conf, conf->bpf_file)){
    //       elog("[!] Failed to load bpf from file.\n");
    //    }
    //}
    //if (conf->pcap_file) {
    //    struct stat sb;
    //    if(stat(conf->pcap_file, &sb) || !sb.st_size) {
    //       elog("[!] '%s' not a pcap. Bailing.\n", conf->pcap_file);
    //       exit(1);
    //    }

    //    /* Read from PCAP file specified by '-r' switch. */
    //    olog("[*] Reading from file %s\n", conf->pcap_file);
    //    if (!(conf->handle = pcap_open_offline(conf->pcap_file, conf->errbuf))) {
    //        olog("[*] Unable to open %s.  (%s)\n", conf->pcap_file, conf->errbuf);
    //    } 

    //} else {
    //    int uid, gid;
    //    if(conf->drop_privs_flag) {
    //        if(getuid() != 0) {
    //            conf->drop_privs_flag = 0;
    //            elog("[!] Can't drop privileges, not root.\n");
    //        } else {
    //            /* getting numerical ids before chroot call */
    //            gid = get_gid(conf->group_name);
    //            uid = get_uid(conf->user_name, &gid);
    //            if(!gid){
    //                elog("[!] Problem finding user %s group %s\n", conf->user_name, conf->group_name);
    //                exit(ENOENT);
    //            }
    //            if (gid && getuid() == 0 && initgroups(conf->user_name, gid) < 0) {
    //                elog("[!] Unable to init group names (%s/%u)\n", conf->user_name, gid);
    //            }
    //        }
    //    }

    //    /* * look up an available device if non specified */
    //    if (conf->dev == 0x0)
    //        conf->dev = pcap_lookupdev(conf->errbuf);
    //    if (conf->dev){
    //        *conf->errbuf = 0;
    //    }else{
    //        elog("[*] Error looking up device: '%s', try setting device with -i flag.\n", conf->errbuf);
    //        exit(1);
    //    }

    //    olog("[*] Device: %s\n", conf->dev);
    //
    //    // disable promiscuous mode
    //    if ((conf->handle = pcap_open_live(conf->dev, SNAPLENGTH, 0, 500, conf->errbuf)) == NULL) {
    //        elog("[!] Error pcap_open_live: %s \n", conf->errbuf);
    //        exit(1);
    //    }
    //    /* * B0rk if we see an error... */
    //    if (strlen(conf->errbuf) > 0) {
    //        elog("[*] Error errbuf: %s \n", conf->errbuf);
    //        exit(1);
    //    }

    //    if(conf->chroot_dir){

    //        olog("[*] Chrooting to dir '%s'..\n", conf->chroot_dir);
    //        if(set_chroot()){
    //            elog("[!] failed to chroot\n");
    //            exit(1);
    //        }
    //    }
    //    /* gotta create/chown pidfile before dropping privs */
    //    if(conf->pidfile)
    //        touch_pid_file(conf->pidfile, uid, gid);

    //    if (conf->drop_privs_flag && ( uid || gid)) {
    //        olog("[*] Dropping privileges to %s:%s...\n", 
    //           conf->user_name?conf->user_name:"", conf->group_name?conf->group_name:"");
    //        drop_privs(uid, gid);
    //    }
    //    /* NOTE: we init sancp-style conntrack-logging after dropping privs,
    //     * because the logs need rotation after dropping privs */
    //    /*if(config.cxtlogdir[0] != '\0'){
    //       static char log_prefix[PATH_MAX];
    //       snprintf(log_prefix, PATH_MAX, "%sstats.%s", 
    //                config.cxtlogdir, config.dev? config.dev : "pcap");
    //       int rc = init_logging(LOG_SGUIL, log_prefix, 0);
    //       if (rc)
    //          perror("Logging to sguil output failed!");
    //    }*/

    //    if(conf->pidfile){
    //       if (!is_valid_path(conf->pidfile)){
    //          elog("[!] Pidfile '%s' is not writable.\n", conf->pidfile);
    //          exit(ENOENT);
    //       }
    //    }
    //    if (conf->daemon_flag) {
    //        olog("[*] Daemonizing...\n");
    //        daemonize(NULL);
    //    }
    //    if (conf->pidfile) {
    //       int rc;
    //       if((rc=create_pid_file(conf->pidfile))) {
    //           elog("[!] pidfile error, wrong permissions or prads already running? %s: %s\n", conf->pidfile, strerror(rc));
    //           exit(ENOENT);
    //       }
    //    }
    //}
    return 0;
}

void prads_version(void)
{
    olog("[*] prads %s\n", VERSION);
    // olog("    Using %s\n", pcap_lib_version());
    // olog("    Using PCRE version %s\n", pcre_version());
}

/* magic main (of the original PRADS) */
int init_prads_host(int argc, char *argv[])
{
    int32_t rc = 0;
    int ch = 0, verbose_already = 0;

    vlog(2, "%08x =? %08x, endianness: %s\n\n", 0xdeadbeef, ntohl(0xdeadbeef), (0xdead == ntohs(0xdead)?"big":"little") );

    memset(&config, 0, sizeof(globalconfig));
    set_default_config_options(&config);

    inpacket = gameover = intr_flag = 0;

    /*signal(SIGTERM, game_over);
    signal(SIGINT, game_over);
    signal(SIGQUIT, game_over);
    signal(SIGALRM, set_end_sessions);
    signal(SIGHUP, reparse_conf);
    signal(SIGUSR1, set_end_sessions);*/
#ifdef DEBUG
    //signal(SIGUSR1, cxt_log_buckets);
#endif

    // do first-pass args parse for commandline-passed config file
    opterr = 0;
    while ((ch = getopt(argc, argv, ARGS)) != -1)
        switch (ch) {
        case 'c':
            config.file = optarg;
            break;
        case 'v':
            config.verbose++;
            break;
        case 'q':
            config.cflags |= CONFIG_QUIET;
            break;
        case 'h':
            usage();
            exit(0);
        default:
            break;
        }

    if(config.verbose)
        verbose_already = 1;

    parse_config_file(config.file);

    // reset verbosity before 2nd coming, but only if set on cli
    if(verbose_already)
        config.verbose = 0;
    optind = 1;
    prads_version();

    if(parse_args(&config, argc, argv, ARGS) != 0){
        usage();
        exit(0);
    }
    // we're done parsing configs - now initialize prads
    /*if(ISSET_CONFIG_SYSLOG(config)) {
        openlog("prads", LOG_PID | LOG_CONS, LOG_DAEMON);
    }*/
    /*if (config.ringbuffer) {
        rc = init_logging(LOG_RINGBUFFER, NULL, config.cflags);
        if (rc)
            perror("Logging to ringbuffer failed!");
    }
    if (config.cflags & (CONFIG_VERBOSE | CONFIG_CXWRITE | CONFIG_CONNECT)) {
        rc = init_logging(LOG_STDOUT, NULL, config.cflags);
        if(rc) perror("Logging to standard out failed!");
    }*/
    if(config.assetlog) {
        olog("logging to file '%s'\n", config.assetlog);
        //rc = init_logging(LOG_FILE, config.assetlog, config.cflags);
#if LOG_AGENCY==1
        rc = init_log_agency(config.assetlog, config.cflags);
#endif
        if(rc) perror("Logging to file failed!");
    }
    /*if(config.fifo) {
        olog("logging to FIFO '%s'\n", config.fifo);
        rc = init_logging(LOG_FIFO, config.fifo, config.cflags);
        if(rc) perror("Logging to fifo failed!");
    }*/
    /* moved NOTE: cxtlog is inited in prads_initialize, after dropping privs */
    if(config.s_net){
       parse_nets(config.s_net, network);
    }
    olog("[*] Loading fingerprints:\n");
/* helper macro to avoid duplicate code */
#define load_foo(func, conf, flag, file, hash, len, dump) \
    if(config. conf & flag) { \
        int _rc; \
        olog("  %-11s %s\n", # flag, (config. file)); \
        _rc = func (config. file, & config. hash, config. len); \
        if(_rc) perror( #flag " load failed!"); \
        else if(config.verbose > 1) { \
            printf("[*] Dumping " #flag " signatures:\n"); \
            dump (config. hash, config. len); \
            printf("[*] " #flag " signature dump ends.\n"); \
        } \
    }

    load_foo(load_mac , cof, CS_MAC, sig_file_mac, sig_mac, mac_hashsize, dump_macs);
    load_foo(load_sigs, ctf, CO_SYN, sig_file_syn, sig_syn, sig_hashsize, dump_sigs);
    load_foo(load_sigs, ctf, CO_SYNACK, sig_file_synack, sig_synack, sig_hashsize, dump_sigs);
    load_foo(load_sigs, ctf, CO_ACK, sig_file_ack, sig_ack, sig_hashsize, dump_sigs);
    load_foo(load_sigs, ctf, CO_FIN, sig_file_fin, sig_fin, sig_hashsize, dump_sigs);
    load_foo(load_sigs, ctf, CO_RST, sig_file_rst, sig_rst, sig_hashsize, dump_sigs);
    load_foo(load_dhcp_sigs, ctf, CO_DHCP, sig_file_dhcp, sig_dhcp, sig_hashsize, dump_dhcp_sigs);
    load_foo(load_servicefp_file, cof, CS_TCP_SERVER, sig_file_serv_tcp, sig_serv_tcp, sig_hashsize, dump_sig_service);
    load_foo(load_servicefp_file, cof, CS_UDP_SERVICES, sig_file_serv_udp, sig_serv_udp, sig_hashsize, dump_sig_service);
    load_foo(load_servicefp_file, cof, CS_TCP_CLIENT, sig_file_cli_tcp, sig_client_tcp, sig_hashsize, dump_sig_service);
    //init_services();

    display_config(&config);

    prads_initialize(&config);
 
    //alarm(SIG_ALRM);

    /** segfaults on empty pcap! */
    //struct bpf_program  cfilter;        /**/
    //if ((pcap_compile(config.handle, &cfilter, config.bpff, 1, config.net_mask)) == -1) {
    //        olog("[*] Error pcap_compile user_filter: %s\n", pcap_geterr(config.handle));
    //        exit(1);
    //}

    //if (pcap_setfilter(config.handle, &cfilter)) {
    //        olog("[*] Unable to set pcap filter!  %s", pcap_geterr(config.handle));
    //}
    //pcap_freecode(&cfilter);

    //cxt_init();
    //olog("[*] Sniffing...\n");
    /*pcap_loop(config.handle, -1, got_packet, NULL);

    game_over();*/
    return (0);
}

