

/* For setsockopt(2) */
#define SOL_SOCKET	1

#define SO_DEBUG	1
#define SO_REUSEADDR	2
#define SO_TYPE		3
#define SO_ERROR	4
#define SO_DONTROUTE	5
#define SO_BROADCAST	6
#define SO_SNDBUF	7
#define SO_RCVBUF	8
#define SO_SNDBUFFORCE	32
#define SO_RCVBUFFORCE	33
#define SO_KEEPALIVE	9
#define SO_OOBINLINE	10
#define SO_NO_CHECK	11
#define SO_PRIORITY	12
#define SO_LINGER	13
#define SO_BSDCOMPAT	14
#define SO_REUSEPORT	15
#ifndef SO_PASSCRED /* powerpc only differs in these */
#define SO_PASSCRED	16
#define SO_PEERCRED	17
#define SO_RCVLOWAT	18
#define SO_SNDLOWAT	19
#define SO_RCVTIMEO	20
#define SO_SNDTIMEO	21
#endif

/* Security levels - as per NRL IPv6 - don't actually do anything */
#define SO_SECURITY_AUTHENTICATION		22
#define SO_SECURITY_ENCRYPTION_TRANSPORT	23
#define SO_SECURITY_ENCRYPTION_NETWORK		24

#define SO_BINDTODEVICE	25

/* Socket filtering */
#define SO_ATTACH_FILTER	26
#define SO_DETACH_FILTER	27
#define SO_GET_FILTER		SO_ATTACH_FILTER

#define SO_PEERNAME		28
#define SO_TIMESTAMP		29
#define SCM_TIMESTAMP		SO_TIMESTAMP

#define SO_ACCEPTCONN		30

#define SO_PEERSEC		31
#define SO_PASSSEC		34
#define SO_TIMESTAMPNS		35
#define SCM_TIMESTAMPNS		SO_TIMESTAMPNS

#define SO_MARK			36

#define SO_TIMESTAMPING		37
#define SCM_TIMESTAMPING	SO_TIMESTAMPING

#define SO_PROTOCOL		38
#define SO_DOMAIN		39

#define SO_RXQ_OVFL             40

#define SO_WIFI_STATUS		41
#define SCM_WIFI_STATUS	SO_WIFI_STATUS
#define SO_PEEK_OFF		42

/* Instruct lower device to use last 4-bytes of skb data as FCS */
#define SO_NOFCS		43

#define SO_LOCK_FILTER		44

#define SO_SELECT_ERR_QUEUE	45

#define SO_BUSY_POLL		46

#define SO_MAX_PACING_RATE	47

#define SO_BPF_EXTENSIONS	48

#define SO_INCOMING_CPU		49

#define SO_ATTACH_BPF		50
#define SO_DETACH_BPF		SO_DETACH_FILTER

/*io_control.h*/

#define TCGETS		0x5401
#define TCSETS		0x5402
#define TCSETSW		0x5403
#define TCSETSF		0x5404
#define TCGETA		0x5405
#define TCSETA		0x5406
#define TCSETAW		0x5407
#define TCSETAF		0x5408
#define TCSBRK		0x5409
#define TCXONC		0x540A
#define TCFLSH		0x540B
#define TIOCEXCL	0x540C
#define TIOCNXCL	0x540D
#define TIOCSCTTY	0x540E
#define TIOCGPGRP	0x540F
#define TIOCSPGRP	0x5410
#define TIOCOUTQ	0x5411
#define TIOCSTI		0x5412
#define TIOCGWINSZ	0x5413
#define TIOCSWINSZ	0x5414
#define TIOCMGET	0x5415
#define TIOCMBIS	0x5416
#define TIOCMBIC	0x5417
#define TIOCMSET	0x5418
#define TIOCGSOFTCAR	0x5419
#define TIOCSSOFTCAR	0x541A
#define FIONREAD	0x541B
#define TIOCINQ		FIONREAD
#define TIOCLINUX	0x541C
#define TIOCCONS	0x541D
#define TIOCGSERIAL	0x541E
#define TIOCSSERIAL	0x541F
#define TIOCPKT		0x5420
#define FIONBIO		0x5421
#define TIOCNOTTY	0x5422
#define TIOCSETD	0x5423
#define TIOCGETD	0x5424
#define TCSBRKP		0x5425	/* Needed for POSIX tcsendbreak() */
#define TIOCSBRK	0x5427  /* BSD compatibility */
#define TIOCCBRK	0x5428  /* BSD compatibility */
#define TIOCGSID	0x5429  /* Return the session ID of FD */
#define TCGETS2		_IOR('T', 0x2A, struct termios2)
#define TCSETS2		_IOW('T', 0x2B, struct termios2)
#define TCSETSW2	_IOW('T', 0x2C, struct termios2)
#define TCSETSF2	_IOW('T', 0x2D, struct termios2)
#define TIOCGRS485	0x542E
#ifndef TIOCSRS485
#define TIOCSRS485	0x542F
#endif
#define TIOCGPTN	_IOR('T', 0x30, unsigned int) /* Get Pty Number (of pty-mux device) */
#define TIOCSPTLCK	_IOW('T', 0x31, int)  /* Lock/unlock Pty */
#define TIOCGDEV	_IOR('T', 0x32, unsigned int) /* Get primary device node of /dev/console */
#define TCGETX		0x5432 /* SYS5 TCGETX compatibility */
#define TCSETX		0x5433
#define TCSETXF		0x5434
#define TCSETXW		0x5435
#define TIOCSIG		_IOW('T', 0x36, int)  /* pty: generate signal */
#define TIOCVHANGUP	0x5437
#define TIOCGPKT	_IOR('T', 0x38, int) /* Get packet mode state */
#define TIOCGPTLCK	_IOR('T', 0x39, int) /* Get Pty lock state */
#define TIOCGEXCL	_IOR('T', 0x40, int) /* Get exclusive mode state */

#define FIONCLEX	0x5450
#define FIOCLEX		0x5451
#define FIOASYNC	0x5452
#define TIOCSERCONFIG	0x5453
#define TIOCSERGWILD	0x5454
#define TIOCSERSWILD	0x5455
#define TIOCGLCKTRMIOS	0x5456
#define TIOCSLCKTRMIOS	0x5457
#define TIOCSERGSTRUCT	0x5458 /* For debugging only */
#define TIOCSERGETLSR   0x5459 /* Get line status register */
#define TIOCSERGETMULTI 0x545A /* Get multiport config  */
#define TIOCSERSETMULTI 0x545B /* Set multiport config */

#define TIOCMIWAIT	0x545C	/* wait for a change on serial input line(s) */
#define TIOCGICOUNT	0x545D	/* read serial port __inline__ interrupt counts */

/*
* Some arches already define FIOQSIZE due to a historical
* conflict with a Hayes modem-specific ioctl value.
*/
#ifndef FIOQSIZE
# define FIOQSIZE	0x5460
#endif

/* Used for packet mode */
#define TIOCPKT_DATA		 0
#define TIOCPKT_FLUSHREAD	 1
#define TIOCPKT_FLUSHWRITE	 2
#define TIOCPKT_STOP		 4
#define TIOCPKT_START		 8
#define TIOCPKT_NOSTOP		16
#define TIOCPKT_DOSTOP		32
#define TIOCPKT_IOCTL		64

#define TIOCSER_TEMT	0x01	/* Transmitter physically empty */



/* Protocol families.  */
#define	PF_UNSPEC	0	/* Unspecified.  */
#define	PF_LOCAL	1	/* Local to host (pipes and file-domain).  */
#define	PF_UNIX		PF_LOCAL /* POSIX name for PF_LOCAL.  */
#define	PF_FILE		PF_LOCAL /* Another non-standard name for PF_LOCAL.  */
#define	PF_INET		2	/* IP protocol family.  */
#define	PF_AX25		3	/* Amateur Radio AX.25.  */
#define	PF_IPX		4	/* Novell Internet Protocol.  */
#define	PF_APPLETALK	5	/* Appletalk DDP.  */
#define	PF_NETROM	6	/* Amateur radio NetROM.  */
#define	PF_BRIDGE	7	/* Multiprotocol bridge.  */
#define	PF_ATMPVC	8	/* ATM PVCs.  */
#define	PF_X25		9	/* Reserved for X.25 project.  */
#define	PF_INET6	10	/* IP version 6.  */
#define	PF_ROSE		11	/* Amateur Radio X.25 PLP.  */
#define	PF_DECnet	12	/* Reserved for DECnet project.  */
#define	PF_NETBEUI	13	/* Reserved for 802.2LLC project.  */
#define	PF_SECURITY	14	/* Security callback pseudo AF.  */
#define	PF_KEY		15	/* PF_KEY key management API.  */
#define	PF_NETLINK	16
#define	PF_ROUTE	PF_NETLINK /* Alias to emulate 4.4BSD.  */
#define	PF_PACKET	17	/* Packet family.  */
#define	PF_ASH		18	/* Ash.  */
#define	PF_ECONET	19	/* Acorn Econet.  */
#define	PF_ATMSVC	20	/* ATM SVCs.  */
#define PF_RDS		21	/* RDS sockets.  */
#define	PF_SNA		22	/* Linux SNA Project */
#define	PF_IRDA		23	/* IRDA sockets.  */
#define	PF_PPPOX	24	/* PPPoX sockets.  */
#define	PF_WANPIPE	25	/* Wanpipe API sockets.  */
#define PF_LLC		26	/* Linux LLC.  */
#define PF_CAN		29	/* Controller Area Network.  */
#define PF_TIPC		30	/* TIPC sockets.  */
#define	PF_BLUETOOTH	31	/* Bluetooth sockets.  */
#define	PF_IUCV		32	/* IUCV sockets.  */
#define PF_RXRPC	33	/* RxRPC sockets.  */
#define PF_ISDN		34	/* mISDN sockets.  */
#define PF_PHONET	35	/* Phonet sockets.  */
#define PF_IEEE802154	36	/* IEEE 802.15.4 sockets.  */
#define PF_CAIF		37	/* CAIF sockets.  */
#define PF_ALG		38	/* Algorithm sockets.  */
#define PF_NFC		39	/* NFC sockets.  */
#define PF_VSOCK	40	/* vSockets.  */
#define	PF_MAX		41	/* For now..  */

/* Address families.  */
#define	AF_UNSPEC	PF_UNSPEC
#define	AF_LOCAL	PF_LOCAL
#define	AF_UNIX		PF_UNIX
#define	AF_FILE		PF_FILE
#define	AF_INET		PF_INET
#define	AF_AX25		PF_AX25
#define	AF_IPX		PF_IPX
#define	AF_APPLETALK	PF_APPLETALK
#define	AF_NETROM	PF_NETROM
#define	AF_BRIDGE	PF_BRIDGE
#define	AF_ATMPVC	PF_ATMPVC
#define	AF_X25		PF_X25
#define	AF_INET6	PF_INET6
#define	AF_ROSE		PF_ROSE
#define	AF_DECnet	PF_DECnet
#define	AF_NETBEUI	PF_NETBEUI
#define	AF_SECURITY	PF_SECURITY
#define	AF_KEY		PF_KEY
#define	AF_NETLINK	PF_NETLINK
#define	AF_ROUTE	PF_ROUTE
#define	AF_PACKET	PF_PACKET
#define	AF_ASH		PF_ASH
#define	AF_ECONET	PF_ECONET
#define	AF_ATMSVC	PF_ATMSVC
#define AF_RDS		PF_RDS
#define	AF_SNA		PF_SNA
#define	AF_IRDA		PF_IRDA
#define	AF_PPPOX	PF_PPPOX
#define	AF_WANPIPE	PF_WANPIPE
#define AF_LLC		PF_LLC
#define AF_CAN		PF_CAN
#define AF_TIPC		PF_TIPC
#define	AF_BLUETOOTH	PF_BLUETOOTH
#define	AF_IUCV		PF_IUCV
#define AF_RXRPC	PF_RXRPC
#define AF_ISDN		PF_ISDN
#define AF_PHONET	PF_PHONET
#define AF_IEEE802154	PF_IEEE802154
#define AF_CAIF		PF_CAIF
#define AF_ALG		PF_ALG
#define AF_NFC		PF_NFC
#define AF_VSOCK	PF_VSOCK
#define	AF_MAX		PF_MAX

/* Socket level values.  Others are defined in the appropriate headers.

XXX These definitions also should go into the appropriate headers as
far as they are available.  */
#define SOL_RAW		255
#define SOL_DECNET      261
#define SOL_X25         262
#define SOL_PACKET	263
#define SOL_ATM		264	/* ATM layer (cell level).  */
#define SOL_AAL		265	/* ATM Adaption Layer (packet level).  */
#define SOL_IRDA	266

/* Maximum queue length specifiable by listen.  */
#define SOMAXCONN	128


/* Types of sockets.  */
enum __socket_type
{
	SOCK_STREAM = 1,		/* Sequenced, reliable, connection-based
							byte streams.  */
#define SOCK_STREAM SOCK_STREAM
	SOCK_DGRAM = 2,		/* Connectionless, unreliable datagrams
						of fixed maximum length.  */
#define SOCK_DGRAM SOCK_DGRAM
	SOCK_RAW = 3,			/* Raw protocol interface.  */
#define SOCK_RAW SOCK_RAW
	SOCK_RDM = 4,			/* Reliably-delivered messages.  */
#define SOCK_RDM SOCK_RDM
	SOCK_SEQPACKET = 5,		/* Sequenced, reliable, connection-based,
							datagrams of fixed maximum length.  */
#define SOCK_SEQPACKET SOCK_SEQPACKET
	SOCK_DCCP = 6,		/* Datagram Congestion Control Protocol.  */
#define SOCK_DCCP SOCK_DCCP
	SOCK_PACKET = 10,		/* Linux specific way of getting packets
							at the dev level.  For writing rarp and
							other similar things on the user level. */
#define SOCK_PACKET SOCK_PACKET

							/* Flags to be ORed into the type parameter of socket and socketpair and
							used for the flags parameter of paccept.  */

	SOCK_CLOEXEC = 02000000,	/* Atomically set close-on-exec flag for the
								new descriptor(s).  */
#define SOCK_CLOEXEC SOCK_CLOEXEC
	SOCK_NONBLOCK = 00004000	/* Atomically mark descriptor(s) as
								non-blocking.  */
#define SOCK_NONBLOCK SOCK_NONBLOCK
};


#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_ZLEN	60		/* Min. octets in frame sans FCS */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */
#define ETH_FCS_LEN	4		/* Octets in the FCS		 */

/*
*	These are the defined Ethernet Protocol ID's.
*/

#define ETH_P_LOOP	0x0060		/* Ethernet Loopback packet	*/
#define ETH_P_PUP	0x0200		/* Xerox PUP packet		*/
#define ETH_P_PUPAT	0x0201		/* Xerox PUP Addr Trans packet	*/
#define ETH_P_TSN	0x22F0		/* TSN (IEEE 1722) packet	*/
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_X25	0x0805		/* CCITT X.25			*/
#define ETH_P_ARP	0x0806		/* Address Resolution packet	*/
#define	ETH_P_BPQ	0x08FF		/* G8BPQ AX.25 Ethernet Packet	[ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_IEEEPUP	0x0a00		/* Xerox IEEE802.3 PUP packet */
#define ETH_P_IEEEPUPAT	0x0a01		/* Xerox IEEE802.3 PUP Addr Trans packet */
#define ETH_P_BATMAN	0x4305		/* B.A.T.M.A.N.-Advanced packet [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_DEC       0x6000          /* DEC Assigned proto           */
#define ETH_P_DNA_DL    0x6001          /* DEC DNA Dump/Load            */
#define ETH_P_DNA_RC    0x6002          /* DEC DNA Remote Console       */
#define ETH_P_DNA_RT    0x6003          /* DEC DNA Routing              */
#define ETH_P_LAT       0x6004          /* DEC LAT                      */
#define ETH_P_DIAG      0x6005          /* DEC Diagnostics              */
#define ETH_P_CUST      0x6006          /* DEC Customer use             */
#define ETH_P_SCA       0x6007          /* DEC Systems Comms Arch       */
#define ETH_P_TEB	0x6558		/* Trans Ether Bridging		*/
#define ETH_P_RARP      0x8035		/* Reverse Addr Res packet	*/
#define ETH_P_ATALK	0x809B		/* Appletalk DDP		*/
#define ETH_P_AARP	0x80F3		/* Appletalk AARP		*/
#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_IPX	0x8137		/* IPX over DIX			*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/
#define ETH_P_PAUSE	0x8808		/* IEEE Pause frames. See 802.3 31B */
#define ETH_P_SLOW	0x8809		/* Slow Protocol. See 802.3ad 43B */
#define ETH_P_WCCP	0x883E		/* Web-cache coordination protocol
* defined in draft-wilson-wrec-wccp-v2-00.txt */
#define ETH_P_MPLS_UC	0x8847		/* MPLS Unicast traffic		*/
#define ETH_P_MPLS_MC	0x8848		/* MPLS Multicast traffic	*/
#define ETH_P_ATMMPOA	0x884c		/* MultiProtocol Over ATM	*/
#define ETH_P_PPP_DISC	0x8863		/* PPPoE discovery messages     */
#define ETH_P_PPP_SES	0x8864		/* PPPoE session messages	*/
#define ETH_P_LINK_CTL	0x886c		/* HPNA, wlan link local tunnel */
#define ETH_P_ATMFATE	0x8884		/* Frame-based ATM Transport
* over Ethernet
*/
#define ETH_P_PAE	0x888E		/* Port Access Entity (IEEE 802.1X) */
#define ETH_P_AOE	0x88A2		/* ATA over Ethernet		*/
#define ETH_P_8021AD	0x88A8          /* 802.1ad Service VLAN		*/
#define ETH_P_802_EX1	0x88B5		/* 802.1 Local Experimental 1.  */
#define ETH_P_TIPC	0x88CA		/* TIPC 			*/
#define ETH_P_8021AH	0x88E7          /* 802.1ah Backbone Service Tag */
#define ETH_P_MVRP	0x88F5          /* 802.1Q MVRP                  */
#define ETH_P_1588	0x88F7		/* IEEE 1588 Timesync */
#define ETH_P_PRP	0x88FB		/* IEC 62439-3 PRP/HSRv0	*/
#define ETH_P_FCOE	0x8906		/* Fibre Channel over Ethernet  */
#define ETH_P_TDLS	0x890D          /* TDLS */
#define ETH_P_FIP	0x8914		/* FCoE Initialization Protocol */
#define ETH_P_80221	0x8917		/* IEEE 802.21 Media Independent Handover Protocol */
#define ETH_P_LOOPBACK	0x9000		/* Ethernet loopback packet, per IEEE 802.3 */
#define ETH_P_QINQ1	0x9100		/* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_QINQ2	0x9200		/* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_QINQ3	0x9300		/* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_EDSA	0xDADA		/* Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_AF_IUCV   0xFBFB		/* IBM af_iucv [ NOT AN OFFICIALLY REGISTERED ID ] */

#define ETH_P_802_3_MIN	0x0600		/* If the value in the ethernet type is less than this value
* then the frame is Ethernet II. Else it is 802.3 */

/*
*	Non DIX types. Won't clash for 1500 types.
*/

#define ETH_P_802_3	0x0001		/* Dummy type for 802.3 frames  */
#define ETH_P_AX25	0x0002		/* Dummy protocol id for AX.25  */
#define ETH_P_ALL	0x0003		/* Every packet (be careful!!!) */
#define ETH_P_802_2	0x0004		/* 802.2 frames 		*/
#define ETH_P_SNAP	0x0005		/* Internal only		*/
#define ETH_P_DDCMP     0x0006          /* DEC DDCMP: Internal only     */
#define ETH_P_WAN_PPP   0x0007          /* Dummy type for WAN PPP frames*/
#define ETH_P_PPP_MP    0x0008          /* Dummy type for PPP MP frames */
#define ETH_P_LOCALTALK 0x0009		/* Localtalk pseudo type 	*/
#define ETH_P_CAN	0x000C		/* CAN: Controller Area Network */
#define ETH_P_CANFD	0x000D		/* CANFD: CAN flexible data rate*/
#define ETH_P_PPPTALK	0x0010		/* Dummy type for Atalk over PPP*/
#define ETH_P_TR_802_2	0x0011		/* 802.2 frames 		*/
#define ETH_P_MOBITEX	0x0015		/* Mobitex (kaz@cafe.net)	*/
#define ETH_P_CONTROL	0x0016		/* Card specific control frames */
#define ETH_P_IRDA	0x0017		/* Linux-IrDA			*/
#define ETH_P_ECONET	0x0018		/* Acorn Econet			*/
#define ETH_P_HDLC	0x0019		/* HDLC frames			*/
#define ETH_P_ARCNET	0x001A		/* 1A for ArcNet :-)            */
#define ETH_P_DSA	0x001B		/* Distributed Switch Arch.	*/
#define ETH_P_TRAILER	0x001C		/* Trailer switch tagging	*/
#define ETH_P_PHONET	0x00F5		/* Nokia Phonet frames          */
#define ETH_P_IEEE802154 0x00F6		/* IEEE802.15.4 frame		*/
#define ETH_P_CAIF	0x00F7		/* ST-Ericsson CAIF protocol	*/
#define ETH_P_XDSA	0x00F8		/* Multiplexed DSA protocol	*/


/* Length of interface name.  */
#define IF_NAMESIZE	16



/* Standard well-defined IP protocols.  */
enum
{
	IPPROTO_IP = 0,	   /* Dummy protocol for TCP.  */
#define IPPROTO_IP		IPPROTO_IP
	IPPROTO_ICMP = 1,	   /* Internet Control Message Protocol.  */
#define IPPROTO_ICMP		IPPROTO_ICMP
	IPPROTO_IGMP = 2,	   /* Internet Group Management Protocol. */
#define IPPROTO_IGMP		IPPROTO_IGMP
	IPPROTO_IPIP = 4,	   /* IPIP tunnels (older KA9Q tunnels use 94).  */
#define IPPROTO_IPIP		IPPROTO_IPIP
	IPPROTO_TCP = 6,	   /* Transmission Control Protocol.  */
#define IPPROTO_TCP		IPPROTO_TCP
	IPPROTO_EGP = 8,	   /* Exterior Gateway Protocol.  */
#define IPPROTO_EGP		IPPROTO_EGP
	IPPROTO_PUP = 12,	   /* PUP protocol.  */
#define IPPROTO_PUP		IPPROTO_PUP
	IPPROTO_UDP = 17,	   /* User Datagram Protocol.  */
#define IPPROTO_UDP		IPPROTO_UDP
	IPPROTO_IDP = 22,	   /* XNS IDP protocol.  */
#define IPPROTO_IDP		IPPROTO_IDP
	IPPROTO_TP = 29,	   /* SO Transport Protocol Class 4.  */
#define IPPROTO_TP		IPPROTO_TP
	IPPROTO_DCCP = 33,	   /* Datagram Congestion Control Protocol.  */
#define IPPROTO_DCCP		IPPROTO_DCCP
	IPPROTO_IPV6 = 41,     /* IPv6 header.  */
#define IPPROTO_IPV6		IPPROTO_IPV6
	IPPROTO_RSVP = 46,	   /* Reservation Protocol.  */
#define IPPROTO_RSVP		IPPROTO_RSVP
	IPPROTO_GRE = 47,	   /* General Routing Encapsulation.  */
#define IPPROTO_GRE		IPPROTO_GRE
	IPPROTO_ESP = 50,      /* encapsulating security payload.  */
#define IPPROTO_ESP		IPPROTO_ESP
	IPPROTO_AH = 51,       /* authentication header.  */
#define IPPROTO_AH		IPPROTO_AH
	IPPROTO_MTP = 92,	   /* Multicast Transport Protocol.  */
#define IPPROTO_MTP		IPPROTO_MTP
	IPPROTO_BEETPH = 94,   /* IP option pseudo header for BEET.  */
#define IPPROTO_BEETPH		IPPROTO_BEETPH
	IPPROTO_ENCAP = 98,	   /* Encapsulation Header.  */
#define IPPROTO_ENCAP		IPPROTO_ENCAP
	IPPROTO_PIM = 103,	   /* Protocol Independent Multicast.  */
#define IPPROTO_PIM		IPPROTO_PIM
	IPPROTO_COMP = 108,	   /* Compression Header Protocol.  */
#define IPPROTO_COMP		IPPROTO_COMP
	IPPROTO_SCTP = 132,	   /* Stream Control Transmission Protocol.  */
#define IPPROTO_SCTP		IPPROTO_SCTP
	IPPROTO_UDPLITE = 136, /* UDP-Lite protocol.  */
#define IPPROTO_UDPLITE		IPPROTO_UDPLITE
	IPPROTO_MPLS = 137,    /* MPLS in IP.  */
#define IPPROTO_MPLS		IPPROTO_MPLS
	IPPROTO_RAW = 255,	   /* Raw IP packets.  */
#define IPPROTO_RAW		IPPROTO_RAW
	IPPROTO_MAX
};

/* Standard well-known ports.  */
enum
{
	IPPORT_ECHO = 7,		/* Echo service.  */
	IPPORT_DISCARD = 9,		/* Discard transmissions service.  */
	IPPORT_SYSTAT = 11,		/* System status service.  */
	IPPORT_DAYTIME = 13,	/* Time of day service.  */
	IPPORT_NETSTAT = 15,	/* Network status service.  */
	IPPORT_FTP = 21,		/* File Transfer Protocol.  */
	IPPORT_TELNET = 23,		/* Telnet protocol.  */
	IPPORT_SMTP = 25,		/* Simple Mail Transfer Protocol.  */
	IPPORT_TIMESERVER = 37,	/* Timeserver service.  */
	IPPORT_NAMESERVER = 42,	/* Domain Name Service.  */
	IPPORT_WHOIS = 43,		/* Internet Whois service.  */
	IPPORT_MTP = 57,

	IPPORT_TFTP = 69,		/* Trivial File Transfer Protocol.  */
	IPPORT_RJE = 77,
	IPPORT_FINGER = 79,		/* Finger service.  */
	IPPORT_TTYLINK = 87,
	IPPORT_SUPDUP = 95,		/* SUPDUP protocol.  */


	IPPORT_EXECSERVER = 512,	/* execd service.  */
	IPPORT_LOGINSERVER = 513,	/* rlogind service.  */
	IPPORT_CMDSERVER = 514,
	IPPORT_EFSSERVER = 520,

	/* UDP ports.  */
	IPPORT_BIFFUDP = 512,
	IPPORT_WHOSERVER = 513,
	IPPORT_ROUTESERVER = 520,

	/* Ports less than this value are reserved for privileged processes.  */
	IPPORT_RESERVED = 1024,

	/* Ports greater this value are reserved for (non-privileged) servers.  */
	IPPORT_USERRESERVED = 5000
};


/* Address to accept any incoming messages.  */
#define	INADDR_ANY		((in_addr_t) 0x00000000)
/* Address to send to all hosts.  */
#define	INADDR_BROADCAST	((in_addr_t) 0xffffffff)
/* Address indicating an error return.  */
#define	INADDR_NONE		((in_addr_t) 0xffffffff)

/* Network number for local host loopback.  */
#define	IN_LOOPBACKNET		127
/* Address to loopback in software to local host.  */
#ifndef INADDR_LOOPBACK
# define INADDR_LOOPBACK	((in_addr_t) 0x7f000001) /* Inet 127.0.0.1.  */
#endif

/* Defines for Multicast INADDR.  */
#define INADDR_UNSPEC_GROUP	((in_addr_t) 0xe0000000) /* 224.0.0.0 */
#define INADDR_ALLHOSTS_GROUP	((in_addr_t) 0xe0000001) /* 224.0.0.1 */
#define INADDR_ALLRTRS_GROUP    ((in_addr_t) 0xe0000002) /* 224.0.0.2 */
#define INADDR_MAX_LOCAL_GROUP  ((in_addr_t) 0xe00000ff) /* 224.0.0.255 */




/*
*	IEEE 802.3 Ethernet magic constants.  The frame sizes omit the preamble
*	and FCS/CRC (frame check sequence).
*/

#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_ZLEN	60		/* Min. octets in frame sans FCS */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */
#define ETH_FCS_LEN	4		/* Octets in the FCS		 */

/*
*	These are the defined Ethernet Protocol ID's.
*/

#define ETH_P_LOOP	0x0060		/* Ethernet Loopback packet	*/
#define ETH_P_PUP	0x0200		/* Xerox PUP packet		*/
#define ETH_P_PUPAT	0x0201		/* Xerox PUP Addr Trans packet	*/
#define ETH_P_TSN	0x22F0		/* TSN (IEEE 1722) packet	*/
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_X25	0x0805		/* CCITT X.25			*/
#define ETH_P_ARP	0x0806		/* Address Resolution packet	*/
#define	ETH_P_BPQ	0x08FF		/* G8BPQ AX.25 Ethernet Packet	[ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_IEEEPUP	0x0a00		/* Xerox IEEE802.3 PUP packet */
#define ETH_P_IEEEPUPAT	0x0a01		/* Xerox IEEE802.3 PUP Addr Trans packet */
#define ETH_P_BATMAN	0x4305		/* B.A.T.M.A.N.-Advanced packet [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_DEC       0x6000          /* DEC Assigned proto           */
#define ETH_P_DNA_DL    0x6001          /* DEC DNA Dump/Load            */
#define ETH_P_DNA_RC    0x6002          /* DEC DNA Remote Console       */
#define ETH_P_DNA_RT    0x6003          /* DEC DNA Routing              */
#define ETH_P_LAT       0x6004          /* DEC LAT                      */
#define ETH_P_DIAG      0x6005          /* DEC Diagnostics              */
#define ETH_P_CUST      0x6006          /* DEC Customer use             */
#define ETH_P_SCA       0x6007          /* DEC Systems Comms Arch       */
#define ETH_P_TEB	0x6558		/* Trans Ether Bridging		*/
#define ETH_P_RARP      0x8035		/* Reverse Addr Res packet	*/
#define ETH_P_ATALK	0x809B		/* Appletalk DDP		*/
#define ETH_P_AARP	0x80F3		/* Appletalk AARP		*/
#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_IPX	0x8137		/* IPX over DIX			*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/
#define ETH_P_PAUSE	0x8808		/* IEEE Pause frames. See 802.3 31B */
#define ETH_P_SLOW	0x8809		/* Slow Protocol. See 802.3ad 43B */
#define ETH_P_WCCP	0x883E		/* Web-cache coordination protocol
* defined in draft-wilson-wrec-wccp-v2-00.txt */
#define ETH_P_MPLS_UC	0x8847		/* MPLS Unicast traffic		*/
#define ETH_P_MPLS_MC	0x8848		/* MPLS Multicast traffic	*/
#define ETH_P_ATMMPOA	0x884c		/* MultiProtocol Over ATM	*/
#define ETH_P_PPP_DISC	0x8863		/* PPPoE discovery messages     */
#define ETH_P_PPP_SES	0x8864		/* PPPoE session messages	*/
#define ETH_P_LINK_CTL	0x886c		/* HPNA, wlan link local tunnel */
#define ETH_P_ATMFATE	0x8884		/* Frame-based ATM Transport
* over Ethernet
*/
#define ETH_P_PAE	0x888E		/* Port Access Entity (IEEE 802.1X) */
#define ETH_P_AOE	0x88A2		/* ATA over Ethernet		*/
#define ETH_P_8021AD	0x88A8          /* 802.1ad Service VLAN		*/
#define ETH_P_802_EX1	0x88B5		/* 802.1 Local Experimental 1.  */
#define ETH_P_TIPC	0x88CA		/* TIPC 			*/
#define ETH_P_8021AH	0x88E7          /* 802.1ah Backbone Service Tag */
#define ETH_P_MVRP	0x88F5          /* 802.1Q MVRP                  */
#define ETH_P_1588	0x88F7		/* IEEE 1588 Timesync */
#define ETH_P_PRP	0x88FB		/* IEC 62439-3 PRP/HSRv0	*/
#define ETH_P_FCOE	0x8906		/* Fibre Channel over Ethernet  */
#define ETH_P_TDLS	0x890D          /* TDLS */
#define ETH_P_FIP	0x8914		/* FCoE Initialization Protocol */
#define ETH_P_80221	0x8917		/* IEEE 802.21 Media Independent Handover Protocol */
#define ETH_P_LOOPBACK	0x9000		/* Ethernet loopback packet, per IEEE 802.3 */
#define ETH_P_QINQ1	0x9100		/* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_QINQ2	0x9200		/* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_QINQ3	0x9300		/* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_EDSA	0xDADA		/* Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_AF_IUCV   0xFBFB		/* IBM af_iucv [ NOT AN OFFICIALLY REGISTERED ID ] */

#define ETH_P_802_3_MIN	0x0600		/* If the value in the ethernet type is less than this value
* then the frame is Ethernet II. Else it is 802.3 */

/*
*	Non DIX types. Won't clash for 1500 types.
*/

#define ETH_P_802_3	0x0001		/* Dummy type for 802.3 frames  */
#define ETH_P_AX25	0x0002		/* Dummy protocol id for AX.25  */
#define ETH_P_ALL	0x0003		/* Every packet (be careful!!!) */
#define ETH_P_802_2	0x0004		/* 802.2 frames 		*/
#define ETH_P_SNAP	0x0005		/* Internal only		*/
#define ETH_P_DDCMP     0x0006          /* DEC DDCMP: Internal only     */
#define ETH_P_WAN_PPP   0x0007          /* Dummy type for WAN PPP frames*/
#define ETH_P_PPP_MP    0x0008          /* Dummy type for PPP MP frames */
#define ETH_P_LOCALTALK 0x0009		/* Localtalk pseudo type 	*/
#define ETH_P_CAN	0x000C		/* CAN: Controller Area Network */
#define ETH_P_CANFD	0x000D		/* CANFD: CAN flexible data rate*/
#define ETH_P_PPPTALK	0x0010		/* Dummy type for Atalk over PPP*/
#define ETH_P_TR_802_2	0x0011		/* 802.2 frames 		*/
#define ETH_P_MOBITEX	0x0015		/* Mobitex (kaz@cafe.net)	*/
#define ETH_P_CONTROL	0x0016		/* Card specific control frames */
#define ETH_P_IRDA	0x0017		/* Linux-IrDA			*/
#define ETH_P_ECONET	0x0018		/* Acorn Econet			*/
#define ETH_P_HDLC	0x0019		/* HDLC frames			*/
#define ETH_P_ARCNET	0x001A		/* 1A for ArcNet :-)            */
#define ETH_P_DSA	0x001B		/* Distributed Switch Arch.	*/
#define ETH_P_TRAILER	0x001C		/* Trailer switch tagging	*/
#define ETH_P_PHONET	0x00F5		/* Nokia Phonet frames          */
#define ETH_P_IEEE802154 0x00F6		/* IEEE802.15.4 frame		*/
#define ETH_P_CAIF	0x00F7		/* ST-Ericsson CAIF protocol	*/
#define ETH_P_XDSA	0x00F8		/* Multiplexed DSA protocol	*/

/* Bits in the FLAGS argument to `send', `recv', et al.  */
enum
{
	MSG_OOB = 0x01,	/* Process out-of-band data.  */
#define MSG_OOB		MSG_OOB
	MSG_PEEK = 0x02,	/* Peek at incoming messages.  */
#define MSG_PEEK	MSG_PEEK
	MSG_DONTROUTE = 0x04,	/* Don't use local routing.  */
#define MSG_DONTROUTE	MSG_DONTROUTE
#ifdef __USE_GNU
							/* DECnet uses a different name.  */
							MSG_TRYHARD = MSG_DONTROUTE,
# define MSG_TRYHARD	MSG_DONTROUTE
#endif
							MSG_CTRUNC = 0x08,	/* Control data lost before delivery.  */
#define MSG_CTRUNC	MSG_CTRUNC
							MSG_PROXY = 0x10,	/* Supply or ask second address.  */
#define MSG_PROXY	MSG_PROXY
							MSG_TRUNC = 0x20,
#define	MSG_TRUNC	MSG_TRUNC
							MSG_DONTWAIT = 0x40, /* Nonblocking IO.  */
#define	MSG_DONTWAIT	MSG_DONTWAIT
							MSG_EOR = 0x80, /* End of record.  */
#define	MSG_EOR		MSG_EOR
							MSG_WAITALL = 0x100, /* Wait for a full request.  */
#define	MSG_WAITALL	MSG_WAITALL
							MSG_FIN = 0x200,
#define	MSG_FIN		MSG_FIN
							MSG_SYN = 0x400,
#define	MSG_SYN		MSG_SYN
							MSG_CONFIRM = 0x800, /* Confirm path validity.  */
#define	MSG_CONFIRM	MSG_CONFIRM
							MSG_RST = 0x1000,
#define	MSG_RST		MSG_RST
							MSG_ERRQUEUE = 0x2000, /* Fetch message from error queue.  */
#define	MSG_ERRQUEUE	MSG_ERRQUEUE
							MSG_NOSIGNAL = 0x4000, /* Do not generate SIGPIPE.  */
#define	MSG_NOSIGNAL	MSG_NOSIGNAL
							MSG_MORE = 0x8000,  /* Sender will send more.  */
#define	MSG_MORE	MSG_MORE
							MSG_WAITFORONE = 0x10000, /* Wait for at least one packet to return.*/
#define MSG_WAITFORONE	MSG_WAITFORONE
							MSG_FASTOPEN = 0x20000000, /* Send data in TCP SYN.  */
#define MSG_FASTOPEN	MSG_FASTOPEN

							MSG_CMSG_CLOEXEC = 0x40000000	/* Set close_on_exit for file
															descriptor received through
															SCM_RIGHTS.  */
#define MSG_CMSG_CLOEXEC MSG_CMSG_CLOEXEC
};



/* Signals.  */
#define	SIGHUP		1	/* Hangup (POSIX).  */
#define	SIGINT		2	/* Interrupt (ANSI).  */
#define	SIGQUIT		3	/* Quit (POSIX).  */
#define	SIGILL		4	/* Illegal instruction (ANSI).  */
#define	SIGTRAP		5	/* Trace trap (POSIX).  */
#define	SIGABRT		6	/* Abort (ANSI).  */
#define	SIGIOT		6	/* IOT trap (4.2 BSD).  */
#define	SIGBUS		7	/* BUS error (4.2 BSD).  */
#define	SIGFPE		8	/* Floating-point exception (ANSI).  */
#define	SIGKILL		9	/* Kill, unblockable (POSIX).  */
#define	SIGUSR1		10	/* User-defined signal 1 (POSIX).  */
#define	SIGSEGV		11	/* Segmentation violation (ANSI).  */
#define	SIGUSR2		12	/* User-defined signal 2 (POSIX).  */
#define	SIGPIPE		13	/* Broken pipe (POSIX).  */
#define	SIGALRM		14	/* Alarm clock (POSIX).  */
#define	SIGTERM		15	/* Termination (ANSI).  */
#define	SIGSTKFLT	16	/* Stack fault.  */
#define	SIGCLD		SIGCHLD	/* Same as SIGCHLD (System V).  */
#define	SIGCHLD		17	/* Child status has changed (POSIX).  */
#define	SIGCONT		18	/* Continue (POSIX).  */
#define	SIGSTOP		19	/* Stop, unblockable (POSIX).  */
#define	SIGTSTP		20	/* Keyboard stop (POSIX).  */
#define	SIGTTIN		21	/* Background read from tty (POSIX).  */
#define	SIGTTOU		22	/* Background write to tty (POSIX).  */
#define	SIGURG		23	/* Urgent condition on socket (4.2 BSD).  */
#define	SIGXCPU		24	/* CPU limit exceeded (4.2 BSD).  */
#define	SIGXFSZ		25	/* File size limit exceeded (4.2 BSD).  */
#define	SIGVTALRM	26	/* Virtual alarm clock (4.2 BSD).  */
#define	SIGPROF		27	/* Profiling alarm clock (4.2 BSD).  */
#define	SIGWINCH	28	/* Window size change (4.3 BSD, Sun).  */
#define	SIGPOLL		SIGIO	/* Pollable event occurred (System V).  */
#define	SIGIO		29	/* I/O now possible (4.2 BSD).  */
#define	SIGPWR		30	/* Power failure restart (System V).  */
#define SIGSYS		31	/* Bad system call.  */
#define SIGUNUSED	31


/* Identifier for system-wide realtime clock.  */
#   define CLOCK_REALTIME		0
/* Monotonic system-wide clock.  */
#   define CLOCK_MONOTONIC		1
/* High-resolution timer from the CPU.  */
#   define CLOCK_PROCESS_CPUTIME_ID	2
/* Thread-specific CPU-time clock.  */
#   define CLOCK_THREAD_CPUTIME_ID	3
/* Monotonic system-wide clock, not adjusted for frequency scaling.  */
#   define CLOCK_MONOTONIC_RAW		4
/* Identifier for system-wide realtime clock, updated only on ticks.  */
#   define CLOCK_REALTIME_COARSE	5
/* Monotonic system-wide clock, updated only on ticks.  */
#   define CLOCK_MONOTONIC_COARSE	6
/* Monotonic system-wide clock that includes time spent in suspension.  */
#   define CLOCK_BOOTTIME		7
/* Like CLOCK_REALTIME but also wakes suspended system.  */
#   define CLOCK_REALTIME_ALARM		8
/* Like CLOCK_BOOTTIME but also wakes suspended system.  */
#   define CLOCK_BOOTTIME_ALARM		9
/* Like CLOCK_REALTIME but in International Atomic Time.  */
#   define CLOCK_TAI			11

/* Flag to indicate time is absolute.  */
#   define TIMER_ABSTIME		1


#define	IPVERSION	4               /* IP version number */
#define	IP_MAXPACKET	65535		/* maximum packet size */


#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */


# define ifr_name	ifr_ifrn.ifrn_name	/* interface name 	*/
# define ifr_hwaddr	ifr_ifru.ifru_hwaddr	/* MAC address 		*/
# define ifr_addr	ifr_ifru.ifru_addr	/* address		*/
# define ifr_dstaddr	ifr_ifru.ifru_dstaddr	/* other end of p-p lnk	*/
# define ifr_broadaddr	ifr_ifru.ifru_broadaddr	/* broadcast address	*/
# define ifr_netmask	ifr_ifru.ifru_netmask	/* interface net mask	*/
# define ifr_flags	ifr_ifru.ifru_flags	/* flags		*/
# define ifr_metric	ifr_ifru.ifru_ivalue	/* metric		*/
# define ifr_mtu	ifr_ifru.ifru_mtu	/* mtu			*/
# define ifr_map	ifr_ifru.ifru_map	/* device map		*/
# define ifr_slave	ifr_ifru.ifru_slave	/* slave device		*/
# define ifr_data	ifr_ifru.ifru_data	/* for use by interface	*/
# define ifr_ifindex	ifr_ifru.ifru_ivalue    /* interface index      */
# define ifr_bandwidth	ifr_ifru.ifru_ivalue	/* link bandwidth	*/
# define ifr_qlen	ifr_ifru.ifru_ivalue	/* queue length		*/
# define ifr_newname	ifr_ifru.ifru_newname	/* New name		*/
# define _IOT_ifreq	_IOT(_IOTS(char),IFNAMSIZ,_IOTS(char),16,0,0)
# define _IOT_ifreq_short _IOT(_IOTS(char),IFNAMSIZ,_IOTS(short),1,0,0)
# define _IOT_ifreq_int	_IOT(_IOTS(char),IFNAMSIZ,_IOTS(int),1,0,0)