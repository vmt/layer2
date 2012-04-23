/* layer2.h - layer2 core definitions
 *
 * Copyright (c) 2005 Vivek Mohan <vivek@sig9.com>
 * All rights reserved.
 * See (LICENSE)
 */
#ifndef _LAYER2_H_
#define _LAYER2_H_

#include <libnet.h>
#include <pcap.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

/* ----------------------------------------------------------------------------
 * L2_PROTO_NUM		This is the protocol number used by L2 to transport a 
 *			frame from one border gateway to another. 
 * L2_FILTER_BUFSIZ	Buffer size of a filter rule associated with a route.
 * ----------------------------------------------------------------------------
 */
#define L2_PROTO_NUM		64
#define L2_FILTER_BUFSIZ	256

/* ----------------------------------------------------------------------------
 * l2_route_t - Routing information associated with a interface.
 *
 * dst_addr:	The destination address of the packet to be routed.
 * msk_addr:	The mask associated with the address.
 * bgw_addr:	Border gateway address.
 * iface:	Pointer to an interface object.
 * eth_proto_arp: Non-zero, filter ARP packets.
 * eth_proto_rarp: Non-zero, filter REVARP packets.
 * eth_proto_dec: Non-zero, filter DEC packets.
 * filter:	Pcap filter rule for this route.
 * next:	Pointer to the next object for linked lists.
 * ----------------------------------------------------------------------------
 */
typedef struct l2_route_t 
{
	u_long			dst_addr;
	u_long			msk_addr;
	u_long			bgw_addr;
	struct l2_iface_t*	iface;
	int			eth_proto_arp;
	int			eth_proto_rarp;
	int			eth_proto_dec;
	char			filter[L2_FILTER_BUFSIZ];
	struct l2_route_t*	next;
} l2_route_t;

/* ----------------------------------------------------------------------------
 * l2_iface_t - Interface object. This stucture defines an object associated 
 * with an interface that participates in this program.
 *
 * dev_name:	Interface device name, eg "eth0", "eth1", "tap0" etc.
 * net_addr:	network address of the interface.
 * msk_addr:	net msk_addr of interface.
 * pcap_desc:	This is the libpcap pcap_t context block associated with 
 * 		the interface.
 * ll_desc:	The libnet link layer interface structure. 
 * mutex:	Mutext lock for exclusive iface write access.
 * next:	'next' for linked lists.
 * route_head:	route rules list head.
 * route_tail:	route rules list tail.
 * ----------------------------------------------------------------------------
 */
typedef struct l2_iface_t 
{	
	char			dev_name[32];
	bpf_u_int32		net_addr;
	bpf_u_int32		msk_addr;
	pcap_t*			pcap_desc;
	libnet_t*		ll_desc;
	pthread_mutex_t		mutex;
	pthread_t		thread;
	libnet_ptag_t		ptag;
	struct l2_route_t*	route_head;
	struct l2_route_t*	route_tail;
	unsigned int		route_cnt;
	struct l2_iface_t*	next;
} l2_iface_t;

/* ----------------------------------------------------------------------------
 * l2_frame_t - Holds essential data extracted from an ether frame. This is for
 * internal use, and does not map any protocol structures.
 *
 * frame_ptr:	 Points to the packet in memory.
 * size:	 Size of Frame.
 * eth_header:	 Points to the ether header.
 * eth_type:	 Ethernet type (IP/ARP/RARP/DEC)
 * eth_addr_src: Source Ethernet address.
 * eth_addr_dst: Destination Ethernet address.
 * arp:		 Points to the arp header if the protocol is ARP.
 * ip_header:	 Points to ip header.
 * ip_proto:	 The upper layer protocol for the IP packet.
 * ip_len:	 Overall length of the IP packet.
 * ip_dst_addr:	 Destination IP Address of IP Packet.
 * ip_src_addr:	 Source IP Address of IP Packet.
 * payload:	 Pointer to the packet payload.
 * ----------------------------------------------------------------------------
 */
typedef struct l2_frame_t 
{
	void*			frame_ptr;
	size_t			size;
	struct ether_header*	eth_header;
	u_int16_t		eth_type;
	char 			eth_addr_src[32];
	char 			eth_addr_dst[32];
	struct ether_arp* 	arp;
	struct ip* 		ip_header;
	u_int8_t		ip_proto;
	u_short			ip_len;
	u_long			ip_dst_addr;
	u_long			ip_src_addr;
	const u_char*		payload;
} l2_frame_t;

/* ----------------------------------------------------------------------------
 * Global functions. Prefix = l2_
 * ----------------------------------------------------------------------------
 */
extern int l2_init();
extern l2_iface_t* l2_dev_to_iface(const char*);
extern l2_iface_t* l2_add_iface(char*);
extern l2_route_t* l2_add_route(l2_iface_t*, u_long, u_long, u_long, l2_iface_t*, int, int, int);
extern int l2_set_filters();
extern int l2_route();
extern void l2_deinit();

/* ----------------------------------------------------------------------------
 * ntop() - Converts an ip address in network form to presentation form.
 * - ip: The ip address in network byte order.
 * - buf: The buffer to which the converted form is to be stored.
 * - Returns, pointer to buf if successful else NULL.
 * ! Thread Safe.
 * ! Assumes buf is atleast INET_ADDRSTRLEN bytes long.
 * ----------------------------------------------------------------------------
 */
static inline char* ntop(u_long ip, char* buf)
{
	struct in_addr in;
	in.s_addr = ip;
	if (inet_ntop(AF_INET, (const void *) &in, buf, INET_ADDRSTRLEN) == NULL)
		return(NULL);
	return buf;
}

/* ----------------------------------------------------------------------------
 * pton() - Converts an ip address in presentation form to network form.
 * - buf: The buffer which contains the ip address in presentation form
 * - ip: pointer to u_long to which ip address will be stored.
 * - Returns, pointer tp ip address in network byte order if successful 
 *   else NULL.
 * ! Thread Safe.
 * ----------------------------------------------------------------------------
 */
static inline u_long* pton(char* buf, u_long* ip)
{
	struct in_addr in;
	if (inet_pton(AF_INET, buf, &in) <= 0)
		return(NULL);
	*ip = in.s_addr;
	return ip;
}

/* ----------------------------------------------------------------------------
 * _printd() - Print function for debugging.
 * - line: Line number.
 * - file: Source File Name.
 * - fmt: Output format.
 * ! NOT Thread Safe.
 * ----------------------------------------------------------------------------
 */
static inline void _printd(unsigned int line, const char* file,
			  	const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	printf("===> ");
#ifdef L2_VERBOSE_POS
	printf("%s:%d ", file, line);
#endif
	vprintf(fmt, ap);
	printf("\n");
	va_end(ap);
}

/* ----------------------------------------------------------------------------
 * printd(): Wrapper for _printd();
 * printd_r(): Thread safe version of printd().
 * ----------------------------------------------------------------------------
 */
#ifdef L2_VERBOSE
#  define printd(fmt, n...) _printd(__LINE__, __FILE__, fmt, ##n)
#else
#  define printd(fmt, n...)
#endif
#endif
