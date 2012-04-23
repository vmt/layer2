/* layer2.c - layer2 core routines.
 *
 * Copyright (c) 2005 Vivek Mohan <vivek@sig9.com>
 * All rights reserved.
 * See (LICENSE)
 */
#include <libnet.h>
#include <pthread.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

#include "layer2.h"

/* ----------------------------------------------------------------------------
 * Globals
 * =======
 * iface_ll_head:	iface linked list head.
 * iface_ll_tail:	iface linked list tail.
 * raw_sock:		LIBNET_RAW socket for writing ip packets.
 * raw_sock_mutex:	mutex to lock raw_sock.
 * con_mutex:		mutex to lock console.
 * errbuf:		buffer for error messages;
 * dst_add_s:		temp storage for destination network address.
 * msk_add_s:		temp storage for destination network mask address.
 * bgw_add_s:		temp storage for gateway network address.
 * ----------------------------------------------------------------------------
 */
static l2_iface_t* iface_ll_head = NULL;
static l2_iface_t* iface_ll_tail = NULL;
static libnet_t* raw_sock = NULL;
static pthread_mutex_t raw_sock_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t con_mutex = PTHREAD_MUTEX_INITIALIZER;
static char errbuf[PCAP_ERRBUF_SIZE | LIBNET_ERRBUF_SIZE];
static char addr_buf1[INET_ADDRSTRLEN];
static char addr_buf2[INET_ADDRSTRLEN];
static char addr_buf3[INET_ADDRSTRLEN];

/* ----------------------------------------------------------------------------
 * fprintf_r(): Thread safe version of fprintf().
 * ----------------------------------------------------------------------------
 */
#define fprintf_r(fp, n...) 			\
  do {						\
	pthread_mutex_lock(&con_mutex);		\
	fprintf(fp, ##n); 			\
	pthread_mutex_unlock(&con_mutex); 	\
  } while (0)

#define printd_r(f, n...) 			\
  do {						\
	pthread_mutex_lock(&con_mutex);		\
	printd(f, ##n); 			\
	pthread_mutex_unlock(&con_mutex); 	\
  } while (0)

/* ----------------------------------------------------------------------------
 * l2_init(device name) - Initialize l2. Allocates the libnet raw socket for
 * writing ip packets.
 * - Returns Non-zero on success, else 0.
 * ! NOT Thread Safe.
 * ----------------------------------------------------------------------------
 */
extern int l2_init()
{
	if ((raw_sock = libnet_init(LIBNET_RAW4, NULL, errbuf)) == NULL) {
		fprintf(stderr, "Error: Failed to create raw socket, %s.\n",
				errbuf);
		return(0);
	}
	return(1);
}

/* ----------------------------------------------------------------------------
 * l2_add_iface(device name) - Allocates an l2_iface_t structure corresponding 
 * to a device. Calls can be redundant, ie more than one attempts to add the 
 * same device is possible in which case the subsequent calls only pretend as 
 * though the device was added. * 
 * - dev_name:	The device name, "eth0", "eth1" etc.
 * - Returns NULL, if the device name does not exist or is not valid, or a 
 *   pointer to the structure if added.
 * ! NOT thread safe.
 * ----------------------------------------------------------------------------
 */
extern l2_iface_t* l2_add_iface(char* dev_name)
{
	l2_iface_t* iface;
	pcap_t* p;
	libnet_t* l;

	/* check if its already added */
	if ((iface = l2_dev_to_iface(dev_name)))
		return(iface);

	printd("Adding %s:", dev_name);

	/* Create pcap struct */
	if (! (p = pcap_open_live(dev_name, BUFSIZ, 1, 0, errbuf))) {
		fprintf(stderr, "Error: Failed to open, %s.\n", errbuf);
		return(NULL);
	}

	/* Create link layer libnet interface. It is opened in advanced mode
	 * so we can use the advanced libnet routines for writing frames to
	 * the interface.
	 */
	if (! (l = libnet_init(LIBNET_LINK_ADV, (char*)dev_name, errbuf))) {
		fprintf(stderr, 
			"Error: Failed to open libnet link interface, %s.\n", 
			errbuf);
		pcap_close(p);
		return(NULL);
	}

	/* allocate l2_iface_t */
	if (! (iface = (l2_iface_t*) malloc(sizeof(l2_iface_t)))) {
		fprintf(stderr, "Error: Out of memory, the mind boggles.\n");
		return(NULL);
	}

	/* init fields */
	strcpy(iface->dev_name, dev_name);
	iface->pcap_desc   = p;
	iface->ll_desc     = l;
	iface->next        = NULL;
	iface->route_head  = NULL;
	iface->route_tail  = NULL;
	iface->route_cnt   = 1;

	/* initialize mutex */
	pthread_mutex_init(&iface->mutex, NULL);

	/* lookup device ip, msk_addr 
	 * pcap_lookupnet() gives us only the subnet part of the ip address, so 
	 * we use libnet.
	 */
	pcap_lookupnet(dev_name, &iface->net_addr, &iface->msk_addr, errbuf);	
	iface->net_addr = libnet_get_ipaddr4(iface->ll_desc);

	printd("\tNet Address: %s Mask: %s", ntop(iface->net_addr, addr_buf1), 
			ntop(iface->msk_addr, addr_buf2));

	/* add to linked list */
	if (iface_ll_head == NULL) {
		iface_ll_head = iface;
		iface_ll_tail = iface;
	} else {
		iface_ll_tail->next = iface;
		iface_ll_tail = iface;
	}

	/* return pointer to interface */
	return(iface);
}

/* ----------------------------------------------------------------------------
 * l2_dev_to_iface(dev_name) - Performs a case insensitive search for dev_name
 * in the iface linked list.
 * - dev_name:	The device name, "eth0", "eth1" etc. 
 * - Returns a pointer to the structure corresponding to dev_name if it exists
 *   else returns a NULL.
 * ! Thread Safe.
 * ----------------------------------------------------------------------------
 */
extern l2_iface_t* l2_dev_to_iface(const char* dev_name)
{
	l2_iface_t *i = iface_ll_head;

	while (i) {
		if (strcasecmp(i->dev_name, dev_name) == 0)
			return i;
		else	i = i->next;
	}
	return NULL;
}

/* ----------------------------------------------------------------------------
 * l2_deinit() - Deallocates all ifaces listed in the global linked list and 
 * all the routing info associated with them.
 * - NOT Thread Safe.
 * ----------------------------------------------------------------------------
 */
extern void l2_deinit()
{
	l2_iface_t *i = iface_ll_head;
	l2_route_t *r;

	/* clear all interfaces */
	while (iface_ll_head) {
		i = iface_ll_head;
		r = i->route_head;
		
		/* clear routes */
		while (i->route_head) {
			r = i->route_head;
			i->route_head = i->route_head->next;
			free(r);
		}

		iface_ll_head = i->next;
		pcap_close(i->pcap_desc);
		libnet_destroy(i->ll_desc);

		free(i);		
	}

	/* destroy global raw socket */
	libnet_destroy(raw_sock);
}

/* ----------------------------------------------------------------------------
 * l2_add_route(l2_iface_t obj) - Adds a new route associated with frames 
 * arriving at obj.
 * - iface: packet capture device.
 * - dst_addr: packet's destination network address.
 * - msk_addr: network mask for destination network address.
 * - bgw_addr: border gateway to which the packet is to be transported to.
 * - link_iface: interface to which the packet is to be routed to.
 * - eth_proto_arp, eth_proto_rarp, eth_proto_dec - 1 = route protocol, 0 = 
 *   discard protocol.
 * - Returns pointer to new route if successful, else NULL.
 * ! NOT Thread Safe.
 * ----------------------------------------------------------------------------
 */
extern l2_route_t* l2_add_route(l2_iface_t* iface, u_long dst_addr, u_long msk_addr, 
				u_long bgw_addr, l2_iface_t* link_iface,
				int eth_proto_arp, int eth_proto_rarp,
				int eth_proto_dec)
{
	l2_route_t* r;

	if ((r = (l2_route_t*) malloc(sizeof(l2_route_t))) == NULL) {
		fprintf(stderr, "Error: Out of memory, the mind boggles.\n");
		return(NULL);
	}

	r->dst_addr       = dst_addr;
	r->msk_addr       = msk_addr;
	r->bgw_addr       = bgw_addr;
	r->iface          = link_iface;
	r->eth_proto_arp  = eth_proto_arp;
	r->eth_proto_rarp = eth_proto_rarp;
	r->eth_proto_dec  = eth_proto_dec;
	r->next           = NULL;

	/* create filter */
	ntop(dst_addr, addr_buf1);
	ntop(msk_addr, addr_buf2);
	ntop(iface->net_addr, addr_buf3);

	sprintf(r->filter, 
			"((ether proto \\ip %s %s %s) "
			"and ((dst net %s mask %s) "
			"or (dst net %s and ip proto %d)))",

			(eth_proto_arp)  ? "or \\arp" : "",
			(eth_proto_rarp) ? "or \\rarp" : "",
			(eth_proto_dec)  ? "or \\decnet" : "",
			addr_buf1,
			addr_buf2,
			addr_buf3,
			L2_PROTO_NUM
		);

	/* add to list */
	if (iface->route_head == NULL) {
		iface->route_tail = (iface->route_head = r);
	} else {
		iface->route_tail->next = r;
		iface->route_tail = r;
	}

	/* increase the route count */
	iface->route_cnt++;

	return(r);
}

/* ----------------------------------------------------------------------------
 * l2_set_filter() - Goes through each iface in the linked list, generates 
 * pcap filter rules and compiles it for that iface.
 * - Returns Non-zero on success, else 0.
 * ! NOT Thread Safe
 * ----------------------------------------------------------------------------
 */
extern int l2_set_filters()
{
	l2_iface_t *i = iface_ll_head;

	while (i) {
		l2_route_t *r = i->route_head;
		struct bpf_program fp;
		char *f_buf;
		if ((f_buf = (char*) malloc(L2_FILTER_BUFSIZ * i->route_cnt))
			== NULL) {
			fprintf(stderr, "Error: Out of memory, the mind boggles.\n");
			return(0);			
		}

		*f_buf = 0;

		if (r) {
			strcat(f_buf, r->filter);
			r = r->next;
		}
		while (r) {
			strcat(f_buf, " or ");
			strcat(f_buf, r->filter);
			printd("%s", f_buf);
			r = r->next;
		}

		printd("Setting filter for %s: %s", i->dev_name, f_buf);
		
		/* Compile the filter script */
		if (pcap_compile(i->pcap_desc, &fp, f_buf, 0, i->net_addr) == -1) { 
			fprintf(stderr, "Error: Failed to compile filter, %s.\n", 
						pcap_geterr(i->pcap_desc));
			return(0);
		}

		/* Set the compiled program as the filter */
		if (pcap_setfilter(i->pcap_desc, &fp) == -1) { 
			fprintf(stderr, "Error: Failed to set filter, %s.\n", 
						pcap_geterr(i->pcap_desc));
			return(0);
		}

		free(f_buf);
		i = i->next;
	}

	return(1);
}

/* ----------------------------------------------------------------------------
 * frame_data(arg) - Extracts data from frame into l2_frame_t object.
 * f: The Frame data object.
 * packet: Captured Packet of data.
 * ! Thread Safe 
 * [TODO] Add support for RARP, DEC protocols.
 * ----------------------------------------------------------------------------
 */
static void frame_data(l2_frame_t *f, const u_char* packet)
{
	f->frame_ptr = (void*)packet;
	f->eth_header = (struct ether_header*) packet;
	f->eth_type = ntohs(f->eth_header->ether_type);

	if (f->eth_type == ETHERTYPE_IP) {

		f->ip_header = (struct ip*) (packet + sizeof(struct ether_header));
		f->ip_proto = f->ip_header->ip_p;
		f->ip_len = ntohs(f->ip_header->ip_len);
		f->payload = packet + sizeof(struct ether_header) + sizeof(struct ip);
		f->ip_src_addr = f->ip_header->ip_src.s_addr;
		f->ip_dst_addr = f->ip_header->ip_dst.s_addr;

	} else if (f->eth_type == ETHERTYPE_ARP) {

		f->arp = (struct ether_arp*) (packet + sizeof(struct ether_header));
		memcpy((void*)&f->ip_src_addr, (const void*)f->arp->arp_spa, sizeof(f->ip_src_addr));
		memcpy((void*)&f->ip_dst_addr, (const void*)f->arp->arp_tpa, sizeof(f->ip_dst_addr));
	} else {
		fprintf_r(stderr, "Error: (BUG).\n");
	}

	ether_ntoa_r((struct ether_addr*)f->eth_header->ether_shost, f->eth_addr_src);
	ether_ntoa_r((struct ether_addr*)f->eth_header->ether_dhost, f->eth_addr_dst);
}

/* ----------------------------------------------------------------------------
 * l2_recv_packet(arg) - pcap_loop callback function.
 * ! Thread Safe
 * ----------------------------------------------------------------------------
 */
static void l2_recv_packet(u_char *arg, const struct pcap_pkthdr *pk_header, 
				const u_char *packet)
{
	l2_iface_t* iface;
	l2_frame_t  frame;
	char dst_addr_s[INET_ADDRSTRLEN];
	char src_addr_s[INET_ADDRSTRLEN];
	l2_route_t* route;
	size_t size;

	/* extract values from packet */
	size = pk_header->caplen;
	iface = (l2_iface_t*) arg;
	frame_data(&frame, packet);

	printd_r("%s Recvd Frame: %d bytes ", iface->dev_name, size);

	if (frame.eth_type == ETHERTYPE_IP) {
		printd_r("\tType = IP");
		/* strip if its an L2 packet */
		if (frame.ip_proto == L2_PROTO_NUM) {
			printd_r("\tProtocol = L2, Stripping");
			frame_data(&frame, frame.payload);
			size = size - sizeof(struct ether_header) 
				- sizeof(struct ip);
		}
	} else if (frame.eth_type == ETHERTYPE_ARP) {
		printd_r("\tType = ARP");
	} else if (frame.eth_type == ETHERTYPE_REVARP) {
		printd_r("\tType = REVARP");
	} else {
		printd_r("\tType = UNKNOWN");
		return;
	}

	printd_r("\t%s->%s", ntop(frame.ip_src_addr, dst_addr_s), ntop(frame.ip_dst_addr, src_addr_s));

	/* route */
	route = iface->route_head;
	while (route) {
		if ((route->dst_addr & route->msk_addr) == (frame.ip_dst_addr & route->msk_addr))
			break;
		route = route->next;
	}

	/* No route for packet */
	if (! route) {
		printd_r("No Route Found!");
		return;
	}

	printd_r("\tRouting frame, size: %d bytes", size);
	/* if gateway */
	if (route->bgw_addr) {

		ssize_t s;
		int tag;
		printd_r("\t\tTo Border Gateway: %s", ntop(route->bgw_addr, dst_addr_s));

		pthread_mutex_lock(&raw_sock_mutex);
		if ((tag = libnet_build_ipv4(
			LIBNET_IPV4_H + size,  /* length */
			0,			/* TOS */
			242,			/* IP ID */
			0,			/* IP Frag */
			64,			/* TTL */
			L2_PROTO_NUM,		/* protocol */
			0,			/* checksum */
			0,			/* source IP */
			route->bgw_addr,	/* destination IP */
			frame.frame_ptr,	/* payload */
			size,			/* payload size */
			raw_sock,		/* libnet handle */
			iface->ptag)) == -1) {	/* libnet id */
			fprintf(stderr, "Failed to build ipv4 packet, %s.\n", 
				libnet_geterror(raw_sock));
		}		
		if (tag >= 0)
			iface->ptag = tag;
		if ((s = libnet_write(raw_sock)) == -1) 
			fprintf_r(stderr, "Failed to write packet, %s.\n", 
				libnet_geterror(raw_sock));
		pthread_mutex_unlock(&raw_sock_mutex);

	} else if (route->iface) {
		printd_r("\t\tTo IFace: %s", route->iface->dev_name);
		if (libnet_adv_write_link(route->iface->ll_desc, 
			frame.frame_ptr, size) == -1) {
			fprintf_r(stderr, "Failed to write packet, %s.\n", 
				libnet_geterror(route->iface->ll_desc));
		}
	}
}

/* ----------------------------------------------------------------------------
 * iface_thread(arg) - Entry point for thread per iface. 
 * - arg: pointer to the l2_iface_t object.
 * ! Thread Safe.
 * ----------------------------------------------------------------------------
 */
static void* iface_thread(void* arg)
{
	l2_iface_t* iface = (l2_iface_t*) arg;
	if (pcap_loop(iface->pcap_desc, -1, l2_recv_packet, (void*)iface) < 0)
		pcap_perror(iface->pcap_desc, "Error: ");
	return NULL;
}

/* ----------------------------------------------------------------------------
 * l2_route() - Spawns one thread per interface added to the global list.
 * - Returns Non-zero on success, else 0.
 * ! NOT Thread Safe.
 * ----------------------------------------------------------------------------
 */
extern int l2_route()
{
	l2_iface_t *i = iface_ll_head;

	/* spawn thread per interface */
	while (i) {
		i->ptag = 0;
		if (pthread_create(&i->thread, NULL, iface_thread, (void*)i)) {
			fprintf_r(stderr, "Error: Failed to spawn thread. Aborting.\n");
			return(0);			
		}
		i = i->next;
	}
	/* wait for them to get over. */
	i = iface_ll_head;
	while (i) {
		int r;
		pthread_join(i->thread, (void **)&(r));
		i = i->next;
	}

	return(1);
}
