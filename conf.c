/* conf.c - "config.conf" reading routines. (conf.h)
 *
 * Copyright (c) 2005 Vivek Mohan <vivek@sig9.com>
 * All rights reserved.
 * See (LICENSE)
 */

#include <string.h>
#include <assert.h>
#include "conf.h"
#include "layer2.h"

/* ----------------------------------------------------------------------------
 * skip_spaces(l) - Skips all whitespace characters.
 * - l:	The line buffer.
 * - Returns a pointer to the next non white space character, NULL at end of 
 *   string.
 * ----------------------------------------------------------------------------
 */
static char* skip_spaces(char *l)
{
	while (*l && isspace(*l))
		++l;
	if (*l == 0)
		return NULL;
	return l;
}

/* ----------------------------------------------------------------------------
 * parse(input, buf) - Parses the input string for a group of 
 * non-whitespace characters. It excludes a few delimiters - "[", "]", ":" 
 * from the grouping. The routine also skips spaces after the group till, 
 * either the end of string or the begining of next group.
 * - input: The input buffer.
 * - buf: The token buffer, ie the buffer to which the parsed token is to be
 *        stored.
 * - Returns pointer to new position for input buffer, NULL if end of input.
 * ----------------------------------------------------------------------------
 */
static char* parse(char* input, char* buf)
{
	if ((input = skip_spaces(input)) == NULL)
		return NULL;
	while (*input && ! isspace(*input) && 
		*input != '[' && *input != ']' && *input != ':')
		*buf++ = *input++;
	*buf = 0;
	if ((input = skip_spaces(input)) == NULL)
		return NULL;
	if (*input == 0)
		return NULL;
	return input;
}

/* ----------------------------------------------------------------------------
 * l2_parse_conf_line(char *l, int sub) - This routine is to parse a line from 
 * the configuration file and add routing information .
 * - l: A line from the configuration file.
 * - sub: 1 = its a subsection header, 0 = not.
 * - Returns 1 on success, 0 on failure.
 * ----------------------------------------------------------------------------
 */
static int parse_conf_line(char* l, int sub)
{
	static int in_sub = 0;
	static char parse_buf[1024];
	static l2_iface_t* device = NULL;
	static int eth_proto_arp = 0;
	static int eth_proto_rarp = 0;
	static int eth_proto_dec = 0;
	static u_long r_dst_addr;
	static u_long r_msk_addr;
	static u_long r_bgw_addr;
	static l2_iface_t* r_iface;
	static char r_dst_addr_s[INET_ADDRSTRLEN];
	static char r_msk_addr_s[INET_ADDRSTRLEN];
	static char r_bgw_addr_s[INET_ADDRSTRLEN];

	if (sub) {
	
		in_sub = 0;
		eth_proto_arp = 0;
		eth_proto_rarp = 0;
		eth_proto_dec = 0;

		/* Interface */
		l++;
		if (! (l = parse(l, parse_buf)))
			return(0);

		/* Try to add, abort if not possible */
		if ((device = l2_add_iface(parse_buf)) == NULL) {
			fprintf(stderr, "Error: Device %s invalid/cannot be used.\n", parse_buf);
			return(0);
		}		

		/* Expect delimiter */
		if (*l != ':') {
			fprintf(stderr, "Error: Syntax error, ':' expected.\n");
			return(0);
		}
		l++;

		if ((l = skip_spaces(l)) == NULL)
			return(0);

		while (*l != ']') {
			if (! (l = parse(l, parse_buf))) {
				fprintf(stderr, "Error: Syntax error, ']' expected.\n");
				return(0);
			}
			if (strcmp(parse_buf, "ip") == 0)
				;
			else if (strcmp(parse_buf, "arp") == 0)
				eth_proto_arp = 1;
			else if (strcmp(parse_buf, "rarp") == 0)
			 	eth_proto_rarp = 1;
			else if (strcmp(parse_buf, "dec") == 0)
				eth_proto_dec = 1;
			else {
				fprintf(stderr, "Error: Unknown Ethernet Protocol, "
						"'ip/arp/rarp/dec' expected. Ignoring.\n");
			}	
		}
		
		in_sub = 1;
		return(1);

	} else if (in_sub) {

		r_dst_addr = 0;
		r_msk_addr = 0;
		r_bgw_addr = 0;
		r_iface = NULL;

		/* parse route, destination ip address */
		if (! (l = parse(l, parse_buf)))
			return(0);
		if (! pton(parse_buf, &r_dst_addr))
			return(0);
		strncpy(r_dst_addr_s, parse_buf, sizeof(r_dst_addr_s));

		/* net mask, */
		if (! (l = parse(l, parse_buf)))
			return(0);
		if (! pton(parse_buf, &r_msk_addr))
			return(0);
		strncpy(r_msk_addr_s, parse_buf, sizeof(r_msk_addr_s));

		/* border gateway address */
		if (! (l = parse(l, parse_buf)))
			return(0);
		if (strcmp("*", parse_buf) == 0) {
			r_bgw_addr = 0;
		} else { 
			if (! pton(parse_buf, &r_bgw_addr))
				return(0);
			strncpy(r_bgw_addr_s, parse_buf, sizeof(r_bgw_addr_s));
		}

		/* interface */
		if (! (l = parse(l, parse_buf))) 
			return(0);
		if (strcmp("*", parse_buf) == 0) {
			r_iface = NULL;
			if (r_bgw_addr == 0) {
				fprintf(stderr, "Error: You must specify a Gateway or an Interface.\n");
				return(0);
			}
		} else if ((r_iface = l2_add_iface(parse_buf)) == 0) {
			fprintf(stderr, "Error: Invalid Interface, %s.\n", parse_buf);
			return(0);
		}

		/* Check end of line, if not- error */
		if (*l != '.')
			return(0);

		/* add route */
		printd( "Adding Route+Filter Rule:");
		printd( "\tIFACE: %s, DEST-NET: %s, MASK: %s,",
			device->dev_name,
			r_dst_addr_s,
			r_msk_addr_s);
		printd( "\tBGW: %s, R-IFACE: %s, FILTER: (ip, %s, %s, %s).",
			r_bgw_addr_s,
			(r_iface) ? r_iface->dev_name : "*",
			(eth_proto_arp) ? "arp" : "*",
			(eth_proto_rarp) ? "rarp" : "*",
			(eth_proto_dec) ? "dec" : "*");

		if (l2_add_route(device, r_dst_addr, r_msk_addr, r_bgw_addr, r_iface, 
				eth_proto_arp, eth_proto_rarp, eth_proto_dec) == NULL) {
			fprintf(stderr, "Error: Failed to add route. (BUG)\n");
			return(0);
		}

		return(1);
	}
	
	return(0);
}

/* ------------------------------------------------------------------------
 * l2_parse_conf(f*) - Parses a configuration file. Reads the file
 * line by line and calls parse_conf_line().
 * - f: File pointer to config file.
 * [TODO] - Extreme case, truncate config line if its length exceeds 1024.
 * -------------------------------------------------------------------------
 */
extern int l2_parse_conf(FILE* f)
{
	static unsigned int lineno = 0;
	static char conf_line_buf[1024];
	int c, i = 0;
	int sub = 0;
	assert(f != NULL);

	printd("Reading Config File...");

start:
	sub = 0;
	conf_line_buf[i = 0] = 0;
	c = 0;

	for (; (c = fgetc(f)) != -1 && isspace(c);)
		if (c == '\n')
			goto start;
	if (c == -1)
		return(1);
	if (c == '[')
		sub = 1;

	/* if its a comment, don't even bother */
	if (c != '#') {
		do { 
			conf_line_buf[i++] = c; 
			c = fgetc(f);
		} while (c != -1 && c != '\n' && c != '#');

		/* add an end of line marker */
		conf_line_buf[i++] = ' ';
		conf_line_buf[i++] = '.';
		conf_line_buf[i]   = 0  ;
	}

	/* if scanning stopped b'cos of a comment, drop till line break */
	if (c == '#') {
		while (c != '\n' && c != -1)
			c = fgetc(f);
	}

	++lineno;

	if (i) {
		if ( ! parse_conf_line(conf_line_buf, sub)) {
			fprintf(stderr, "Error: Config file parser aborted at line %d.\n", 
				lineno);
			return(0);
		}
	}
	if (c == -1)
		return(1);
	else goto start;
}
