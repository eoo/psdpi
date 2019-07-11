#ifndef PSIP_H
#define PSIP_H

#include <stdint.h>
#include <arpa/inet.h>
#include "l3l4.h"

#define ETHERNET_OFFSET 14
#define IPV6_HEADER_SIZE 40

typedef struct ipv4_header
{
        uint8_t  ip_vhl;                 	/* version << 4 | header length >> 2 */
#define IP_HL(ip)          	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
        uint8_t  ip_tos;                 	/* type of service */
        uint16_t ip_len;                 	/* total length */
        uint16_t ip_id;                  	/* identification */
        uint16_t ip_off;                 	/* fragment offset field */
        uint8_t  ip_ttl;            	    /* time to live */
        uint8_t  ip_p;          	        /* protocol */
        uint16_t ip_sum;    	            /* checksum */
        struct in_addr ip_src, ip_dst;  	/* source and dest address */
} ipv4_header_t;

typedef struct ipv6_header
{
	uint32_t offset;
	uint16_t payload_len;
	uint8_t next_header;					// Transport Layer Protocol
	uint8_t hop_limit;
	struct in6_addr ip_src;					// 128-bit source address
	struct in6_addr ip_dst;					// 128-bit destination address
} ipv6_header_t;


typedef struct tcp_header 
{
        uint16_t src_port;         		   /* source port */
        uint16_t dst_port;        	 	   /* destination port */
        uint32_t seq_num;       	   	   /* sequence number */
        uint32_t ack_num;   	       	   /* acknowledgement number */
        uint8_t  hdr_len; 	       			/* header length and reserved */
#define HDR_LEN(tcp)      (((tcp)->hdr_len & 0xf0) >> 4)
        uint8_t  flags;
        uint16_t win_size;                 	/* window size*/
        uint16_t chk_sum;                 	/* checksum */
        uint16_t urg_ptr;                	/* urgent pointer */
} tcp_header_t;

extern uint8_t ps_parse_ipv4 (const uint8_t * packet,  l3l4_quin_t * quin);
extern uint8_t ps_parse_ipv6 (const uint8_t * packet,  l3l4_quin_t * quin);

#endif
