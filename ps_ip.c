#include <stdio.h>
#include <string.h>
#include "ps_ip.h"
#include "hash.h"

void ps_parse_tcp(const uint8_t *, const uint8_t, l3l4_quin_t *);					// declaration

void ps_parse_ipv4(const uint8_t * packet, l3l4_quin_t * quin)
{
	const ipv4_header_t *ip;
	int ipv4_header_size;

	ip = (ipv4_header_t*)(packet + ETHERNET_OFFSET);

	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	ipv4_header_size = IP_HL(ip)*4;

	// Find out the Protocol
	switch(ip->ip_p)
	{
		case 0x06:
			printf("   Protocol: TCP\n");
			ps_parse_tcp (packet, ipv4_header_size, quin);							// If TCP, also parse it
			break;
		case 0x11:
			printf("   Protocol: UDP\n");
			break;
		case 0x01:
			printf("   Protocol: ICMP\n");
			break;
		default:
			printf("   Protocol: unknown\n");
			break;
	}
	
	//UPDATE QUINTUPLE
	quin->src_ip.version = l3_ip_v4;
	quin->src_ip.un.v4.ip = ip->ip_src.s_addr;
	quin->dst_ip.un.v4.ip = ip->ip_dst.s_addr;
	quin->proto = ip->ip_p;

	return;
}



void ps_parse_ipv6 (const uint8_t * packet, l3l4_quin_t * quin)
{
	const ipv6_header_t * ip;
	ip = (ipv6_header_t*)(packet + ETHERNET_OFFSET);

	char addr[46];

	printf("       From: %s\n", inet_ntop(AF_INET6, &(ip->ip_src), addr, 46));
	printf("         To: %s\n", inet_ntop(AF_INET6, &(ip->ip_dst), addr, 46));

	switch(ip->next_header)
	{
		case 0x06:
			printf("   Protocol: TCP\n");
			ps_parse_tcp (packet, IPV6_HEADER_SIZE, quin);							// If TCP, also parse it
			break;
		case 0x11:
			printf("   Protocol: UDP\n");
			break;
		case 0x01:
			printf("   Protocol: ICMP\n");
			break;
		default:
			printf("   Protocol: unknown\n");
			break;
	}

	//update quintuple

	quin->src_ip.version = l3_ip_v6;
	//quintuple->src_ip.un.v6.ip = (uint32_t)*(uint32_t*)&ip->ip_src.s6_addr;
	//quintuple->dst_ip.un.v6.ip = (uint32_t)*(uint32_t*)&ip->ip_dst.s6_addr;
	memcpy(quin->src_ip.un.v6.ip, ip->ip_src.s6_addr, 16);
	memcpy(quin->dst_ip.un.v6.ip, ip->ip_dst.s6_addr, 16);
	quin->proto = ip->next_header;
	
	return;
}





void ps_parse_tcp(const uint8_t * packet, const uint8_t ip_size, l3l4_quin_t * quin)
{
	tcp_header_t * tcp;
	tcp = (tcp_header_t*)(packet + ETHERNET_OFFSET + ip_size);

	printf("   Src port: %d\n", ntohs(tcp->src_port));
	printf("   Dst port: %d\n", ntohs(tcp->dst_port));

	quin->src_port = tcp->src_port;
	quin->dst_port = tcp->dst_port;
}


void update_quintuple(l3l4_quin_t * quintuple, char * layer)
{

}