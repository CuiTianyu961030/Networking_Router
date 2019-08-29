#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code, u32 sip)
{
	//fprintf(stderr, "TODO: malloc and send icmp packet.\n");

	int offset;
	char* icmp_packet;
	struct ether_header* eh_temp = (struct ether_header*)(in_pkt);
	struct iphdr* iph_temp = (struct iphdr*)(in_pkt + ETHER_HDR_SIZE);
	struct icmphdr* icmp_temp = (struct icmp*)(in_pkt + ETHER_HDR_SIZE + IP_HDR_SIZE(iph_temp));
	if(type == 0 && code == 0){
		icmp_packet = (char*)malloc(len);
		struct ether_header* eh = (struct ether_header*)icmp_packet;
		struct iphdr* iph = (struct iphdr*)(icmp_packet + ETHER_HDR_SIZE);
		struct icmphdr* icmph = (struct icmphdr*)(icmp_packet + ETHER_HDR_SIZE + IP_HDR_SIZE(iph_temp));
		eh->ether_type = htons(ETH_P_IP);
		memcpy(eh->ether_shost, eh_temp->ether_dhost, ETH_ALEN);
		memcpy(eh->ether_dhost, eh_temp->ether_shost, ETH_ALEN);
		u32 daddr_temp = sip;
		u32 saddr_temp = ntohl(iph_temp->saddr);
		ip_init_hdr(iph,daddr_temp,saddr_temp,len - ETHER_HDR_SIZE,IPPROTO_ICMP);	
		icmph->type = 0;
		icmph->code = 0;
		
		memcpy(((char*)icmph) + 4,((char*)icmp_temp) + 4,len-ETHER_HDR_SIZE-IP_HDR_SIZE(iph_temp));

		icmph->checksum=icmp_checksum(icmph,len-ETHER_HDR_SIZE-IP_HDR_SIZE(iph_temp));
		offset = len;		
	}
	else{
		offset = ETHER_HDR_SIZE + 2*IP_HDR_SIZE(iph_temp) + 16;
		icmp_packet = (char*)malloc(ETHER_HDR_SIZE + IP_HDR_SIZE(iph_temp) + 8 + IP_HDR_SIZE(iph_temp) + 8);
		struct ether_header* eh = (struct ether_header*)icmp_packet;
		struct iphdr* iph = (struct iphdr*)(icmp_packet + ETHER_HDR_SIZE);
		struct icmphdr* icmph = (struct icmphdr*)(icmp_packet + ETHER_HDR_SIZE + IP_HDR_SIZE(iph_temp));
		eh->ether_type = htons(ETH_P_IP);
		memcpy(eh->ether_dhost, eh_temp->ether_shost, ETH_ALEN);
		memcpy(((char*)icmph) + 8, (char*)iph_temp,IP_HDR_SIZE(iph_temp) + 8);
		u32 daddr_temp = sip;
		u32 saddr_temp = ntohl(iph_temp->saddr);
		ip_init_hdr(iph,daddr_temp,saddr_temp,offset - ETHER_HDR_SIZE,IPPROTO_ICMP);	
		memset(((char*)icmph) + 4, 0, 4);
		icmph->type = type;
		icmph->code = code;
		icmph->checksum=icmp_checksum(icmph,offset-ETHER_HDR_SIZE-IP_HDR_SIZE(iph_temp));				
	}
	ip_send_packet(icmp_packet, offset);
}
