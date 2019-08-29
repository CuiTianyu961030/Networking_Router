#include "arp.h"
#include "base.h"
#include "types.h"
#include "packet.h"
#include "ether.h"
#include "arpcache.h"
#include "icmp.h"
#include "rtable.h"
#include "ip.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	char* packet;
	packet = (char*)malloc(sizeof(struct ether_header) + sizeof(struct ether_arp));
	struct ether_header* eh;
	eh = (struct ether_header*)(packet);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	u8 temp = 255;
	for(int q = 0; q < ETH_ALEN; q++) eh->ether_dhost[q] = temp;
	eh->ether_type = htons(ETH_P_ARP);

	struct ether_arp* eh_arp;
	eh_arp = (struct ether_arp*)(packet + ETHER_HDR_SIZE);
	eh_arp->arp_hrd = htons((u16)1);
	eh_arp->arp_pro = htons((u16)0x0800);
	eh_arp->arp_hln = (u8)6;
	eh_arp->arp_pln = (u8)4;
	eh_arp->arp_op = htons((u16)0x01);
	memcpy(eh_arp->arp_sha, iface->mac, ETH_ALEN);
	eh_arp->arp_spa = htonl(iface->ip);
	eh_arp->arp_tpa = htonl(dst_ip);
	memset(eh_arp->arp_tha,0,ETH_ALEN);
	iface_send_packet(iface, packet, ETHER_HDR_SIZE+sizeof(struct ether_arp));
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{	
	char* packet;
	packet = (char*)malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	struct ether_header* eh;
	eh = (struct ether_header*)packet;
	struct ether_arp* eh_arp;
	eh_arp = (struct eh_arp*)(packet + ETHER_HDR_SIZE);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	memcpy(eh->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
	eh->ether_type = htons(ETH_P_ARP);
	eh_arp->arp_hrd = htons(0x01);
	eh_arp->arp_pro = htons(0x0800);
	eh_arp->arp_hln = 6;
	eh_arp->arp_pln = 4;
	eh_arp->arp_op = htons(ARPOP_REPLY);
	eh_arp->arp_spa = htonl(iface->ip);
	u32 my_ip = ntohl(req_hdr->arp_spa);
	eh_arp->arp_tpa = htonl(my_ip);
	memcpy(eh_arp->arp_sha,iface->mac,ETH_ALEN);
	memcpy(eh_arp->arp_tha,req_hdr->arp_sha,ETH_ALEN);

	iface_send_packet(iface,packet,sizeof(struct ether_arp)+ETHER_HDR_SIZE);
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{	
	struct ether_header* eh;
	struct ether_arp* eh_arp;
	eh = (struct ether_header*)(packet);
	eh_arp = (struct ether_arp*)(packet + ETHER_HDR_SIZE);
	if(ntohs(eh_arp->arp_op) == 0x01){
		if(ntohl(eh_arp->arp_tpa) == iface->ip){
			arp_send_reply(iface, eh_arp);
			arpcache_insert(ntohl(eh_arp->arp_spa),eh_arp->arp_sha);
		}
	}
	else if(ntohs(eh_arp->arp_op) == 0x02){
		if(ntohl(eh_arp->arp_tpa) == iface->ip){
			arpcache_insert(ntohl(eh_arp->arp_spa), eh_arp->arp_sha);
		}
	}
	free(packet);
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);
	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		if(ntohs(eh->ether_type) == ETH_P_IP){
			struct iphdr* myiph;
			myiph = (struct iphdr*)(packet + ETHER_HDR_SIZE);
			struct icmphdr* myicmph;
			myicmph = (struct icmphdr*)(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(myiph));
			u32 sip = ntohl(myiph->saddr);
			u32 dip = ntohl(myiph->daddr);
		}
		iface_send_packet(iface, packet, len);
	}
	else {
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
	
}
