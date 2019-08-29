#include "ip.h"
#include "icmp.h"
#include "rtable.h"
#include "arp.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>

// forward the IP packet from the interface specified by longest_prefix_match, 
// when forwarding the packet, you should check the TTL, update the checksum,
// determine the next hop to forward the packet, then send the packet by 
// iface_send_packet_by_arp
void ip_forward_packet(u32 ip_dst, char *packet, int len)
{
	// fprintf(stderr, "TODO: forward ip packet.\n");

	struct ether_header* eh = (struct ether_header*)packet;
	struct iphdr* my_iph = packet_to_ip_hdr(packet);
	struct icmphdr* my_icmph = (struct icmphdr *)(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(my_iph));

	// handle the packet
	u32 dst = ntohl(my_iph->daddr);
	rt_entry_t* my_entry = longest_prefix_match(dst);
	
	
	//failed in looking up
	if(!my_entry){
		u32 dst = ntohl(my_iph->saddr);
       	rt_entry_t* my_entry = longest_prefix_match(dst);
		u32 sip = my_entry->iface->ip;
		icmp_send_packet(packet, len, 3, 0, sip);
		free(packet);
		return;		
	}
	
	//TTL - 1 <= 0
	my_iph->ttl -= 1;
	if(my_iph->ttl <= 0){
                u32 dst = ntohl(my_iph->saddr);
                rt_entry_t* my_entry = longest_prefix_match(dst);
                u32 sip = my_entry->iface->ip;

		icmp_send_packet(packet, len, 11, 0,sip);
		free(packet);
		return;				
	}
	my_iph->checksum = ip_checksum(my_iph);
	memcpy(eh->ether_shost, my_entry->iface->mac, ETH_ALEN);
	u32 next_hop = my_entry->gw;
	if (!next_hop)
		next_hop = ntohl(my_iph->daddr);
	iface_send_packet_by_arp(my_entry->iface, next_hop, packet, len);
}

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	// struct iphdr *ip = packet_to_ip_hdr(packet);
	// struct icmphdr* icmp = (struct icmphdr *)(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(ip));
	// u32 daddr = ntohl(ip->daddr);
	// if (icmp->type == 8 && daddr == iface->ip) {
	// 	// fprintf(stderr, "TODO: reply to the sender if it is ping packet.\n");
	// 	u32 dst = ntohl(ip->saddr);
 //        	rt_entry_t* entry = longest_prefix_match(dst);
 //        	u32 sip = entry->iface->ip;

	// 	icmp_send_packet(packet, len, 0, 0, sip);
				
	// 	free(packet);
	// 	return;
	// }
	// else {
	// 	ip_forward_packet(daddr, packet, len);
	// }

	struct ether_header* eh = (struct ether_header*)packet;
	struct iphdr* my_iph = packet_to_ip_hdr(packet);
	struct icmphdr* my_icmph = (struct icmphdr *)(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(my_iph));

	if(my_icmph->type == 8 && ntohl(my_iph->daddr) == iface->ip){
                u32 dst = ntohl(my_iph->saddr);
                rt_entry_t* my_entry = longest_prefix_match(dst);
                u32 sip = my_entry->iface->ip;

				icmp_send_packet(packet, len, 0, 0, sip);
				free(packet);
				return;
	}
	else {
		ip_forward_packet(my_iph->daddr, packet, len);
	}

}
