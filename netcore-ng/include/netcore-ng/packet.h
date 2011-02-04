
#ifndef	__PACKET_H__
#define __PACKET_H__

#include <stdint.h>

#include <netcore-ng/protocols/layers_all.h>

#define ETHERNET 0x4554

struct packet {
	uint8_t type;
	struct ethhdr *ethernet_header;
	/* Union l2.5 */
	struct vlan_hdr *vlan_header;
	/* Union l3 */
	struct arphdr *arp_header;
	struct iphdr *ip_header;
	struct ipv6hdr *ipv6_header;
	/* Union l4 */
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	struct icmphdr *icmp_header;
	/* > l4 */
	/* Make a map of how the packet looks like */
#define MAX_STEPS		20
	uint16_t pkt_map[MAX_STEPS];
	uint8_t step;
	uint8_t *payload;
	uint32_t payload_len;
	uint8_t *raw;
	uint32_t len;
};

static inline void set_pkt_step(struct packet *pkt, uint16_t type)
{
	assert(pkt);
	pkt->pkt_map[pkt->step++] = type;
}

static inline int parse_packet(uint8_t * raw, uint32_t len, struct packet *pkt)
{
	uint8_t **buffer = &raw;
	uint32_t tmp_len = len;
	uint16_t l4_type = 0;

	memset(pkt, 0, sizeof(*pkt));

	pkt->raw = raw;
	pkt->ethernet_header = get_ethhdr(buffer, &tmp_len);
	set_pkt_step(pkt, ETHERNET);

	switch (get_ethertype(pkt->ethernet_header)) {
	case ETH_P_8021Q:
	case ETH_P_8021QinQ:
		pkt->vlan_header = get_vlanhdr(buffer, &tmp_len);
		set_pkt_step(pkt, ETH_P_8021Q);
		break;

	case ETH_P_ARP:
		pkt->arp_header = get_arphdr(buffer, &tmp_len);
		set_pkt_step(pkt, ETH_P_ARP);
		break;

	case ETH_P_IP:
		pkt->ip_header = get_iphdr(buffer, &tmp_len);
		set_pkt_step(pkt, ETH_P_IP);
		l4_type = get_l4_type_from_ipv4(pkt->ip_header);
		break;

	case ETH_P_IPV6:
		pkt->ipv6_header = get_ipv6hdr(buffer, &tmp_len);
		set_pkt_step(pkt, ETH_P_IPV6);
		l4_type = get_l4_type_from_ipv6(pkt->ipv6_header);
		break;

	default:
		break;
	}

	switch (l4_type) {
	case IPPROTO_TCP:
		pkt->tcp_header = get_tcphdr(buffer, &tmp_len);
		set_pkt_step(pkt, IPPROTO_TCP);
		break;

	case IPPROTO_UDP:
		pkt->udp_header = get_udphdr(buffer, &tmp_len);
		set_pkt_step(pkt, IPPROTO_UDP);
		break;

	case IPPROTO_ICMP:
		pkt->icmp_header = get_icmphdr(buffer, &tmp_len);
		set_pkt_step(pkt, IPPROTO_ICMP);
		break;

	default:
		break;
	}

	pkt->payload = *buffer;
	pkt->payload_len = tmp_len;

	return (0);
}

#endif				/* __PACKET_H__ */
