#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#ifndef MAX_VLAN_DEPTH
#define MAX_VLAN_DEPTH 2
#endif

struct hdr_cursor {
	void* pos;
};

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};


static __always_inline int is_vlan(__u16 h_proto) {
	return !!(h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int parse_eth_vlan_header(struct hdr_cursor* hc, void* data_end, struct ethhdr** eth_hdr) {
	struct ethhdr* eth = hc->pos;
	if (eth + 1 > data_end) return -1;
	hc->pos += sizeof(*eth);
	*eth_hdr = eth;
	int proto = eth->h_proto;

	struct vlan_hdr* vlan = hc->pos;
	#pragma unroll
	for(int i = 0; i < MAX_VLAN_DEPTH; i++) {
		if (!is_vlan(proto)) break;
		if (vlan + 1 > data_end) break;
		proto = vlan->h_vlan_encapsulated_proto;
		vlan++;
	}
	return proto;
}

static __always_inline int parse_ipv4_header(struct hdr_cursor* hc, void* data_end, struct iphdr** ipv4_hdr) {
	struct iphdr* ipv4h = hc->pos;
	int hdrsize;

	if (ipv4h + 1 > data_end) return -1;
	hdrsize = ipv4h->ihl * 4; // ihl gives number of 32-bit words
	if (hdrsize < sizeof(ipv4h)) return -1;

	// ipv4 hdr has variable size; use hdrsize from packet itself
	if (hc->pos + hdrsize > data_end) return -1;

	hc->pos += hdrsize;
	*ipv4_hdr = ipv4h;

	return ipv4h->protocol;
}

static __always_inline int parse_ipv6_header(struct hdr_cursor* hc, void* data_end, struct ipv6hdr** ipv6_hdr) {
	struct ipv6hdr* ipv6h = hc->pos;

	if (ipv6h + 1 > data_end) return -1;
	
	hc->pos = ipv6h + 1;
	*ipv6_hdr = ipv6h;

	return ipv6h->nexthdr;
}

static __always_inline int parse_icmp6_header(struct hdr_cursor* hc, void* data_end, struct icmp6hdr** icmp6_hdr) {
	struct icmp6hdr* icmp6h = hc->pos;

	if (icmp6h + 1 > data_end) return -1;

	hc->pos = icmp6h + 1;
	*icmp6_hdr = icmp6h;

	return icmp6h->icmp6_type;
}

static __always_inline int parse_icmp_header(struct hdr_cursor* hc, void* data_end, struct icmphdr** icmp_hdr) {
	struct icmphdr* icmph = hc->pos;

	if (icmph + 1 > data_end) return -1;

	hc->pos = icmph + 1;
	*icmp_hdr = icmph;

	return icmph->type;
}

static __always_inline int parse_tcp_header(struct hdr_cursor* hc, void* data_end, struct tcphdr** tcp_hdr) {
	int len;
	struct tcphdr* tcph = hc->pos;

	if (tcph + 1 > data_end) return -1;
	
  len = tcph->doff * 4;
  /* Sanity check packet field is valid */
	if(len < sizeof(tcph))
		return -1;

	/* Variable-length TCP header, need to use byte-based arithmetic */
	if (hc->pos + len > data_end)
		return -1;

	hc->pos += len;
	*tcp_hdr = tcph;

	return len;
}

static __always_inline int parse_udp_header(struct hdr_cursor* hc, void* data_end, struct udphdr** udp_hdr) {
	int len;
	struct udphdr* udph = hc->pos;

	if (udph + 1 > data_end) return -1;
	hc->pos = udph + 1;	

//	len = bpf_ntohs(udph->len) - sizeof(struct udphdr);
  len = bpf_ntohs(udph->len);
	if (len < 0) return -1;

	*udp_hdr = udph;
	return len;
}
