#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 2
#endif

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

struct ip_stats_rec {
	__u64 ipv4_rx_packets;
	__u64 ipv4_rx_bytes;
	__u64 ipv6_rx_packets;
	__u64 ipv6_rx_bytes;
};

struct bpf_map_def SEC("maps") ip_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct ip_stats_rec),
	.max_entries = 1,
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	/* copied from xdp-tutorial */
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

SEC("xdp-ip-stats")
int ip_analyzer(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* copied from xdp-tutorial */
	#pragma unroll
		for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (vlh + 1 > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;

		vlh++;
	}

	struct ethhdr *ehdr = data;
	if (ehdr + 1 > data_end)
		goto out;

	__u32 idx = 0;
	struct ip_stats_rec *rec = bpf_map_lookup_elem(&ip_stats_map, &idx);
	if (!rec)
		goto out;

	__u64 bytes = data_end - data;

	if (bpf_ntohs(ehdr->h_proto) == ETH_P_IPV6) {
		rec->ipv6_rx_packets++;
		rec->ipv6_rx_bytes += bytes;
	} else if (bpf_ntohs(ehdr->h_proto) == ETH_P_IP) {
		rec->ipv4_rx_packets++;
		rec->ipv4_rx_bytes += bytes;
	}

out:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
