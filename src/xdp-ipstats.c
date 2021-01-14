/* SPDX-License-Identifier: GPL-2.0 */

#include "uxdp.h"

struct ip_stats_rec {
	__u64 ipv4_rx_packets;
	__u64 ipv4_rx_bytes;
	__u64 ipv6_rx_packets;
	__u64 ipv6_rx_bytes;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(-1);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

struct record {
	__u64 timestamp;
	struct ip_stats_rec total; /* defined in common_kern_user.h */
};

struct stats_record {
	struct record stats[1]; /* Assignment#2: Hint */
};

static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	struct record *rec, *prev;
	double period;
	__u64 packets_ipv4, packets_ipv6;
	__u64 bytes_ipv4, bytes_ipv6;
	double pps_ipv4, pps_ipv6;
	double bytess_ipv4, bytess_ipv6;
	{
		char *fmt_ipv4 = "IPv4: %-12s %'11lld pkts (%'10.0f pps)"
			//" %'11lld Kbytes (%'6.0f Mbits/s)"
			" period:%f\n";
		char *fmt_ipv6 = "IPv6: %-12s %'11lld pkts (%'10.0f pps)"
			//" %'11lld Kbytes (%'6.0f Mbits/s)"
			" period:%f\n";

		char *fileprint = "%f,%lld,%f,%lld,%f,%lld,%f,%lld,%f\n";

		const char *action = "";
		rec  = &stats_rec->stats[0];
		prev = &stats_prev->stats[0];

		period = calc_period(rec, prev);
		if (period == 0)
		       return;

		packets_ipv4 = rec->total.ipv4_rx_packets - prev->total.ipv4_rx_packets;
		packets_ipv6 = rec->total.ipv6_rx_packets - prev->total.ipv6_rx_packets;
		pps_ipv4     = packets_ipv4 / period;
		pps_ipv6     = packets_ipv6 / period;

		bytes_ipv4 = rec->total.ipv4_rx_bytes - prev->total.ipv4_rx_bytes;
		bytes_ipv6 = rec->total.ipv6_rx_bytes - prev->total.ipv6_rx_bytes;
		bytess_ipv4     = bytes_ipv4 / period;
		bytess_ipv6     = bytes_ipv6 / period;

		printf(fmt_ipv4, action, rec->total.ipv4_rx_packets, pps_ipv4, period);
		printf(fmt_ipv6, action, rec->total.ipv6_rx_packets, pps_ipv6, period);
		
		printf(fileprint, period,
			rec->total.ipv4_rx_packets, pps_ipv4, rec->total.ipv4_rx_bytes, bytess_ipv4,
			rec->total.ipv6_rx_packets, pps_ipv6, rec->total.ipv6_rx_bytes, bytess_ipv6
		);
		
		FILE *fp;
		fp = fopen("/tmp/ip-stats.csv", "a");
		fprintf(fp, fileprint, period,
			rec->total.ipv4_rx_packets, pps_ipv4, rec->total.ipv4_rx_bytes, bytess_ipv4,
			rec->total.ipv6_rx_packets, pps_ipv6, rec->total.ipv6_rx_bytes, bytess_ipv6
		);
		fclose(fp);
	}
}

static void map_get_value_array(int fd, __u32 key, struct ip_stats_rec *value)
{
	if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_xdp_map_elem failed key:0x%X\n", key);
	}
}

static bool map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
	struct ip_stats_rec value;

	rec->timestamp = gettime();

	switch (map_type) {
	case BPF_MAP_TYPE_ARRAY:
		map_get_value_array(fd, key, &value);
		break;
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		/* fall-through */
	default:
		fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n",
			map_type);
		return false;
		break;
	}
	
	rec->total.ipv4_rx_packets = value.ipv4_rx_packets;
	rec->total.ipv4_rx_bytes = value.ipv4_rx_bytes;
	rec->total.ipv6_rx_packets = value.ipv6_rx_packets;
	rec->total.ipv6_rx_bytes = value.ipv6_rx_bytes;

	return true;
}

static void stats_collect(int map_fd, __u32 map_type,
			  struct stats_record *stats_rec)
{
	__u32 key = XDP_PASS;

	map_collect(map_fd, map_type, key, &stats_rec->stats[0]);
}

static void stats_poll(int map_fd, __u32 map_type, int interval)
{
	struct stats_record prev, record = { 0 };

	/* Get initial reading quickly */
	stats_collect(map_fd, map_type, &record);
	usleep(1000000/4);

	while (1) {
		prev = record; /* struct copy */
		stats_collect(map_fd, map_type, &record);
		stats_print(&record, &prev);
		sleep(interval);
	}
}

int
main(int argc, char **argv)
{
	struct xdp_map xdp_map = {
		.prog = "ip_analyzer",
		.map = "ip_stats_map",
		.map_want = {
			.key_size = sizeof(__u32),
			.value_size = sizeof(struct ip_stats_rec),
			.max_entries = XDP_ACTION_MAX,
		},
	};
	int interval = 2;
	int ch;

	while ((ch = getopt(argc, argv, "d:f:p:")) != -1) {
		switch (ch) {
		case 'd':
			xdp_map.net = optarg;
			break;
		default:
			fprintf(stderr, "Invalid argument\n");
			exit(-1);
		}
	}
	if (!xdp_map.net) {
		fprintf(stderr, "invalid arguments\n");
		return -1;
	}

	if (map_lookup(&xdp_map)) {
		fprintf(stderr, "failed to xdp_map map\n");
		return -1;
	}

	FILE *fp;
	fp = fopen("/tmp/ip-stats.csv", "w");
	if(fp == NULL)
		printf("Error!");

	fprintf(fp, "perid,ipv4_rx_packets,pps_ipv4,ipv4_rx_bytes,bytess_ipv4,ipv6_rx_packets,pps_ipv6,ipv6_rx_bytes,bytess_ipv6\n");
	fclose(fp);

	stats_poll(xdp_map.map_fd, xdp_map.map_info.type, interval);
	return 0;
}
