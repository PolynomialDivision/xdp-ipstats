## XDP IPstats

If you want to findout more about your IPv4/IPv6 Fraction in your network.

It uses the xdp part blogic wrote:
https://github.com/blogic/ubpf

Further, we used parts of:
https://github.com/xdp-project/xdp-tutorial

## Installation/Usage

Install the ubpf loader https://github.com/blogic/ubpf

Load the xdp into the kern:

    xdpload -d br-lan -f /usr/xdp/ipstats_kern.o -p xdp-ip-stats


Now run the xdp-stats

    xdp-ipstats -d br-lan

It will write the statistics to

    /tmp/ip-stats.csv