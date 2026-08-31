// SPDX-License-Identifier: GPL-2.0
/* ddosguard: load/configure/monitor the XDP DDoS mitigation program. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_link.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ddosguard.skel.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define BPFFS_ROOT "/sys/fs/bpf"
#define PIN_DIR "ddosguard"

#define CFG_MODE 0
#define CFG_FLAGS 1
#define CFG_SYN_SRC_RATE 2
#define CFG_SYN_SRC_BURST 3
#define CFG_SYN_SVC_RATE 4
#define CFG_SYN_SVC_BURST 5
#define CFG_ICMP_RATE 6
#define CFG_ICMP_BURST 7
#define CFG_UDP_RATE 8
#define CFG_UDP_BURST 9
#define CFG_BAN_THRESH 10
#define CFG_BAN_TIME 11

#define FLAG_BAD_FLAGS (1U << 0)
#define FLAG_SYN_RATE (1U << 1)
#define FLAG_ICMP_RATE (1U << 2)
#define FLAG_UDP_RATE (1U << 3)

enum stats_idx {
	STAT_DROP_DENY = 0,
	STAT_DROP_BADFLAGS,
	STAT_DROP_POLICY,
	STAT_DROP_RATE_SYN,
	STAT_DROP_RATE_ICMP,
	STAT_DROP_RATE_UDP,
	STAT_DROP_BAN,
	STAT_PASS_WHITELIST,
	STAT_PASS,
	STAT_DROP_TOTAL,
	STAT_TOTAL,
};

static const char *stats_names[] = {
	"drop/denylist", "drop/bad-tcp-flags", "drop/port-policy",
	"drop/rate-syn", "drop/rate-icmp", "drop/rate-udp",
	"drop/ban", "pass/whitelist", "pass", "drop/total", "total",
};

struct v4_key {
	__u32 prefixlen;
	__u32 addr;
};

struct iface_maps {
	int cfg;
	int tcp_allow, tcp_deny;
	int udp_allow, udp_deny;
	int icmp_allow;
	int deny4, allow4;
	int deny6, allow6;
	int ban_viol, ban4;
	int stats;
};

static char pin_dir[256];
static char pin_prog[320];

static const char *map_names[] = {
	"cfg", "tcp_allow", "tcp_deny", "udp_allow", "udp_deny",
	"icmp_allow", "deny4", "allow4", "deny6", "allow6",
	"ban_viol", "ban4", "stats",
};

static void usage(const char *argv0)
{
	fprintf(stderr,
"ddosguard - XDP DDoS mitigation (advanced tier)\n"
"\n"
"Load / unload:\n"
"  %s load <iface> [--mode skb|native]\n"
"  %s unload <iface>\n"
"\n"
"Monitor:\n"
"  %s show <iface>\n"
"\n"
"Configure (applies to a loaded program):\n"
"  %s mode <iface> allow|block\n"
"      allow  = default-deny (only allowed ports/IPs pass)\n"
"      block  = default-allow (drop only denied + rate-limited)\n"
"  %s feature <iface> <all|badflags|syn|icmp|udp> on|off\n"
"  %s syn-rate <iface> <per_sec> [burst]     (per source; svc = per_sec*8)\n"
"  %s icmp-rate <iface> <per_sec> [burst]\n"
"  %s udp-rate <iface> <per_sec> [burst]\n"
"  %s ban <iface> <threshold> <seconds>   (SYN over-limit -> /24 block)\n"
"  %s allow <iface> ip <a.b.c.d>|net <a.b.c.d>/<n>|port tcp|udp <p>|<lo-hi>|icmp <type>|ip6 <addr>\n"
"  %s deny  <iface> ip <a.b.c.d>|net <a.b.c.d>/<n>|port tcp|udp <p>|<lo-hi>|ip6 <addr>\n"
"  %s del   <iface> ip|net|port|icmp|ip6 ...  (same syntax as allow/deny)\n"
"  %s flush <iface> <all|ports|ipv4|ipv6>\n",
			argv0, argv0, argv0, argv0, argv0, argv0,
			argv0, argv0, argv0, argv0, argv0, argv0, argv0);
	exit(1);
}

static void die(const char *msg)
{
	fprintf(stderr, "ddosguard: %s: %s\n", msg, strerror(errno));
	exit(1);
}

static int set_pin_paths(const char *iface)
{
	snprintf(pin_dir, sizeof(pin_dir), "%s/%s/%s", BPFFS_ROOT, PIN_DIR, iface);
	snprintf(pin_prog, sizeof(pin_prog), "%s/prog", pin_dir);
	return 0;
}

static int open_maps(struct iface_maps *m)
{
	char path[320];
	int *fds[] = { &m->cfg, &m->tcp_allow, &m->tcp_deny, &m->udp_allow,
		       &m->udp_deny, &m->icmp_allow, &m->deny4, &m->allow4,
		       &m->deny6, &m->allow6, &m->ban_viol, &m->ban4,
		       &m->stats };

	memset(m, 0, sizeof(*m));
	for (size_t i = 0; i < ARRAY_SIZE(map_names); i++) {
		snprintf(path, sizeof(path), "%s/%s", pin_dir, map_names[i]);
		*fds[i] = bpf_obj_get(path);
		if (*fds[i] < 0) {
			errno = -(*fds[i]);
			die(path);
		}
	}
	return 0;
}

static __u32 cfg_get(int fd, __u32 idx)
{
	__u32 v = 0;
	if (bpf_map_lookup_elem(fd, &idx, &v) != 0)
		die("cfg lookup");
	return v;
}

static void cfg_set(int fd, __u32 idx, __u32 v)
{
	if (bpf_map_update_elem(fd, &idx, &v, BPF_ANY) != 0)
		die("cfg update");
}

static int ensure_dir(const char *path)
{
	char buf[320];
	snprintf(buf, sizeof(buf), "%s", path);
	for (char *p = buf + 5; *p; p++) {
		if (*p == '/') {
			*p = 0;
			if (mkdir(buf, 0750) && errno != EEXIST)
				return -1;
			*p = '/';
		}
	}
	return mkdir(buf, 0750) && errno != EEXIST ? -1 : 0;
}

/* ---------------- load / unload ---------------- */

static int do_load(const char *iface, int use_skb)
{
	unsigned int ifindex = if_nametoindex(iface);
	struct ddosguard_bpf *skel;
	struct bpf_program *prog;
	__u32 one = 1, flags;
	int err, prog_fd;

	if (!ifindex)
		die("interface not found");

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	skel = ddosguard_bpf__open();
	if (!skel)
		die("open skeleton");
	err = ddosguard_bpf__load(skel);
	if (err) {
		errno = -err;
		die("load skeleton");
	}

	prog = skel->progs.ddosguard;
	prog_fd = bpf_program__fd(prog);

	flags = use_skb ? XDP_FLAGS_SKB_MODE : 0;
	if (bpf_xdp_attach(ifindex, prog_fd, flags, NULL)) {
		if (!use_skb) {
			fprintf(stderr, "native attach failed (%s); "
				"trying generic (SKB) mode\n", strerror(errno));
			flags = XDP_FLAGS_SKB_MODE;
			if (bpf_xdp_attach(ifindex, prog_fd, flags, NULL)) {
				perror("attach (skb)");
				ddosguard_bpf__destroy(skel);
				return 1;
			}
		} else {
			perror("attach");
			ddosguard_bpf__destroy(skel);
			return 1;
		}
	}
	fprintf(stderr, "attached %s mode on %s\n",
		(flags & XDP_FLAGS_SKB_MODE) ? "generic/skb" : "native/drv", iface);

	if (ensure_dir(pin_dir))
		die("mkdir pin dir");
	if (bpf_obj_pin(prog_fd, pin_prog))
		die("pin program");

	struct bpf_map *map;
	for (size_t i = 0; i < ARRAY_SIZE(map_names); i++) {
		map = bpf_object__find_map_by_name(skel->obj, map_names[i]);
		if (!map)
			continue;
		char path[320];
		snprintf(path, sizeof(path), "%s/%s", pin_dir, map_names[i]);
		if (bpf_map__pin(map, path))
			die("pin map");
	}

	/* default safe config */
	int cfg_fd = bpf_map__fd(skel->maps.cfg);
	cfg_set(cfg_fd, CFG_MODE, 0);                       /* block mode */
	flags = FLAG_BAD_FLAGS | FLAG_SYN_RATE |
		FLAG_ICMP_RATE | FLAG_UDP_RATE;
	cfg_set(cfg_fd, CFG_FLAGS, flags);
	cfg_set(cfg_fd, CFG_SYN_SRC_RATE, 1000);
	cfg_set(cfg_fd, CFG_SYN_SRC_BURST, 1000);
	cfg_set(cfg_fd, CFG_SYN_SVC_RATE, 20000);
	cfg_set(cfg_fd, CFG_SYN_SVC_BURST, 10000);
	cfg_set(cfg_fd, CFG_ICMP_RATE, 100);
	cfg_set(cfg_fd, CFG_ICMP_BURST, 100);
	cfg_set(cfg_fd, CFG_UDP_RATE, 2000);
	cfg_set(cfg_fd, CFG_UDP_BURST, 2000);
	cfg_set(cfg_fd, CFG_BAN_THRESH, 4);
	cfg_set(cfg_fd, CFG_BAN_TIME, 600);

	/* allow pings by default (echo request + reply) */
	bpf_map_update_elem(bpf_map__fd(skel->maps.icmp_allow), &one, &one, BPF_ANY);

	ddosguard_bpf__destroy(skel);
	printf("ddosguard loaded on %s (maps pinned in %s)\n", iface, pin_dir);
	return 0;
}

static int do_unload(const char *iface, int use_skb)
{
	unsigned int ifindex = if_nametoindex(iface);
	int prog_fd;
	unsigned int flags;

	if (!ifindex)
		die("interface not found");
	prog_fd = bpf_obj_get(pin_prog);
	if (prog_fd < 0) {
		fprintf(stderr, "no pinned program at %s\n", pin_prog);
		return 1;
	}
	flags = use_skb ? XDP_FLAGS_SKB_MODE : 0;
	if (bpf_xdp_detach(ifindex, flags, NULL))
		perror("detach");

	/* remove pins */
	unlink(pin_prog);
	for (size_t i = 0; i < ARRAY_SIZE(map_names); i++) {
		char path[320];
		snprintf(path, sizeof(path), "%s/%s", pin_dir, map_names[i]);
		unlink(path);
	}
	rmdir(pin_dir);
	printf("ddosguard unloaded from %s\n", iface);
	return 0;
}

/* ---------------- show ---------------- */

static void show_addrs(const char *label, int map_fd, int is_lpm, int is_v6)
{
	char line[8192], ip[64];
	int key[16] = {0}, next[16] = {0};
	int n = 0, r;

	line[0] = 0;
	while (bpf_map_get_next_key(map_fd, key, next) == 0) {
		__u8 val;
		bpf_map_lookup_elem(map_fd, next, &val);
		if (is_v6) {
			inet_ntop(AF_INET6, next, ip, sizeof(ip));
		} else if (is_lpm) {
			struct v4_key *k = (struct v4_key *)next;
			inet_ntop(AF_INET, &k->addr, ip, sizeof(ip));
			snprintf(ip + strlen(ip), sizeof(ip) - strlen(ip), "/%u", k->prefixlen);
		} else {
			inet_ntop(AF_INET, next, ip, sizeof(ip));
		}
		if (n >= (int)sizeof(line) - 1)
			break;
		r = snprintf(line + n, sizeof(line) - n, "%s%s",
			     n ? " " : "", ip);
		if (r < 0 || n >= (int)sizeof(line) - r)
			break;
		n += r;
		memcpy(key, next, sizeof(next));
	}
	if (n)
		printf("  %-14s: %s\n", label, line);
	else
		printf("  %-14s: (empty)\n", label);
}

static void show_ports(const char *label, int map_fd)
{
	__u32 key = 0, next = 0;
	char line[8192] = {0};
	int n = 0, r;

	while (bpf_map_get_next_key(map_fd, &key, &next) == 0) {
		if (n >= (int)sizeof(line) - 1)
			break;
		r = snprintf(line + n, sizeof(line) - n, "%s%u",
			     n ? " " : "", next);
		if (r < 0 || n >= (int)sizeof(line) - r)
			break;
		n += r;
		key = next;
	}
	if (n)
		printf("  %-14s: %s\n", label, line);
	else
		printf("  %-14s: (empty)\n", label);
}

static void show_icmp(int map_fd)
{
	__u32 key = 0, next = 0;
	char line[256] = {0};
	int n = 0;

	while (bpf_map_get_next_key(map_fd, &key, &next) == 0) {
		n += snprintf(line + n, sizeof(line) - n, "%s%u",
			      n ? " " : "", next);
		key = next;
	}
	if (n)
		printf("  %-14s: %s\n", "icmp-types", line);
}

static int do_show(const char *iface)
{
	struct iface_maps m;
	unsigned int ifindex = if_nametoindex(iface);
	struct bpf_xdp_query_opts q = { .sz = sizeof(q) };
	__u32 mode, flags;

	if (!ifindex)
		die("interface not found");
	open_maps(&m);
	if (bpf_xdp_query(ifindex, 0, &q))
		die("xdp query");

	printf("interface: %s\n", iface);
	if (q.prog_id) {
		printf("  xdp program id: %u\n", q.prog_id);
		printf("  attach mode: %s\n",
		       q.attach_mode == XDP_FLAGS_SKB_MODE ? "generic/skb" : "native/drv");
	} else {
		printf("  xdp: not attached\n");
	}

	mode = cfg_get(m.cfg, CFG_MODE);
	flags = cfg_get(m.cfg, CFG_FLAGS);
	printf("  mode      : %s (default-%s)\n",
	       mode ? "allow" : "block", mode ? "deny" : "allow");
	printf("  features  : badflags=%s syn=%s icmp=%s udp=%s\n",
	       (flags & FLAG_BAD_FLAGS) ? "on" : "off",
	       (flags & FLAG_SYN_RATE) ? "on" : "off",
	       (flags & FLAG_ICMP_RATE) ? "on" : "off",
	       (flags & FLAG_UDP_RATE) ? "on" : "off");
	printf("  syn-rate  : %u/s per-src (burst %u), %u/s per-service (burst %u)\n",
	       cfg_get(m.cfg, CFG_SYN_SRC_RATE), cfg_get(m.cfg, CFG_SYN_SRC_BURST),
	       cfg_get(m.cfg, CFG_SYN_SVC_RATE), cfg_get(m.cfg, CFG_SYN_SVC_BURST));
	printf("  icmp-rate : %u/s (burst %u)\n",
	       cfg_get(m.cfg, CFG_ICMP_RATE), cfg_get(m.cfg, CFG_ICMP_BURST));
	printf("  udp-rate  : %u/s per source-port (burst %u)\n",
	       cfg_get(m.cfg, CFG_UDP_RATE), cfg_get(m.cfg, CFG_UDP_BURST));
	printf("  ban       : after %u over-limit SYNs -> /24 block for %u s\n",
	       cfg_get(m.cfg, CFG_BAN_THRESH), cfg_get(m.cfg, CFG_BAN_TIME));

	printf("  allow rules:\n");
	show_ports("tcp", m.tcp_allow);
	show_ports("udp", m.udp_allow);
	show_icmp(m.icmp_allow);
	show_addrs("ipv4", m.allow4, 1, 0);
	show_addrs("ipv6", m.allow6, 0, 1);
	printf("  deny rules:\n");
	show_ports("tcp", m.tcp_deny);
	show_ports("udp", m.udp_deny);
	show_addrs("ipv4", m.deny4, 1, 0);
	show_addrs("ipv6", m.deny6, 0, 1);

	printf("  active /24 bans (src->expiry_ms_ns):\n");
	{
		__u32 k = 0, n = 0;
		char line[256] = {0};
		int nl = 0;
		while (bpf_map_get_next_key(m.ban4, &k, &n) == 0) {
			__u32 a = ntohl(n);
			char tmp[64];
			snprintf(tmp, sizeof(tmp), "%u.%u.%u.0/24",
				 (a >> 24) & 0xff, (a >> 16) & 0xff,
				 (a >> 8) & 0xff);
			int t = snprintf(line + nl, sizeof(line) - nl, "%s%s",
					 nl ? " " : "", tmp);
			nl += t;
			if (nl > (int)sizeof(line) - 80)
				break;
			k = n;
		}
		if (nl)
			printf("  %-14s: %s\n", "ban4", line);
		else
			printf("  %-14s: (none)\n", "ban4");
	}

	printf("  stats:\n");
	for (int i = 0; i < STAT_TOTAL; i++) {
		__u32 k = i;
		__u64 v = 0;
		bpf_map_lookup_elem(m.stats, &k, &v);
		printf("    %-20s %llu\n", stats_names[i], (unsigned long long)v);
	}
	return 0;
}

/* ---------------- config commands ---------------- */

static int do_mode(const char *iface, const char *mode)
{
	struct iface_maps m;
	open_maps(&m);
	cfg_set(m.cfg, CFG_MODE, !strcmp(mode, "allow") ? 1 : 0);
	printf("mode -> %s\n", !strcmp(mode, "allow") ? "allow (default-deny)" : "block (default-allow)");
	return 0;
}

static int do_feature(const char *iface, const char *feat, const char *state)
{
	struct iface_maps m;
	int on = !strcmp(state, "on");
	__u32 flags, mask;

	open_maps(&m);
	flags = cfg_get(m.cfg, CFG_FLAGS);
	if (!strcmp(feat, "all"))
		mask = FLAG_BAD_FLAGS | FLAG_SYN_RATE | FLAG_ICMP_RATE | FLAG_UDP_RATE;
	else if (!strcmp(feat, "badflags"))
		mask = FLAG_BAD_FLAGS;
	else if (!strcmp(feat, "syn"))
		mask = FLAG_SYN_RATE;
	else if (!strcmp(feat, "icmp"))
		mask = FLAG_ICMP_RATE;
	else if (!strcmp(feat, "udp"))
		mask = FLAG_UDP_RATE;
	else {
		fprintf(stderr, "unknown feature '%s'\n", feat);
		return 1;
	}
	if (on)
		flags |= mask;
	else
		flags &= ~mask;
	cfg_set(m.cfg, CFG_FLAGS, flags);
	printf("feature %s -> %s\n", feat, on ? "on" : "off");
	return 0;
}

static int do_rate(const char *iface, const char *kind, const char *s_per, const char *s_burst)
{
	struct iface_maps m;
	unsigned long per = strtoul(s_per, NULL, 10);
	unsigned long burst = s_burst ? strtoul(s_burst, NULL, 10) : per;

	open_maps(&m);
	if (!strcmp(kind, "syn")) {
		cfg_set(m.cfg, CFG_SYN_SRC_RATE, per);
		cfg_set(m.cfg, CFG_SYN_SRC_BURST, burst);
		cfg_set(m.cfg, CFG_SYN_SVC_RATE, per * 8);
		cfg_set(m.cfg, CFG_SYN_SVC_BURST, burst * 8);
		printf("syn-rate per-src=%lu/s svc=%lu/s (burst %lu)\n",
		       per, per * 8, burst);
	} else if (!strcmp(kind, "icmp")) {
		cfg_set(m.cfg, CFG_ICMP_RATE, per);
		cfg_set(m.cfg, CFG_ICMP_BURST, burst);
		printf("icmp-rate %lu/s (burst %lu)\n", per, burst);
	} else if (!strcmp(kind, "udp")) {
		cfg_set(m.cfg, CFG_UDP_RATE, per);
		cfg_set(m.cfg, CFG_UDP_BURST, burst);
		printf("udp-rate %lu/s per src:port (burst %lu)\n", per, burst);
	} else {
		fprintf(stderr, "unknown rate '%s' (syn|icmp|udp)\n", kind);
		return 1;
	}
	return 0;
}

/* ---------------- rule commands ---------------- */

static int parse_ipv4(const char *s, struct v4_key *k, int is_net)
{
	char buf[64], *slash;
	strncpy(buf, s, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = 0;
	k->prefixlen = 32;
	if (is_net) {
		slash = strchr(buf, '/');
		if (slash) {
			*slash = 0;
			k->prefixlen = atoi(slash + 1);
			if (k->prefixlen > 32)
				return -1;
		}
	}
	if (inet_pton(AF_INET, buf, &k->addr) != 1)
		return -1;
	return 0;
}

static int parse_range(const char *s, __u32 *lo, __u32 *hi)
{
	char buf[32], *dash;
	strncpy(buf, s, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = 0;
	dash = strchr(buf, '-');
	if (dash) {
		*dash = 0;
		*lo = atoi(buf);
		*hi = atoi(dash + 1);
	} else {
		*lo = *hi = atoi(buf);
	}
	if (*lo == 0 || *hi == 0 || *lo > *hi || *hi > 65535)
		return -1;
	return 0;
}

static int port_set(int map_fd, __u32 lo, __u32 hi, int del, int allowed, const char *proto)
{
	__u8 one = 1;
	for (__u32 p = lo; p <= hi; p++) {
		if (del) {
			bpf_map_delete_elem(map_fd, &p);
		} else if (bpf_map_update_elem(map_fd, &p, &one, BPF_ANY)) {
			fprintf(stderr, "failed to %s %s port %u\n",
				del ? "del" : "add", proto, p);
			return 1;
		}
		(void)allowed;
	}
	return 0;
}

static int do_ban(const char *iface, const char *s_thresh, const char *s_secs)
{
	struct iface_maps m;
	open_maps(&m);
	unsigned long thresh = strtoul(s_thresh, NULL, 10);
	unsigned long secs = strtoul(s_secs, NULL, 10);
	cfg_set(m.cfg, CFG_BAN_THRESH, thresh);
	cfg_set(m.cfg, CFG_BAN_TIME, secs);
	printf("ban thresh=%lu violations -> /24 block %lu s\n", thresh, secs);
	return 0;
}

static int do_rule(const char *iface, const char *verb, const char *kind,
		   const char *arg, const char *proto, const char *val)
{
	struct iface_maps m;
	int del = !strcmp(verb, "del");
	open_maps(&m);

	if (!strcmp(kind, "port")) {
		__u32 lo, hi;
		if (!proto || !val)
			goto bad;
		if (parse_range(val, &lo, &hi))
			goto bad;
		if (!strcmp(proto, "tcp"))
			port_set(del ? m.tcp_deny : m.tcp_allow, lo, hi, del, 1, "tcp");
		else if (!strcmp(proto, "udp"))
			port_set(del ? m.udp_deny : m.udp_allow, lo, hi, del, 1, "udp");
		else
			goto bad;
		printf("%s %s port %s\n", verb, proto, val);
		return 0;
	}
	if (!strcmp(kind, "icmp")) {
		__u32 t = atoi(val);
		__u8 one = 1;
		if (del)
			bpf_map_delete_elem(m.icmp_allow, &t);
		else
			bpf_map_update_elem(m.icmp_allow, &t, &one, BPF_ANY);
		printf("%s icmp type %s\n", verb, val);
		return 0;
	}
	if (!strcmp(kind, "ip") || !strcmp(kind, "net")) {
		struct v4_key k;
		int is_deny = !strcmp(verb, "deny");
		int map_fd = is_deny ? m.deny4 : m.allow4;
		if (parse_ipv4(arg, &k, !strcmp(kind, "net")))
			goto bad;
		if (del)
			bpf_map_delete_elem(map_fd, &k);
		else {
			__u8 one = 1;
			if (bpf_map_update_elem(map_fd, &k, &one, BPF_ANY))
				die("map update");
		}
		printf("%s %s %s\n", verb, kind, arg);
		return 0;
	}
	if (!strcmp(kind, "ip6")) {
		__u8 addr[16];
		int is_deny = !strcmp(verb, "deny");
		int map_fd = is_deny ? m.deny6 : m.allow6;
		if (inet_pton(AF_INET6, arg, addr) != 1)
			goto bad;
		if (del)
			bpf_map_delete_elem(map_fd, addr);
		else {
			__u8 one = 1;
			if (bpf_map_update_elem(map_fd, addr, &one, BPF_ANY))
				die("map update");
		}
		printf("%s ip6 %s\n", verb, arg);
		return 0;
	}
bad:
	fprintf(stderr, "invalid rule syntax\n");
	return 1;
}

static int do_flush(const char *iface, const char *what)
{
	struct iface_maps m;
	open_maps(&m);
	if (!strcmp(what, "all") || !strcmp(what, "ports")) {
		__u32 k = 0, n = 0;
		while (bpf_map_get_next_key(m.tcp_allow, &k, &n) == 0) {
			bpf_map_delete_elem(m.tcp_allow, &n);
			k = 0;
		}
		while (bpf_map_get_next_key(m.tcp_deny, &k, &n) == 0) {
			bpf_map_delete_elem(m.tcp_deny, &n);
			k = 0;
		}
		while (bpf_map_get_next_key(m.udp_allow, &k, &n) == 0) {
			bpf_map_delete_elem(m.udp_allow, &n);
			k = 0;
		}
		while (bpf_map_get_next_key(m.udp_deny, &k, &n) == 0) {
			bpf_map_delete_elem(m.udp_deny, &n);
			k = 0;
		}
		k = 0; n = 0;
		while (bpf_map_get_next_key(m.icmp_allow, &k, &n) == 0) {
			bpf_map_delete_elem(m.icmp_allow, &n);
			k = 0;
		}
	}
	if (!strcmp(what, "all") || !strcmp(what, "ipv4")) {
		struct v4_key k = {0}, n;
		while (bpf_map_get_next_key(m.deny4, &k, &n) == 0) {
			bpf_map_delete_elem(m.deny4, &n);
			k.prefixlen = 0; k.addr = 0;
		}
		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(m.allow4, &k, &n) == 0) {
			bpf_map_delete_elem(m.allow4, &n);
			k.prefixlen = 0; k.addr = 0;
		}
		__u32 bk = 0, bn = 0;
		while (bpf_map_get_next_key(m.ban4, &bk, &bn) == 0) {
			bpf_map_delete_elem(m.ban4, &bn);
			bk = 0;
		}
		bk = 0;
		while (bpf_map_get_next_key(m.ban_viol, &bk, &bn) == 0) {
			bpf_map_delete_elem(m.ban_viol, &bn);
			bk = 0;
		}
	}
	if (!strcmp(what, "all") || !strcmp(what, "ipv6")) {
		__u8 k[16] = {0}, n[16];
		while (bpf_map_get_next_key(m.deny6, k, n) == 0) {
			bpf_map_delete_elem(m.deny6, n);
			memset(k, 0, sizeof(k));
		}
		memset(k, 0, sizeof(k));
		while (bpf_map_get_next_key(m.allow6, k, n) == 0) {
			bpf_map_delete_elem(m.allow6, n);
			memset(k, 0, sizeof(k));
		}
	}
	printf("flushed %s rules on %s\n", what, iface);
	return 0;
}

/* ---------------- main ---------------- */

int main(int argc, char **argv)
{
	int skb = 0;
	int argi = 1;

	if (argc < 2)
		usage(argv[0]);

	if (!strcmp(argv[1], "load")) {
		if (argc < 3)
			usage(argv[0]);
		const char *iface = argv[2];
		argi = 3;
		if (argc >= 5 && !strcmp(argv[3], "--mode")) {
			skb = !strcmp(argv[4], "skb");
			argi = 5;
		}
		if (argc > argi)
			usage(argv[0]);
		set_pin_paths(iface);
		return do_load(iface, skb);
	}
	if (!strcmp(argv[1], "unload")) {
		if (argc < 3)
			usage(argv[0]);
		const char *iface = argv[2];
		argi = 3;
		if (argc >= 5 && !strcmp(argv[3], "--mode")) {
			skb = !strcmp(argv[4], "skb");
			argi = 5;
		}
		if (argc > argi)
			usage(argv[0]);
		set_pin_paths(iface);
		return do_unload(iface, skb);
	}
	if (!strcmp(argv[1], "show")) {
		if (argc != 3)
			usage(argv[0]);
		set_pin_paths(argv[2]);
		return do_show(argv[2]);
	}
	if (!strcmp(argv[1], "mode") && argc == 4) {
		set_pin_paths(argv[2]);
		return do_mode(argv[2], argv[3]);
	}
	if (!strcmp(argv[1], "feature") && argc == 5) {
		set_pin_paths(argv[2]);
		return do_feature(argv[2], argv[3], argv[4]);
	}
	if (!strcmp(argv[1], "ban") && argc == 5) {
		set_pin_paths(argv[2]);
		return do_ban(argv[2], argv[3], argv[4]);
	}
	if (!strcmp(argv[1], "syn-rate") || !strcmp(argv[1], "icmp-rate") ||
	    !strcmp(argv[1], "udp-rate")) {
		if (argc < 4 || argc > 5)
			usage(argv[0]);
		const char *kind = argv[1][0] == 's' ? "syn" :
				   argv[1][0] == 'i' ? "icmp" : "udp";
		set_pin_paths(argv[2]);
		return do_rate(argv[2], kind, argv[3], argc == 5 ? argv[4] : NULL);
	}
	if (!strcmp(argv[1], "allow") || !strcmp(argv[1], "deny") || !strcmp(argv[1], "del")) {
		/* ddosguard allow <iface> ip <addr> | net <addr>/<n> | port tcp|udp <p> | icmp <type> | ip6 <addr> */
		if (argc < 4)
			usage(argv[0]);
		set_pin_paths(argv[2]);
		const char *kind = argv[3];
		const char *arg = argc >= 5 ? argv[4] : NULL;
		const char *proto = NULL, *val = NULL;
		if (!strcmp(kind, "port")) {
			if (argc < 6)
				usage(argv[0]);
			proto = arg;
			val = argv[5];
		} else if (!strcmp(kind, "icmp")) {
			val = arg;
		}
		return do_rule(argv[2], argv[1], kind, arg, proto, val);
	}
	if (!strcmp(argv[1], "flush") && argc == 4) {
		set_pin_paths(argv[2]);
		return do_flush(argv[2], argv[3]);
	}

	usage(argv[0]);
	return 1;
}
