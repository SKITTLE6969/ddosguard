// SPDX-License-Identifier: GPL-2.0
/* ddosguard: XDP program for DDoS mitigation.
 *
 * Two policy modes (set via cfg[CFG_MODE]):
 *   BLOCK_MODE (0) - default allow. Drop only what matches deny sets,
 *                    bad flag combos, and traffic above rate limits.
 *   ALLOW_MODE (1) - default deny. Drop everything except matching
 *                    allow sets / trusted sources, subject to rate limits.
 *
 * Order of checks:
 *   1. deny list  -> DROP        (always wins)
 *   2. bad TCP flags -> DROP     (if feature on)
 *   3. whitelist  -> PASS        (trusted sources skip policies+limits)
 *   4. port policy (allow/deny sets) -> DROP when applicable
 *   5. rate limits (SYN / ICMP / UDP) -> DROP when exceeded
 *   6. else PASS
 *
 * Never drops non-Ethernet / unknown frames, and always passes ICMPv6
 * neighbour-discovery traffic so IPv6 link-local operation is unaffected.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#define CFG_MODE            0
#define CFG_FLAGS           1
#define CFG_SYN_SRC_RATE    2
#define CFG_SYN_SRC_BURST   3
#define CFG_SYN_SVC_RATE    4
#define CFG_SYN_SVC_BURST   5
#define CFG_ICMP_RATE       6
#define CFG_ICMP_BURST      7
#define CFG_UDP_RATE        8
#define CFG_UDP_BURST       9
#define CFG_BAN_THRESH      10
#define CFG_BAN_TIME        11

#define FLAG_BAD_FLAGS     (1U << 0)
#define FLAG_SYN_RATE      (1U << 1)
#define FLAG_ICMP_RATE     (1U << 2)
#define FLAG_UDP_RATE      (1U << 3)

#define BLOCK_MODE 0
#define ALLOW_MODE 1

#define MAX_KEYS 16

/* stats counters */
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

struct rate_bucket {
	__u64 last_ns;
	__u32 count;
};

struct cfg { __u32 v; };

/* ------------------------------------------------------------------ */
/* Maps                                                                */
/* ------------------------------------------------------------------ */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, MAX_KEYS);
	 __type(key, __u32); __type(value, struct cfg);
} cfg SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536);
	 __type(key, __u32); __type(value, __u8);
} tcp_deny SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 2048);
	 __type(key, __u32); __type(value, __u8);
} tcp_allow SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536);
	 __type(key, __u32); __type(value, __u8);
} udp_deny SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 2048);
	 __type(key, __u32); __type(value, __u8);
} udp_allow SEC(".maps");
/* ICMP types allowed in ALLOW_MODE (e.g. type 8 = echo request) */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 32);
	 __type(key, __u32); __type(value, __u8);
} icmp_allow SEC(".maps");

/* IPv4 LPM tries: key = {prefixlen, addr} */
struct v4_key { __u32 prefixlen; __u32 addr; };
struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE); __uint(max_entries, 65536);
	 __type(key, struct v4_key); __type(value, __u8);
	 __uint(map_flags, BPF_F_NO_PREALLOC);
} deny4 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE); __uint(max_entries, 4096);
	 __type(key, struct v4_key); __type(value, __u8);
	 __uint(map_flags, BPF_F_NO_PREALLOC);
} allow4 SEC(".maps");

/* IPv6 exact matches */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
	 __type(key, __u8[16]); __type(value, __u8);
} deny6 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
	 __type(key, __u8[16]); __type(value, __u8);
} allow6 SEC(".maps");

/* SYN-ban escalation: per-source violation count, and /24 bans (value = expiry ns) */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536);
	 __type(key, __u32); __type(value, __u32);
} ban_viol SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384);
	 __type(key, __u32); __type(value, __u64);
} ban4 SEC(".maps");

/* rate-limit buckets */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536);
	 __type(key, __u32); __type(value, struct rate_bucket);
} syn_src SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384);
	 __type(key, __u64); __type(value, struct rate_bucket);
} syn_svc SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
	 __type(key, __u32); __type(value, struct rate_bucket);
} icmp_src SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384);
	 __type(key, __u64); __type(value, struct rate_bucket);
} udp_svc SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, STAT_TOTAL);
	 __type(key, __u32); __type(value, __u64);
} stats SEC(".maps");

/* ------------------------------------------------------------------ */

static __always_inline __u32 cfg_get(__u32 idx)
{
	struct cfg *c = bpf_map_lookup_elem(&cfg, &idx);
	return c ? c->v : 0;
}

static __always_inline void stat_inc(__u32 idx)
{
	__u32 k = idx;
	__u64 *v = bpf_map_lookup_elem(&stats, &k);
	if (v)
		__sync_fetch_and_add(v, 1);
}

/* Return the 8 TCP flags (FIN LSB .. CWR MSB) as a little-endian byte. */
static __always_inline __u16 tcp_flags(const struct tcphdr *tcp)
{
	return __builtin_bswap16(*(const __u16 *)((const void *)tcp + 12));
}

/* Increment a rate bucket and return true if over limit. */
static __always_inline bool rate_check(struct rate_bucket *b, __u64 now,
				       __u32 per_sec, __u32 burst)
{
	const __u64 span = 1000000000ULL;
	if (now - b->last_ns >= span) {
		b->last_ns = now;
		b->count = 1;
		return false;
	}
	if (b->count > per_sec + burst)
		return true;
	b->count++;
	return false;
}

static __always_inline bool syn_rate_limited(__u32 src, __u16 dport)
{
	__u64 now = bpf_ktime_get_ns();
	__u32 rate = cfg_get(CFG_SYN_SRC_RATE);
	__u32 burst = cfg_get(CFG_SYN_SRC_BURST);
	struct rate_bucket *b;

	if (rate) {
		b = bpf_map_lookup_elem(&syn_src, &src);
		if (b) {
			if (rate_check(b, now, rate, burst)) {
				stat_inc(STAT_DROP_RATE_SYN);
				return true;
			}
		} else {
			struct rate_bucket nb = { .last_ns = now, .count = 1 };
			bpf_map_update_elem(&syn_src, &src, &nb, BPF_ANY);
		}
	}

	rate = cfg_get(CFG_SYN_SVC_RATE);
	burst = cfg_get(CFG_SYN_SVC_BURST);
	if (rate) {
		__u64 key = ((__u64)src << 32) | dport;
		b = bpf_map_lookup_elem(&syn_svc, &key);
		if (b) {
			if (rate_check(b, now, rate, burst)) {
				stat_inc(STAT_DROP_RATE_SYN);
				return true;
			}
		} else {
			struct rate_bucket nb = { .last_ns = now, .count = 1 };
			bpf_map_update_elem(&syn_svc, &key, &nb, BPF_ANY);
		}
	}
	return false;
}

/* Mask a network-order IPv4 addr down to a /24, keeping network byte order
 * in the key so it round-trips through inet_ntop cleanly.
 */
static __always_inline __u32 v4_net24(__u32 saddr)
{
	__u32 h = __builtin_bswap32(saddr);   /* host order */
	h &= 0xFFFFFF00;                        /* /24 */
	return __builtin_bswap32(h);            /* back to network order */
}

/* Ban escalation: after CFG_BAN_THRESH over-limit SYNs from a source,
 * block its /24 for CFG_BAN_TIME seconds. Returns true to drop.
 * ban4 stores { /24 addr (net order) } -> { expiry_ns }.
 */
static __always_inline bool ban_escalate(__u32 src, __u16 dport)
{
	__u32 thresh = cfg_get(CFG_BAN_THRESH);
	__u32 secs = cfg_get(CFG_BAN_TIME);
	if (!thresh || !secs)
		return false;

	__u32 *v = bpf_map_lookup_elem(&ban_viol, &src);
	if (!v) {
		__u32 one = 1;
		bpf_map_update_elem(&ban_viol, &src, &one, BPF_ANY);
		return false;
	}
	*v += 1;
	if (*v < thresh)
		return false;

	__u32 net = v4_net24(src);
	__u64 now = bpf_ktime_get_ns();
	__u64 expiry = now + (__u64)secs * 1000000000ULL;
	bpf_map_update_elem(&ban4, &net, &expiry, BPF_ANY);
	(void)dport;
	return true;
}

/* Check /24 bans. Expired entries are torn down lazily as packets arrive. */
static __always_inline bool ban4_limited(__u32 src)
{
	__u64 now = bpf_ktime_get_ns();
	__u32 net = v4_net24(src);
	__u64 *exp = bpf_map_lookup_elem(&ban4, &net);
	if (!exp)
		return false;
	if (*exp > now) {
		stat_inc(STAT_DROP_BAN);
		return true;
	}
	bpf_map_delete_elem(&ban4, &net);
	return false;
}

static __always_inline void udp_rate_check(__u32 hashed, __u16 dport)
{
	__u64 now = bpf_ktime_get_ns();
	__u32 rate = cfg_get(CFG_UDP_RATE);
	__u32 burst = cfg_get(CFG_UDP_BURST);
	struct rate_bucket *b;

	if (!rate)
		return;
	__u64 key = ((__u64)hashed << 32) | dport;
	b = bpf_map_lookup_elem(&udp_svc, &key);
	if (b) {
		if (rate_check(b, now, rate, burst))
			stat_inc(STAT_DROP_RATE_UDP);
	} else {
		struct rate_bucket nb = { .last_ns = now, .count = 1 };
		bpf_map_update_elem(&udp_svc, &key, &nb, BPF_ANY);
	}
}

static __always_inline void icmp_rate_check(__u32 src)
{
	__u64 now = bpf_ktime_get_ns();
	__u32 rate = cfg_get(CFG_ICMP_RATE);
	__u32 burst = cfg_get(CFG_ICMP_BURST);
	struct rate_bucket *b;

	if (!rate)
		return;
	b = bpf_map_lookup_elem(&icmp_src, &src);
	if (b) {
		if (rate_check(b, now, rate, burst))
			stat_inc(STAT_DROP_RATE_ICMP);
	} else {
		struct rate_bucket nb = { .last_ns = now, .count = 1 };
		bpf_map_update_elem(&icmp_src, &src, &nb, BPF_ANY);
	}
}

/* Returns true to drop. */
static __always_inline bool handle_ipv4(void *data, void *data_end)
{
	struct ethhdr *eth = data;
	struct iphdr *iph = data + sizeof(*eth);
	struct v4_key dk = { .prefixlen = 32, .addr = 0 };
	__u32 mode = cfg_get(CFG_MODE);
	__u32 flags = cfg_get(CFG_FLAGS);

	if ((void *)iph + sizeof(*iph) > data_end)
		return false;

	/* whitelist first (Sri Lanka LK allowlist): trusted sources ALWAYS pass —
	 * skip deny list, escalation bans, policy and rate limits. Keeps LK
	 * clients unblocked even if an attacker shares their CIDR. */
	{
		struct v4_key ak = { .prefixlen = 32, .addr = iph->saddr };
		if (bpf_map_lookup_elem(&allow4, &ak)) {
			stat_inc(STAT_PASS_WHITELIST);
			return false;
		}
	}

	/* deny list (IPv4, prefix aware) */
	dk.addr = iph->saddr;
	if (bpf_map_lookup_elem(&deny4, &dk)) {
		stat_inc(STAT_DROP_DENY);
		return true;
	}

	/* escalation bans: boost after the whitelist so trusted IPs stay up */
	if (ban4_limited(iph->saddr))
		return true;

	switch (iph->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcp;
		__u16 dport;
		__u16 tf;

		tcp = data + sizeof(*eth) + (iph->ihl << 2);
		if ((void *)tcp + sizeof(*tcp) > data_end)
			return false;
		dport = bpf_ntohs(tcp->dest);
		tf = tcp_flags(tcp);
		if ((flags & FLAG_BAD_FLAGS) && (tf & 0x7)) {
			__u8 syn = !!(tf & 0x2);
			__u8 fin = !!(tf & 0x1);
			__u8 rst = !!(tf & 0x4);
			if ((syn && (fin || rst)) || (fin && rst)) {
				stat_inc(STAT_DROP_BADFLAGS);
				return true;
			}
		}
		if (mode == ALLOW_MODE) {
			if (!bpf_map_lookup_elem(&tcp_allow, &dport)) {
				stat_inc(STAT_DROP_POLICY);
				return true;
			}
		} else if (bpf_map_lookup_elem(&tcp_deny, &dport)) {
			stat_inc(STAT_DROP_POLICY);
			return true;
		}
		if ((flags & FLAG_SYN_RATE) && (tf & 0x2)) {
			if (syn_rate_limited(iph->saddr, dport)) {
				if (ban_escalate(iph->saddr, dport))
					stat_inc(STAT_DROP_BAN);
				return true;
			}
		}
		return false;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp;
		__u16 dport;

		udp = data + sizeof(*eth) + (iph->ihl << 2);
		if ((void *)udp + sizeof(*udp) > data_end)
			return false;
		dport = bpf_ntohs(udp->dest);
		if (mode == ALLOW_MODE) {
			if (!bpf_map_lookup_elem(&udp_allow, &dport)) {
				stat_inc(STAT_DROP_POLICY);
				return true;
			}
		} else if (bpf_map_lookup_elem(&udp_deny, &dport)) {
			stat_inc(STAT_DROP_POLICY);
			return true;
		}
		if (flags & FLAG_UDP_RATE)
			udp_rate_check(iph->saddr, dport);
		return false;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *icmp = data + sizeof(*eth) + (iph->ihl << 2);
		__u32 t;

		if ((void *)icmp + sizeof(*icmp) > data_end)
			return false;
		if (mode == ALLOW_MODE) {
			t = icmp->type;
			if (!bpf_map_lookup_elem(&icmp_allow, &t)) {
				stat_inc(STAT_DROP_POLICY);
				return true;
			}
		}
		if (flags & FLAG_ICMP_RATE)
			icmp_rate_check(iph->saddr);
		return false;
	}
	default:
		if (mode == ALLOW_MODE) {
			stat_inc(STAT_DROP_POLICY);
			return true;
		}
		return false;
	}
}

static __always_inline __u32 ipv6_key(const struct in6_addr *a)
{
	const __u32 *w = (const __u32 *)a;
	return w[0] ^ w[1] ^ w[2] ^ w[3];
}

static __always_inline bool handle_ipv6(void *data, void *data_end)
{
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h = data + sizeof(*eth);
	__u32 mode = cfg_get(CFG_MODE);
	__u32 flags = cfg_get(CFG_FLAGS);

	if ((void *)ip6h + sizeof(*ip6h) > data_end)
		return false;

	/* allow first (LK allowlist) — trusted sources always pass */
	if (bpf_map_lookup_elem(&allow6, &ip6h->saddr)) {
		stat_inc(STAT_PASS_WHITELIST);
		return false;
	}

	/* deny exact addresses */
	if (bpf_map_lookup_elem(&deny6, &ip6h->saddr)) {
		stat_inc(STAT_DROP_DENY);
		return true;
	}

	switch (ip6h->nexthdr) {
	case IPPROTO_TCP: {
		struct tcphdr *tcp = (void *)ip6h + sizeof(*ip6h);
		__u16 dport;
		__u16 tf;

		if ((void *)tcp + sizeof(*tcp) > data_end)
			return false;
		dport = bpf_ntohs(tcp->dest);
		tf = tcp_flags(tcp);
		if ((flags & FLAG_BAD_FLAGS) && (tf & 0x7)) {
			__u8 syn = !!(tf & 0x2);
			__u8 fin = !!(tf & 0x1);
			__u8 rst = !!(tf & 0x4);
			if ((syn && (fin || rst)) || (fin && rst)) {
				stat_inc(STAT_DROP_BADFLAGS);
				return true;
			}
		}
		if (mode == ALLOW_MODE) {
			if (!bpf_map_lookup_elem(&tcp_allow, &dport)) {
				stat_inc(STAT_DROP_POLICY);
				return true;
			}
		} else if (bpf_map_lookup_elem(&tcp_deny, &dport)) {
			stat_inc(STAT_DROP_POLICY);
			return true;
		}
		if ((flags & FLAG_SYN_RATE) && (tf & 0x2)) {
			if (syn_rate_limited(ipv6_key(&ip6h->saddr), dport))
				return true;
		}
		return false;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp = (void *)ip6h + sizeof(*ip6h);
		__u16 dport;

		if ((void *)udp + sizeof(*udp) > data_end)
			return false;
		dport = bpf_ntohs(udp->dest);
		if (mode == ALLOW_MODE) {
			if (!bpf_map_lookup_elem(&udp_allow, &dport)) {
				stat_inc(STAT_DROP_POLICY);
				return true;
			}
		} else if (bpf_map_lookup_elem(&udp_deny, &dport)) {
			stat_inc(STAT_DROP_POLICY);
			return true;
		}
		if (flags & FLAG_UDP_RATE)
			udp_rate_check(ipv6_key(&ip6h->saddr), dport);
		return false;
	}
	case IPPROTO_ICMPV6: {
		struct icmp6hdr *icmp6 = (void *)ip6h + sizeof(*ip6h);

		if ((void *)icmp6 + sizeof(*icmp6) > data_end)
			return false;
		/* Always pass neighbour discovery: RS/RA/NS/NA/Redirect */
		if (icmp6->icmp6_type >= 133 && icmp6->icmp6_type <= 137)
			return false;
		if (mode == ALLOW_MODE) {
			__u32 t = icmp6->icmp6_type;
			if (!bpf_map_lookup_elem(&icmp_allow, &t)) {
				stat_inc(STAT_DROP_POLICY);
				return true;
			}
		}
		if (flags & FLAG_ICMP_RATE)
			icmp_rate_check(ipv6_key(&ip6h->saddr));
		return false;
	}
	default:
		if (mode == ALLOW_MODE) {
			stat_inc(STAT_DROP_POLICY);
			return true;
		}
		return false;
	}
}

SEC("xdp")
int ddosguard(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__u16 h_proto;
	bool drop;

	if (data + sizeof(*eth) > data_end)
		return XDP_PASS; /* cannot parse: never drop */

	h_proto = bpf_ntohs(eth->h_proto);

	switch (h_proto) {
	case ETH_P_IP:
		drop = handle_ipv4(data, data_end);
		break;
	case ETH_P_IPV6:
		drop = handle_ipv6(data, data_end);
		break;
	default:
		return XDP_PASS;
	}

	if (drop) {
		stat_inc(STAT_DROP_TOTAL);
		return XDP_DROP;
	}
	stat_inc(STAT_PASS);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";