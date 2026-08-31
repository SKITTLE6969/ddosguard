# ddosguard — XDP DDoS Mitigation Deployment Guide

Deploy the `ddosguard` XDP program on a fresh Ubuntu 24.04 VPS.

---

## 1. Prerequisites (Ubuntu 24.04)

```bash
apt-get update
apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
  linux-headers-$(uname -r) bpftool make gcc git curl
```

---

## 2. Copy Files

Transfer the entire `/opt/ddosguard` tree from the source server:

```bash
# On the SOURCE server:
rsync -avz /opt/ddosguard/ root@NEW_VPS:/opt/ddosguard/

# Or if building from scratch, copy these files:
#   /opt/ddosguard/bpf/ddosguard.bpf.c
#   /opt/ddosguard/bpf/vmlinux.h
#   /opt/ddosguard/src/ddosguard.c
#   /opt/ddosguard/Makefile
```

Transfer config files:

```bash
rsync -avz /etc/xdp-blocklist.txt root@NEW_VPS:/etc/
rsync -avz /etc/xdp-lk-allowlist.txt root@NEW_VPS:/etc/
rsync -avz /etc/xdp-protect-webhook root@NEW_VPS:/etc/  # Discord webhook (optional)
```

---

## 3. Build (if compiling from source)

```bash
cd /opt/ddosguard
make clean && make
```

This produces:
- `ddosguard.bpf.o` — the XDP kernel program
- `ddosguard.skel.h` — libbpf skeleton header
- `ddosguard` — userspace loader/configurator

---

## 4. Deploy Systemd Services

```bash
# Copy service files
cp /opt/ddosguard/systemd/xdp-protect.service /etc/systemd/system/
cp /opt/ddosguard/systemd/xdp-alert.service /etc/systemd/system/
cp /opt/ddosguard/systemd/xdp-alert.timer /etc/systemd/system/

# Copy scripts
install -m 0755 /opt/ddosguard/scripts/xdp-protect.sh /opt/ddosguard/scripts/
install -m 0755 /opt/ddosguard/scripts/xdp-alert.sh /opt/ddosguard/scripts/

# Reload
systemctl daemon-reload
```

If the `systemd/` dir doesn't exist on the new box, create the service files:

**/etc/systemd/system/xdp-protect.service**
```ini
[Unit]
Description=XDP DDoS protect (eth0) — hostile blacklist + SYN rate limiting
Documentation=file:///etc/xdp-blocklist.txt
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=-/etc/default/xdp-protect
ExecStart=/opt/ddosguard/scripts/xdp-protect.sh
ExecStop=/opt/ddosguard/ddosguard unload eth0
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

**/etc/systemd/system/xdp-alert.service**
```ini
[Unit]
Description=XDP drop-counter polling -> Discord attack alerts
After=xdp-protect.service

[Service]
Type=oneshot
ExecStart=/opt/ddosguard/scripts/xdp-alert.sh
```

**/etc/systemd/system/xdp-alert.timer**
```ini
[Unit]
Description=Poll XDP drop counters every 15s and alert on spikes

[Timer]
OnBootSec=30
OnUnitActiveSec=15
AccuracySec=5

[Install]
WantedBy=timers.target
```

---

## 5. Configure

### 5a. Environment file

```bash
cat > /etc/default/xdp-protect <<'EOF'
SYN_RATE=200
MODE=native
EOF
```

- `SYN_RATE` — per-source SYN packets/sec allowed (default 200)
- `MODE` — `native` (driver-level, fastest) or `skb` (generic, works everywhere)

### 5b. Blocklist

Edit `/etc/xdp-blocklist.txt`. One entry per line:

```
# IPv4 single IP
1.2.3.4

# IPv4 CIDR
45.148.10.0/24

# IPv6
2001:db8::1
```

### 5c. Allowlist (optional)

Edit `/etc/xdp-lk-allowlist.txt` with trusted CIDRs. Allowlist entries **always pass** — they bypass deny list, rate limits, and escalation bans.

### 5d. Discord webhook (optional)

```bash
echo "https://discord.com/api/webhooks/YOUR/WEBHOOK" > /etc/xdp-protect-webhook
chmod 600 /etc/xdp-protect-webhook
```

---

## 6. Enable & Start

```bash
systemctl enable --now xdp-protect.service
systemctl enable --now xdp-alert.timer
```

---

## 7. Verify

```bash
# Check XDP attachment
ip link show eth0 | grep xdp

# Check drop counters
/opt/ddosguard/ddosguard show eth0

# Check active rules
/opt/ddosguard/ddosguard show eth0 | grep -A5 "deny rules"
/opt/ddosguard/ddosguard show eth0 | grep -A5 "allow rules"

# Check alert timer
systemctl list-timers xdp-alert --no-pager
```

---

## 8. Runtime Tuning (no restart needed)

```bash
D=/opt/ddosguard/ddosguard

# View current config
$D show eth0

# Change SYN rate
$D syn-rate eth0 300         # 300 SYNs/s per source
$D syn-rate eth0 300 600     # + burst 600

# Change ICMP/UDP rates
$D icmp-rate eth0 50
$D udp-rate eth0 1000

# Toggle features
$D feature eth0 syn on
$D feature eth0 icmp off
$D feature eth0 badflags on

# Ban escalation: after 4 over-limit SYNs, block /24 for 600s
$D ban eth0 4 600

# Switch to default-deny mode (only allowed ports pass)
$D mode eth0 allow
$D mode eth0 block           # back to default-allow

# Add/remove rules live
$D deny eth0 ip 1.2.3.4
$D deny eth0 net 10.0.0.0/8
$D allow eth0 ip 5.6.7.8
$D del eth0 ip 1.2.3.4
```

---

## 9. Updating the Blocklist

```bash
# Edit file
vi /etc/xdp-blocklist.txt

# Restart to reload
systemctl restart xdp-protect

# Or add individual entries without restart
/opt/ddosguard/ddosguard deny eth0 net 192.168.1.0/24
```

---

## 10. Firewall Integration (nftables + fail2ban)

Layer this *behind* the XDP program. Example for SSH brute-force:

```bash
apt-get install -y fail2ban

cat > /etc/fail2ban/jail.d/sshd.conf <<'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
EOF

systemctl enable --now fail2ban
```

---

## 11. Monitoring

```bash
# Raw stats
bpftool map dump pinned /sys/fs/bpf/ddosguard/eth0/stats

# Alert state
cat /var/lib/xdp-protect/stats.last

# Manual alert test
/opt/ddosguard/scripts/xdp-alert.sh

# Live tcpdump (if needed)
tcpdump -nn -i eth0 -c 100
```

---

## 12. Teardown

```bash
systemctl stop xdp-alert.timer xdp-protect.service
systemctl disable xdp-alert.timer xdp-protect.service
/opt/ddosguard/ddosguard unload eth0
```

---

## Architecture

```
                 Incoming Traffic
                       |
                 [ XDP ddosguard ]
                       |
            +----------+-----------+
            |          |           |
        Deny List   Rate Limits  Allow List
        (LPM trie)  (SYN/ICMP/   (always pass)
                     UDP buckets)
            |          |           |
            v          v           v
          DROP       DROP        PASS
                                   |
                             [ Kernel ]
                                   |
                           [ nftables + fail2ban ]
                                   |
                             [ Application ]
```

## Defence Layers

| Layer | Mechanism | Scope |
|---|---|---|
| NIC (XDP) | ddosguard — blocklist, rate limits, ban escalation | All incoming L2/L3/L4 |
| Firewall | nftables — fail2ban-backed sshd + 3x-ipl jails | Service-level |
| Host | fail2ban — brute-force / port scan bans | Process-level |
