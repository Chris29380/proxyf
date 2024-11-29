#!/bin/bash
COLOR1='\033[0;31m'
COLOR2='\033[1;34m'
COLOR3='\033[1;33m'
NC='\033[0m' # No Color

# -----------------------------------------------------------
# check sudo permissions
# -----------------------------------------------------------
if [ "$(id -u)" != "0" ]; then
    echo -e "${COLOR1} This script must be run as root ${NC}" 1>&2
    exit 1
fi

install_antiddos(){

    # Load required kernel modules
    #------------------------------------------------------------------------------
    "$MODPROBE" ip_conntrack_ftp
    "$MODPROBE" ip_conntrack_irc

    # Protect against SYN flood attacks
    sysctl -w net.ipv4.tcp_syncookies=1

    # Ignore all incoming ICMP echo requests
    sysctl -w net.ipv4.icmp_echo_ignore_all=0

    # Ignore ICMP echo requests to broadcast
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

    # Don't log invalid responses to broadcast
    sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1

    # Don't accept or send ICMP redirects.
    sysctl -w net.ipv4.conf.all.accept_redirects=0

    # Don't accept source routed packets.
    sudo sysctl -w net.ipv4.conf.default.accept_source_route=0

    # Disable multicast routing
    sudo sysctl -w net.ipv4.conf.interface.mc_forwarding=0

    # Disable proxy_arp.
    sudo sysctl -w net.ipv4.conf.interface.proxy_arp=0

    # Enable secure redirects, i.e. only accept ICMP redirects for gateways
    # Helps against MITM attacks.
    sudo sysctl -w net.ipv4.conf.interface.secure_redirects=1

    # Disable bootp_relay
    sudo sysctl -w net.ipv4.conf.interface.bootp_relay=0

cp ./ddos/99999-cdt.conf /etc/sysctl.d/99999-cdt.conf

# Cleanup.
    #------------------------------------------------------------------------------

    # Delete all
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F

    # Delete all
    iptables -X
    iptables -t nat -X
    iptables -t mangle -X

    # Zero all packets and counters.
    iptables -Z
    iptables -t nat -Z
    iptables -t mangle -Z

    # Completely disable IPv6.
    #------------------------------------------------------------------------------

    # Block all IPv6 traffic
    # If the ip6tables command is available, try to block all IPv6 traffic.
    if test -x "$IP6TABLES"; then
        # Set the default policies
        # drop everything
        "$IP6TABLES" -P INPUT DROP 2>/dev/null
        "$IP6TABLES" -P FORWARD DROP 2>/dev/null
        "$IP6TABLES" -P OUTPUT DROP 2>/dev/null

        # The mangle table can pass everything
        "$IP6TABLES" -t mangle -P PREROUTING ACCEPT 2>/dev/null
        "$IP6TABLES" -t mangle -P INPUT ACCEPT 2>/dev/null
        "$IP6TABLES" -t mangle -P FORWARD ACCEPT 2>/dev/null
        "$IP6TABLES" -t mangle -P OUTPUT ACCEPT 2>/dev/null
        "$IP6TABLES" -t mangle -P POSTROUTING ACCEPT 2>/dev/null

        # Delete all rules.
        "$IP6TABLES" -F 2>/dev/null
        "$IP6TABLES" -t mangle -F 2>/dev/null

        # Delete all chains.
        "$IP6TABLES" -X 2>/dev/null
        "$IP6TABLES" -t mangle -X 2>/dev/null

        # Zero all packets and counters.
        "$IP6TABLES" -Z 2>/dev/null
        "$IP6TABLES" -t mangle -Z 2>/dev/null
    fi

    # Drop everything by default.
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    # Default policies.
    #------------------------------------------------------------------------------

    # Drop everything by default.
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    # Set the nat/mangle/raw tables' chains to ACCEPT
    iptables -t nat -P PREROUTING ACCEPT
    iptables -t nat -P OUTPUT ACCEPT
    iptables -t nat -P POSTROUTING ACCEPT

    iptables -t mangle -P PREROUTING ACCEPT
    iptables -t mangle -P INPUT ACCEPT
    iptables -t mangle -P FORWARD ACCEPT
    iptables -t mangle -P OUTPUT ACCEPT
    iptables -t mangle -P POSTROUTING ACCEPT

    # Custom user-defined chains.
    #------------------------------------------------------------------------------

    # LOG packets, then ACCEPT.
    iptables -N ACCEPTLOG
    iptables -A ACCEPTLOG -j LOG --log-prefix "ACCEPT " -m limit --limit 3/s --limit-burst 8
    iptables -A ACCEPTLOG -j ACCEPT

    # LOG packets, then DROP.
    iptables -N DROPLOG
    iptables -A DROPLOG -j LOG --log-prefix "DROP " -m limit --limit 3/s --limit-burst 8
    iptables -A DROPLOG -j DROP

    # LOG packets, then REJECT.
    # TCP packets are rejected with a TCP reset.
    iptables -N REJECTLOG
    iptables -A REJECTLOG -j LOG --log-prefix "REJECT " -m limit --limit 3/s --limit-burst 8
    iptables -A REJECTLOG -p tcp -j REJECT --reject-with tcp-reset
    iptables -A REJECTLOG -j REJECT

    # Only allows RELATED ICMP types
    # (destination-unreachable, time-exceeded, and parameter-problem).
    # TODO: Rate-limit this traffic?
    # TODO: Allow fragmentation-needed?
    # TODO: Test.
    iptables -N RELATED_ICMP
    iptables -A RELATED_ICMP -p icmp --icmp-type destination-unreachable -j ACCEPT
    iptables -A RELATED_ICMP -p icmp --icmp-type time-exceeded -j ACCEPT
    iptables -A RELATED_ICMP -p icmp --icmp-type parameter-problem -j ACCEPT
    iptables -A RELATED_ICMP -j DROPLOG

    # Make It Even Harder To Multi-PING
    iptables  -A INPUT -p icmp -m limit --limit 1/s --limit-burst 2 -j ACCEPT
    iptables  -A INPUT -p icmp -m limit --limit 1/s --limit-burst 2 -j LOG --log-prefix "PING-DROP: "
    iptables  -A INPUT -p icmp -j DROP
    iptables  -A OUTPUT -p icmp -j ACCEPT

    # Only allow the minimally required/recommended parts of ICMP. Block the rest.
    #------------------------------------------------------------------------------

    # TODO: This section needs a lot of testing!

    # First, drop all fragmented ICMP packets (almost always malicious).
    iptables -A INPUT -p icmp --fragment -j DROPLOG
    iptables -A OUTPUT -p icmp --fragment -j DROPLOG
    iptables -A FORWARD -p icmp --fragment -j DROPLOG

    # Allow all ESTABLISHED ICMP traffic.
    iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT -m limit --limit 3/s --limit-burst 8
    iptables -A OUTPUT -p icmp -m state --state ESTABLISHED -j ACCEPT -m limit --limit 3/s --limit-burst 8

    # Allow some parts of the RELATED ICMP traffic, block the rest.
    iptables -A INPUT -p icmp -m state --state RELATED -j RELATED_ICMP -m limit --limit 3/s --limit-burst 8
    iptables -A OUTPUT -p icmp -m state --state RELATED -j RELATED_ICMP -m limit --limit 3/s --limit-burst 8

    # Allow incoming ICMP echo requests (ping), but only rate-limited.
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT -m limit --limit 3/s --limit-burst 8

    # Allow outgoing ICMP echo requests (ping), but only rate-limited.
    iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT -m limit --limit 3/s --limit-burst 8

    # Drop any other ICMP traffic.
    iptables -A INPUT -p icmp -j DROPLOG
    iptables -A OUTPUT -p icmp -j DROPLOG
    iptables -A FORWARD -p icmp -j DROPLOG

    # Selectively allow certain special types of traffic.
    #------------------------------------------------------------------------------

    # Allow loopback interface to do anything.
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow incoming connections related to existing allowed connections.
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow outgoing connections EXCEPT invalid
    iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

    # Miscellaneous.
    #------------------------------------------------------------------------------

    # We don't care about Milkosoft, Drop SMB/CIFS/etc..
    iptables -A INPUT -p tcp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP
    iptables -A INPUT -p udp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP

    # Explicitly drop invalid incoming traffic
    iptables -A INPUT -m state --state INVALID -j DROP

    # Drop invalid outgoing traffic, too.
    iptables -A OUTPUT -m state --state INVALID -j DROP

    # If we would use NAT, INVALID packets would pass - BLOCK them anyways
    iptables -A FORWARD -m state --state INVALID -j DROP

    # PORT Scanners (stealth also)
    iptables -A INPUT -m state --state NEW -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A INPUT -m state --state NEW -p tcp --tcp-flags ALL NONE -j DROP

    # TODO: Some more anti-spoofing rules? For example:
    iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
    iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    iptables -N SYN_FLOOD
    iptables -A INPUT -p tcp --syn -j SYN_FLOOD
    iptables -A SYN_FLOOD -m limit --limit 2/s --limit-burst 6 -j RETURN
    iptables -A SYN_FLOOD -j DROP

    # Drop any traffic from IANA-reserved IPs.
    #------------------------------------------------------------------------------

    iptables -A INPUT -s 0.0.0.0/7 -j DROP
    iptables -A INPUT -s 2.0.0.0/8 -j DROP
    iptables -A INPUT -s 5.0.0.0/8 -j DROP
    iptables -A INPUT -s 7.0.0.0/8 -j DROP
    iptables -A INPUT -s 10.0.0.0/8 -j DROP
    iptables -A INPUT -s 23.0.0.0/8 -j DROP
    iptables -A INPUT -s 27.0.0.0/8 -j DROP
    iptables -A INPUT -s 31.0.0.0/8 -j DROP
    iptables -A INPUT -s 36.0.0.0/7 -j DROP
    iptables -A INPUT -s 39.0.0.0/8 -j DROP
    iptables -A INPUT -s 42.0.0.0/8 -j DROP
    iptables -A INPUT -s 49.0.0.0/8 -j DROP
    iptables -A INPUT -s 50.0.0.0/8 -j DROP
    iptables -A INPUT -s 77.0.0.0/8 -j DROP
    iptables -A INPUT -s 78.0.0.0/7 -j DROP
    iptables -A INPUT -s 92.0.0.0/6 -j DROP
    iptables -A INPUT -s 96.0.0.0/4 -j DROP
    iptables -A INPUT -s 112.0.0.0/5 -j DROP
    iptables -A INPUT -s 120.0.0.0/8 -j DROP
    iptables -A INPUT -s 169.254.0.0/16 -j DROP
    iptables -A INPUT -s 172.16.0.0/12 -j DROP
    iptables -A INPUT -s 173.0.0.0/8 -j DROP
    iptables -A INPUT -s 174.0.0.0/7 -j DROP
    iptables -A INPUT -s 176.0.0.0/5 -j DROP
    iptables -A INPUT -s 184.0.0.0/6 -j DROP
    iptables -A INPUT -s 192.0.2.0/24 -j DROP
    iptables -A INPUT -s 197.0.0.0/8 -j DROP
    iptables -A INPUT -s 198.18.0.0/15 -j DROP
    iptables -A INPUT -s 223.0.0.0/8 -j DROP
    iptables -A INPUT -s 224.0.0.0/3 -j DROP

    # Selectively allow certain connections, block the rest.
    #------------------------------------------------------------------------------

    # Allow DNS requests. Few things will work without this.
    iptables -A INPUT -m state --state NEW -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -m state --state NEW -p tcp --dport 53 -j ACCEPT
    iptables -A OUTPUT -m state --state NEW -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -m state --state NEW -p tcp --dport 53 -j ACCEPT

    # Allow HTTP requests. Unencrypted, use with care.
    iptables -A INPUT -m state --state NEW -p tcp --dport 80 -j ACCEPT
    iptables -A OUTPUT -m state --state NEW -p tcp --dport 80 -j ACCEPT

    # Allow HTTPS requests.
    iptables -A INPUT -m state --state NEW -p tcp --dport 443 -j ACCEPT
    iptables -A OUTPUT -m state --state NEW -p tcp --dport 443 -j ACCEPT

    # Allow SSH requests.
    iptables -A INPUT -m state --state NEW -p tcp --dport "$SSHPORT" -j ACCEPT
    iptables -A OUTPUT -m state --state NEW -p tcp --dport "$SSHPORT" -j ACCEPT

    # Explicitly log and reject everything else.
    #------------------------------------------------------------------------------

    # Use REJECT instead of REJECTLOG if you don't need/want logging.
    iptables -A INPUT -j REJECTLOG
    iptables -A OUTPUT -j REJECTLOG
    iptables -A FORWARD -j REJECTLOG
}

install_antiddos