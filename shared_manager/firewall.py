"""Idempotent rules scoped to the new shared instance and its three ports."""
from __future__ import annotations

import argparse
import subprocess

if __package__:
    from .transport import PrivateTransport
else:
    from transport import PrivateTransport

PORTS = "6666,7777,9999"
COMMENT = "shared-node-manager-private-20261107"


def rule(table, chain, args):
    prefix = ["iptables", "-w", "10", "-t", table]
    args = [*args, "-m", "comment", "--comment", COMMENT]
    if subprocess.run([*prefix, "-C", chain, *args], capture_output=True).returncode:
        subprocess.run([*prefix, "-I", chain, "1", *args], check=True)


def transport_rules(role, transport):
    """Return only the shared ports; never rewrite the website's forwarding."""
    t = transport
    if role == "entry":
        return [
            ("nat", "PREROUTING", ["-d", t.entry_public + "/32", "-p", "tcp", "-m", "multiport", "--dports", PORTS,
                                    "-j", "DNAT", "--to-destination", t.exit_private]),
            ("nat", "POSTROUTING", ["-d", t.exit_private + "/32", "-o", t.interface, "-p", "tcp", "-m", "multiport", "--dports", PORTS,
                                     "-j", "SNAT", "--to-source", t.entry_private]),
            ("filter", "FORWARD", ["-o", t.interface, "-d", t.exit_private + "/32", "-p", "tcp", "-m", "multiport", "--dports", PORTS, "-j", "ACCEPT"]),
            ("filter", "FORWARD", ["-i", t.interface, "-s", t.exit_private + "/32", "-p", "tcp", "-m", "multiport", "--sports", PORTS,
                                    "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]),
        ]
    if role == "exit":
        return [
            ("filter", "INPUT", ["-i", t.interface, "-s", t.entry_private + "/32", "-d", t.exit_private + "/32", "-p", "tcp", "-m", "multiport", "--dports", PORTS, "-j", "ACCEPT"]),
            ("filter", "INPUT", ["-i", "lo", "-d", t.exit_private + "/32", "-p", "tcp", "-m", "multiport", "--dports", PORTS, "-j", "ACCEPT"]),
            ("filter", "INPUT", ["-d", t.exit_private + "/32", "-p", "tcp", "-m", "multiport", "--dports", PORTS, "-j", "DROP"]),
        ]
    raise ValueError("unknown role")


def install(role, transport=None):
    transport = transport or PrivateTransport()
    # Insert from lowest to highest priority so source-restricted accepts precede DROP.
    for table, chain, args in reversed(transport_rules(role, transport)):
        rule(table, chain, args)
    if role == "exit":
        import pwd
        rule("filter", "INPUT", ["-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "ACCEPT"])
        # User proxy requests must not access this server's management network.
        uid = str(pwd.getpwnam("shared-singbox").pw_uid)
        for cidr in ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
                     "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4", "168.63.129.16/32", "168.93.208.118/32", "150.242.80.15/32"]:
            rule("filter", "OUTPUT", ["-m", "owner", "--uid-owner", uid, "-d", cidr,
                                       "-m", "conntrack", "--ctstate", "NEW", "-j", "REJECT"])
        # New core has no IPv6 listeners; block private IPv6 destinations for
        # authenticated requests as well, without touching other services.
        for cidr in ["::1/128", "fc00::/7", "fe80::/10", "ff00::/8"]:
            args = ["-m", "owner", "--uid-owner", uid, "-d", cidr, "-m", "conntrack", "--ctstate", "NEW",
                    "-j", "REJECT", "-m", "comment", "--comment", COMMENT]
            prefix = ["ip6tables", "-w", "10"]
            if subprocess.run([*prefix, "-C", "OUTPUT", *args], capture_output=True).returncode:
                subprocess.run([*prefix, "-I", "OUTPUT", "1", *args], check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["entry", "exit"])
    parser.add_argument("--entry-public", default="150.242.80.15")
    parser.add_argument("--entry-private", default="172.16.80.15")
    parser.add_argument("--exit-private", default="172.16.208.118")
    parser.add_argument("--interface", default="ens19")
    args = parser.parse_args()
    install(args.role, PrivateTransport(args.entry_public, args.entry_private, args.exit_private, args.interface))
