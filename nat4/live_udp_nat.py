#!/usr/bin/env python3
"""Provide bounded UDP NAT behavior for a thl network namespace.

Host sockets provide the external mappings. Sandbox policy routes select the
gateway, which records endpoint metadata and encrypted packet categories.
"""

import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import resource
import selectors
import signal
import socket
import struct
import subprocess
import time

from nat_gateway import packet, wire_kind


TABLE = 31072
TUN = "thl-live"


def command(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--external", required=True)
    parser.add_argument("--peer", action="append", required=True)
    parser.add_argument("--observer", action="append", default=[])
    parser.add_argument("--mode", choices=("adm", "apdm"), required=True)
    parser.add_argument("--allocation", choices=("sequential", "random"), default="sequential")
    parser.add_argument("--base", type=int, default=40000)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--duration", type=int, default=300)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"thl-native-[a-f0-9]{10}", args.namespace):
        parser.error("only dedicated thl experiment namespaces are accepted")
    if not 1024 <= args.base <= 57000 or not 1 <= args.duration <= 1800:
        parser.error("invalid port range or lifetime")
    external = str(ipaddress.IPv4Address(args.external))
    soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    required_limit = 8192 + 128
    if hard_limit != resource.RLIM_INFINITY and hard_limit < required_limit:
        parser.error("the experiment needs at least 8320 file descriptors")
    if soft_limit != resource.RLIM_INFINITY and soft_limit < required_limit:
        resource.setrlimit(resource.RLIMIT_NOFILE, (required_limit, hard_limit))
    peers = {str(ipaddress.IPv4Address(peer)) for peer in args.peer}
    observers = set()
    for value in args.observer:
        host, port = value.rsplit(":", 1)
        observers.add((str(ipaddress.IPv4Address(host)), int(port)))
    hostns = os.open("/proc/self/ns/net", os.O_RDONLY)
    clientns = os.open("/run/netns/" + args.namespace, os.O_RDONLY)
    selector = selectors.DefaultSelector()
    mappings = {}
    ports = list(range(args.base, args.base + 8192))
    if args.allocation == "random":
        random.Random(args.seed).shuffle(ports)
    ports = iter(ports)
    stats = {"mode": args.mode, "allocation": args.allocation, "outbound": 0,
             "inbound": 0, "filtered": 0, "unsupported": 0, "denied": {},
             "mappingExpiry": "fixed for each trial"}
    stopping = False
    fd = None
    configured = []
    previous_rpf = None
    started = time.monotonic()

    def stop(*_):
        nonlocal stopping
        stopping = True

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)

    def save():
        report = dict(stats, elapsedSeconds=round(time.monotonic() - started, 3))
        report["mappings"] = [{"internal": entry["internal"], "external": entry["external"],
                               "destinations": sorted(entry["allowed"]), "outbound": entry["outbound"],
                               "inbound": entry["inbound"], "bytesOut": entry["bytesOut"],
                               "bytesIn": entry["bytesIn"], "wire": entry["wire"]} for entry in mappings.values()]
        report["wire"] = {kind: sum(entry["wire"].get(kind, 0) for entry in mappings.values())
                          for kind in ("stun", "dtlsHandshake", "dtlsApplication", "plaintextTestData", "other")}
        temp = args.output.with_suffix(".tmp")
        temp.write_text(json.dumps(report, indent=2) + "\n")
        temp.replace(args.output)

    try:
        os.setns(clientns, 0x40000000)
        if str(TABLE) in command("ip", "rule", "show").stdout:
            raise RuntimeError("sandbox already has the experiment's policy route")
        fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        fcntl.ioctl(fd, 0x400454CA, struct.pack("16sH", TUN.encode(), 0x0001 | 0x1000))
        command("ip", "link", "set", TUN, "up")
        previous_rpf = Path("/proc/sys/net/ipv4/conf/all/rp_filter").read_text()
        Path("/proc/sys/net/ipv4/conf/all/rp_filter").write_text("0\n")
        Path(f"/proc/sys/net/ipv4/conf/{TUN}/rp_filter").write_text("0\n")
        command("ip", "route", "add", "table", str(TABLE), "default", "dev", TUN, "src", "10.0.2.100")
        # Local subnet traffic follows the namespace's main route.
        command("ip", "rule", "add", "priority", str(TABLE - 1), "to", "10.0.2.0/24", "lookup", "main")
        configured.append(TABLE - 1)
        command("ip", "rule", "add", "priority", str(TABLE), "ipproto", "udp", "lookup", str(TABLE))
        configured.append(TABLE)
        os.setns(hostns, 0x40000000)
        selector.register(fd, selectors.EVENT_READ, None)
        print(json.dumps({"ready": True, "mode": args.mode, "namespace": args.namespace}), flush=True)
        last_save = time.monotonic()
        while not stopping and time.monotonic() - started < args.duration:
            for key, _ in selector.select(.1):
                if key.data is None:
                    data = os.read(fd, 65535)
                    if len(data) < 28 or data[0] >> 4 != 4:
                        stats["unsupported"] += 1
                        continue
                    ihl = (data[0] & 15) * 4
                    if len(data) < ihl + 8 or data[9] != 17 or struct.unpack("!H", data[6:8])[0] & 0x3FFF:
                        stats["unsupported"] += 1
                        continue
                    src, dst = socket.inet_ntoa(data[12:16]), socket.inet_ntoa(data[16:20])
                    sport, dport, length, _ = struct.unpack("!HHHH", data[ihl:ihl + 8])
                    remote = (dst, dport)
                    if src != "10.0.2.100" or not (dst in peers or remote in observers):
                        name = dst + ":" + str(dport)
                        stats["denied"][name] = stats["denied"].get(name, 0) + 1
                        continue
                    if length < 8 or ihl + length > len(data):
                        stats["unsupported"] += 1
                        continue
                    identity = (src, sport, dst) + ((dport,) if args.mode == "apdm" else ())
                    entry = mappings.get(identity)
                    if entry is None:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        for port in ports:
                            try:
                                sock.bind((external, port))
                                break
                            except OSError:
                                continue
                        else:
                            sock.close()
                            raise RuntimeError("bounded external port pool exhausted")
                        sock.setblocking(False)
                        entry = {"socket": sock, "external": sock.getsockname(), "internal": (src, sport), "allowed": set(),
                                 "outbound": 0, "inbound": 0, "bytesOut": 0, "bytesIn": 0, "wire": {}}
                        mappings[identity] = entry
                        selector.register(sock, selectors.EVENT_READ, entry)
                    entry["allowed"].add(remote)
                    payload = data[ihl + 8:ihl + length]
                    kind = wire_kind(payload)
                    entry["wire"][kind] = entry["wire"].get(kind, 0) + 1
                    entry["socket"].sendto(payload, remote)
                    entry["outbound"] += 1
                    entry["bytesOut"] += len(payload)
                    stats["outbound"] += 1
                else:
                    entry = key.data
                    payload, remote = entry["socket"].recvfrom(65535)
                    if remote not in entry["allowed"]:
                        stats["filtered"] += 1
                        continue
                    os.write(fd, packet(*remote, *entry["internal"], payload))
                    entry["inbound"] += 1
                    entry["bytesIn"] += len(payload)
                    stats["inbound"] += 1
            if time.monotonic() - last_save >= 1:
                save()
                last_save = time.monotonic()
    except Exception as error:
        stats["error"] = str(error)
        raise
    finally:
        # Release sockets first so cleanup can still spawn ip after resource exhaustion.
        for entry in mappings.values():
            entry["socket"].close()
        selector.close()
        os.setns(clientns, 0x40000000)
        for priority in reversed(configured):
            command("ip", "rule", "del", "priority", str(priority))
        if previous_rpf is not None:
            Path("/proc/sys/net/ipv4/conf/all/rp_filter").write_text(previous_rpf)
        if fd is not None:
            os.close(fd)  # Closing the TUN also removes its route.
        stats["cleanupComplete"] = not configured or str(TABLE) not in command("ip", "rule", "show").stdout
        os.setns(hostns, 0x40000000)
        save()
        os.close(clientns)
        os.close(hostns)


if __name__ == "__main__":
    main()
