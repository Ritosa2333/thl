"""Bounded IPv4 UDP NAT fixture and independent mapping/filter probes."""
import argparse
import fcntl
import json
import os
import random
import selectors
import signal
import socket
import struct
import time

WAN = {"198.18.0.1", "198.18.0.2", "198.18.0.10", "198.18.0.11"}
OBSERVERS = [("198.18.0.10", 3478), ("198.18.0.10", 3479), ("198.18.0.11", 3478)]
COOKIE = 0x2112A442


def wire_kind(payload):
    if len(payload) >= 20 and payload[4:8] == struct.pack("!I", COOKIE):
        return "stun"
    if len(payload) >= 13 and payload[1:3] in (b"\xfe\xff", b"\xfe\xfd"):
        return "dtlsApplication" if payload[0] == 23 else "dtlsHandshake"
    if len(payload) == 96 and payload[0] in (67, 84) and payload[1] <= 1 and payload[2] <= 1:
        seq = int.from_bytes(payload[4:8], "little")
        if all(payload[i] == (seq + i) % 251 for i in range(8, 96)):
            return "plaintextTestData"
    return "other"


def emit(value):
    print(json.dumps(value), flush=True)


def checksum(data):
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(src, sport, dst, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0,
                         64, 17, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + udp


def gateway(args):
    if args.external not in WAN or not 10000 <= args.base <= 60000:
        raise ValueError("fixture addresses and ports only")
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    fcntl.ioctl(fd, 0x400454CA, struct.pack("16sH", b"thl-tun", 0x0001 | 0x1000))
    selector = selectors.DefaultSelector()
    selector.register(fd, selectors.EVENT_READ, None)
    mappings = {}
    rng = random.Random(args.seed)
    ports = list(range(args.base, args.base + 4096))
    if args.allocation == "random":
        rng.shuffle(ports)
    stats = {"mode": args.mode, "allocation": args.allocation,
             "outbound": 0, "inbound": 0, "filtered": 0, "unsupported": 0}
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    emit({"type": "ready"})
    try:
        while running:
            for key, _ in selector.select(0.2):
                if key.data is None:
                    data = os.read(fd, 65535)
                    ihl = (data[0] & 15) * 4
                    if len(data) < ihl + 8 or data[9] != 17 or struct.unpack("!H", data[6:8])[0] & 0x3FFF:
                        stats["unsupported"] += 1
                        continue
                    src, dst = socket.inet_ntoa(data[12:16]), socket.inet_ntoa(data[16:20])
                    sport, dport, length, _ = struct.unpack("!HHHH", data[ihl:ihl + 8])
                    if dst not in WAN or not (src.startswith("10.231.1.") or src.startswith("10.231.2.")):
                        stats["filtered"] += 1
                        continue
                    remote = (dst, dport)
                    identity = (src, sport)
                    if args.mode == "nat4":
                        identity += remote
                    elif args.mode == "nat4-address":
                        identity += (dst,)
                    entry = mappings.get(identity)
                    if entry is None:
                        if len(mappings) >= len(ports):
                            raise RuntimeError("fixture mapping budget exceeded")
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.bind((args.external, ports[len(mappings)]))
                        entry = {"socket": sock, "internal": (src, sport), "allowed": set(), "wire": {}}
                        mappings[identity] = entry
                        selector.register(sock, selectors.EVENT_READ, entry)
                    entry["allowed"].add(remote)
                    payload = data[ihl + 8:ihl + length]
                    kind = wire_kind(payload)
                    entry["wire"][kind] = entry["wire"].get(kind, 0) + 1
                    entry["socket"].sendto(payload, remote)
                    stats["outbound"] += 1
                else:
                    entry = key.data
                    payload, remote = entry["socket"].recvfrom(65535)
                    if args.mode != "open" and remote not in entry["allowed"]:
                        stats["filtered"] += 1
                        continue
                    os.write(fd, packet(*remote, *entry["internal"], payload))
                    stats["inbound"] += 1
    finally:
        stats["mappings"] = len(mappings)
        stats["wire"] = {kind: sum(e["wire"].get(kind, 0) for e in mappings.values())
                         for kind in ("stun", "dtlsHandshake", "dtlsApplication", "plaintextTestData", "other")}
        stats["dataFlows"] = [{"internal": e["internal"], "external": e["socket"].getsockname(),
                               "destinations": sorted(e["allowed"]), "wire": e["wire"]}
                              for e in mappings.values() if e["wire"].get("dtlsApplication")]
        emit({"type": "gateway-result", **stats})
        for entry in mappings.values():
            entry["socket"].close()
        selector.close()
        os.close(fd)


def observe():
    selector = selectors.DefaultSelector()
    sockets = []
    for address in OBSERVERS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(address)
        sockets.append(sock)
        selector.register(sock, selectors.EVENT_READ)
    emit({"type": "ready"})
    while True:
        for key, _ in selector.select():
            sock = key.fileobj
            data, remote = sock.recvfrom(65535)
            if len(data) >= 20 and data[:2] == b"\0\1" and struct.unpack("!I", data[4:8])[0] == COOKIE:
                value = struct.pack("!BBHI", 0, 1, remote[1] ^ (COOKIE >> 16),
                                    struct.unpack("!I", socket.inet_aton(remote[0]))[0] ^ COOKIE)
                attr = struct.pack("!HH", 0x0020, len(value)) + value
                response = struct.pack("!HHI", 0x0101, len(attr), COOKIE) + data[8:20] + attr
                sock.sendto(response, remote)
            elif data.startswith(b'{"probe":'):
                request = json.loads(data)
                source = sockets[request.get("replyFrom", 0)]
                source.sendto(json.dumps({"nonce": request["probe"], "mapped": remote}).encode(), remote)


def probe():
    results = []
    # A fresh socket for each filtering test prevents prior mappings opening the filter.
    for reply in [0, 1, 2]:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.4)
            nonce = os.urandom(8).hex()
            sock.sendto(json.dumps({"probe": nonce, "replyFrom": reply}).encode(), OBSERVERS[0])
            try:
                result = json.loads(sock.recvfrom(4096)[0])
                results.append(result["nonce"] == nonce)
            except socket.timeout:
                results.append(False)
    mappings = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        for index, address in enumerate(OBSERVERS):
            nonce = os.urandom(8).hex()
            sock.sendto(json.dumps({"probe": nonce, "replyFrom": index}).encode(), address)
            result = json.loads(sock.recvfrom(4096)[0])
            if result["nonce"] != nonce:
                raise RuntimeError("probe nonce mismatch")
            mappings.append(result["mapped"])
    emit({"type": "probe-result", "mappings": mappings,
          "sameSocketSameMapping": len({tuple(x) for x in mappings}) == 1,
          "acceptedSources": dict(zip(["same", "otherPort", "otherIp"], results))})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("task", choices=["gateway", "observe", "probe"])
    parser.add_argument("--mode", choices=["open", "nat3", "nat4", "nat4-address"], default="nat3")
    parser.add_argument("--external", default="198.18.0.1")
    parser.add_argument("--base", type=int, default=40000)
    parser.add_argument("--allocation", choices=["sequential", "random"], default="sequential")
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    {"gateway": lambda: gateway(args), "observe": observe, "probe": probe}[args.task]()
