"""Coordinate bounded scanning and local-port rotation in an isolated network.

UDP discovery selects an endpoint. The subsequent native ICE/DTLS session
authenticates the peer and establishes the data channels.
"""
import argparse
import json
import secrets
import socket
import sys
import time

from nat_gateway import OBSERVERS, emit


def bind(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", port))
    except BaseException:
        sock.close()
        raise
    return sock


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=["scan", "rotate"], required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    if not 2000 <= args.port <= 65000:
        parser.error("local port must allow the bounded sweep")
    held = None
    emit({"type": "ready"})
    try:
        for line in sys.stdin:
            command = json.loads(line)
            kind = command["type"]
            if kind == "stop":
                break
            if kind == "observe":
                if held:
                    raise ValueError("observation already active")
                held = bind(args.port)
                held.settimeout(1)
                observed = []
                # Observe two distinct destination addresses through the same socket.
                for index in [0, 2]:
                    nonce = secrets.token_hex(8)
                    held.sendto(json.dumps({"probe": nonce, "replyFrom": index}).encode(), OBSERVERS[index])
                    data, source = held.recvfrom(1024)
                    result = json.loads(data)
                    if source != OBSERVERS[index] or result["nonce"] != nonce:
                        raise ValueError("invalid observation")
                    observed.append(result["mapped"])
                    time.sleep(0.001)
                if args.role == "rotate":
                    held.close()
                    held = None
                emit({"type": "observed", "localPort": args.port, "mappings": observed})
                continue
            peer = command["ip"]
            if peer not in ["198.18.0.1", "198.18.0.2"]:
                raise ValueError("fixture peers only")
            if kind == "scan" and args.role == "scan" and held:
                center = int(command["center"])
                if not 1224 <= center <= 65335:
                    raise ValueError("invalid scan range")
                for port in range(center - 200, center + 201):
                    # 10 ns requests at multiples of 100 are below Python timer resolution.
                    if port % 10000 == 0:
                        time.sleep(0.2)
                    held.sendto(b"", (peer, port))
                emit({"type": "scanned", "first": center - 200, "last": center + 200, "sent": 401})
                until = time.monotonic() + 5
                hit = None
                while time.monotonic() < until:
                    held.settimeout(max(0.001, until - time.monotonic()))
                    try:
                        payload, source = held.recvfrom(100)
                    except socket.timeout:
                        break
                    if source[0] != peer:
                        continue
                    try:
                        local = int(payload.decode("ascii"))
                    except (ValueError, UnicodeError):
                        continue
                    if 1024 <= local <= 65535:
                        hit = {"remote": source, "remoteLocalPort": local, "localPort": args.port}
                        break
                held.close()
                held = None
                emit({"type": "hit", "hit": hit})
            elif kind == "rotate" and args.role == "rotate":
                destination = int(command["port"])
                if not 1024 <= destination <= 65535:
                    raise ValueError("invalid predicted destination")
                sent, occupied = 0, 0
                ports = [args.port]
                for delta in range(1, 201):
                    ports.extend([args.port + delta, args.port - delta])
                for index, port in enumerate(ports):
                    try:
                        sock = bind(port)
                    except OSError:
                        occupied += 1
                        continue
                    with sock:
                        sock.sendto(str(port).encode(), (peer, destination))
                        sent += 1
                    if index > 0 and index % 2 == 0:
                        time.sleep(0.001)
                # DeScan waits 200 ms before reporting completion to the coordinator.
                time.sleep(0.2)
                emit({"type": "rotated", "attempts": 401, "sent": sent, "occupied": occupied,
                      "destination": [peer, destination]})
            else:
                raise ValueError("invalid stage")
    finally:
        if held:
            held.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        emit({"type": "error", "error": str(error)})
        raise
