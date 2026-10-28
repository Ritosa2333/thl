"""Validate public native NAT4 connections through SSH signaling and bounded UDP gateways.

Each endpoint owns a disposable network namespace. The controller shares the
local lab's SDP exchange and data checks, then collects the gateway measurements.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import queue
import shlex
import signal
import subprocess
import sys
import threading
import time
import uuid

from run_lab import HERE, Lab


def emit(value):
    print(json.dumps(value), flush=True)


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10).stdout


def endpoint(args):
    namespace = "thl-native-" + uuid.uuid4().hex[:10]
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    children, logs = [], []
    created, stopping = False, False
    report = {"type": "lab-closed", "namespace": namespace, "cleanupComplete": False,
              "nativeBinarySha256": hashlib.sha256(Path(args.native).read_bytes()).hexdigest()}

    def stop(*_):
        nonlocal stopping
        stopping = True

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)
    try:
        command("ip", "netns", "add", namespace)
        created = True
        command("ip", "-n", namespace, "link", "set", "lo", "up")
        command("ip", "-n", namespace, "link", "add", "eth0", "type", "dummy")
        command("ip", "-n", namespace, "addr", "add", "10.0.2.100/24", "dev", "eth0")
        command("ip", "-n", namespace, "link", "set", "eth0", "up")
        command("ip", "-n", namespace, "route", "add", "default", "dev", "eth0")
        log = (args.output / "gateway.stderr").open("w")
        logs.append(log)
        gateway = subprocess.Popen([sys.executable, str(HERE / "live_udp_nat.py"),
            "--namespace", namespace, "--external", args.external, "--peer", args.peer,
            "--observer", args.stun, "--mode", "apdm", "--base", str(args.base),
            "--allocation", args.allocation, "--seed", str(args.seed),
            "--duration", "180", "--output", str(args.output / "nat.json")],
            stdout=subprocess.PIPE, stderr=log, text=True, start_new_session=True)
        children.append(gateway)
        ready = queue.Queue()
        threading.Thread(target=lambda: ready.put(gateway.stdout.readline()), daemon=True).start()
        if not json.loads(ready.get(timeout=15)).get("ready"):
            raise RuntimeError("gateway initialization failed")
        log = (args.output / "native.stderr").open("w")
        logs.append(log)
        peer = subprocess.Popen(["ip", "netns", "exec", namespace, args.native,
            args.role, str(args.origin), str(args.packets), str(args.idle_seconds), "0", "stun:" + args.stun],
            stdin=sys.stdin, stdout=sys.stdout, stderr=log, start_new_session=True)
        children.append(peer)
        begin = time.monotonic()
        while peer.poll() is None and not stopping and time.monotonic() - begin < 150:
            if gateway.poll() is not None:
                raise RuntimeError("gateway stopped before native endpoint")
            time.sleep(.1)
        report["peerExitCode"] = peer.poll()
        report["stopReason"] = "signal" if stopping else "exit" if peer.poll() is not None else "duration"
    except Exception as error:
        report["error"] = str(error)
        emit({"type": "error", "error": str(error)})
    finally:
        for child in reversed(children):
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=3)
        for log in logs:
            log.close()
        if (args.output / "nat.json").exists():
            report["gateway"] = json.loads((args.output / "nat.json").read_text())
        if created:
            remaining = command("ip", "netns", "pids", namespace).split()
            if remaining:
                report["remainingPids"] = remaining
            else:
                command("ip", "netns", "delete", namespace)
                report["cleanupComplete"] = report.get("gateway", {}).get("cleanupComplete", False)
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        emit(report)


class PublicLab(Lab):
    def __init__(self, args, config):
        super().__init__(args, args.output)
        self.config = config
        self.addresses = {role: str(ipaddress.IPv4Address(config[role]["public"])) for role in ("a", "b")}
        self.readers = []

    def spawn(self, name, role, argv):
        host = self.config[role]
        other = "b" if role == "a" else "a"
        remote = ["python3", host["directory"] + "/live_native_lab.py", "endpoint",
            "--native", host["native"], "--output", host["outputRoot"] + "/" + self.args.output.name,
            "--external", host["external"], "--peer", self.addresses[other],
            "--stun", self.config["stun"], "--base", str(host["base"]),
            "--allocation", self.args.allocation, "--seed", str(self.args.seed),
            "--role", argv[1], "--origin", argv[2], "--packets", argv[3], "--idle-seconds", argv[4]]
        log = (self.directory / (role + ".ssh.stderr")).open("w")
        self.logs.append(log)
        process = subprocess.Popen(["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
            "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3", *host["ssh"], shlex.join(remote)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True, bufsize=1)
        self.processes.append((role, process))

        def read():
            for line in process.stdout:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    value = {"type": "error", "error": "invalid endpoint output"}
                self.events.put((role, value))
            self.events.put((role, {"type": "exit"}))

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        self.readers.append(reader)
        return process

    def close(self):
        for _, process in self.processes:
            if process.poll() is None:
                try:
                    self.send(process, {"type": "stop"})
                    process.stdin.close()
                except (BrokenPipeError, OSError):
                    pass
        for _, process in self.processes:
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.terminate()  # Remote wrapper also has a hard lifetime.
                process.wait(timeout=5)
        for reader in self.readers:
            reader.join(timeout=2)
        for log in self.logs:
            log.close()
        while not self.events.empty():
            role, value = self.events.get_nowait()
            if value["type"] != "description":
                self.history.append({"role": role, **value})
        (self.directory / "events.json").write_text(json.dumps(self.history, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("endpoint", "control"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--native")
    parser.add_argument("--external")
    parser.add_argument("--peer")
    parser.add_argument("--stun")
    parser.add_argument("--base", type=int)
    parser.add_argument("--role", choices=("offer", "answer"))
    parser.add_argument("--origin", type=int, choices=(0, 1))
    parser.add_argument("--packets", type=int, default=300)
    parser.add_argument("--idle-seconds", type=int, choices=range(31), default=0)
    parser.add_argument("--offer", choices=("a", "b"), default="a")
    parser.add_argument("--strategy", choices=("ice", "next-port"), default="next-port")
    parser.add_argument("--next-offset", type=int, choices=range(-16, 17), default=1)
    parser.add_argument("--allocation", choices=("sequential", "random"), default="sequential")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--bad-fingerprint", action="store_true")
    args = parser.parse_args()
    if not 300 <= args.packets <= 3600 or args.packets % 20:
        parser.error("packet count must be a multiple of 20 in [300, 3600]")
    if args.mode == "endpoint":
        if not all([args.native, args.external, args.peer, args.stun, args.base, args.role]) or args.origin is None:
            parser.error("endpoint requires native, external, peer, stun, base, role and origin")
        return endpoint(args)
    if not args.config:
        parser.error("control requires a two-host configuration")
    args.output.mkdir(parents=True, exist_ok=False)
    lab = PublicLab(args, json.loads(args.config.read_text()))
    result = {"offer": args.offer, "allocation": args.allocation, "seed": args.seed,
              "badFingerprint": args.bad_fingerprint, "turnConfigured": False,
              "signaling": "authenticated SSH test coordinator",
              "sourceSha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in
                  ("native_peer.cpp", "run_lab.py", "live_native_lab.py", "live_udp_nat.py", "nat_gateway.py")}}
    try:
        result.update(lab.exchange())
    except Exception as error:
        result.update(success=False, error=str(error))
    finally:
        lab.close()
    result["endpoints"] = [event for event in lab.history if event["type"] == "lab-closed"]
    result["cleanupComplete"] = len(result["endpoints"]) == 2 and all(e["cleanupComplete"] for e in result["endpoints"])
    result["wireVerified"] = len(result["endpoints"]) == 2 and all(
        e.get("gateway", {}).get("wire", {}).get("dtlsApplication", 0) > 0
        and e["gateway"]["wire"].get("plaintextTestData", 0) == 0 for e in result["endpoints"])
    result["success"] = result.get("success", False) and result["wireVerified"] and result["cleanupComplete"]
    (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    emit({k: result.get(k) for k in ("success", "connected", "connectSeconds", "error", "cleanupComplete", "wireVerified")})


if __name__ == "__main__":
    main()
