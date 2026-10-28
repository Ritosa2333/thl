"""Validate native NAT4 traversal with isolated networks, TUN and authenticated data channels."""
import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import sys
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent
CASES = {
    "open-open": ("open", "open"),
    "a4-open": ("nat4", "open"),
    "open-b4": ("open", "nat4"),
    "a4-b3": ("nat4", "nat3"),
    "a3-b4": ("nat3", "nat4"),
    "double4": ("nat4", "nat4"),
    "double4-address": ("nat4-address", "nat4-address"),
    "a-address-b4": ("nat4-address", "nat4"),
    "a4-b-address": ("nat4", "nat4-address"),
}


def run(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True).stdout


class Lab:
    def __init__(self, args, directory):
        self.args, self.directory = args, directory
        self.names = {k: "tl" + uuid.uuid4().hex[:8] + k for k in ["w", "a", "b", "ga", "gb"]}
        self.created, self.processes, self.logs = [], [], []
        self.events = queue.Queue()
        self.history = []
        self.addresses = {"a": "198.18.0.1", "b": "198.18.0.2"}

    def ip(self, name, *args):
        return run("ip", "-n", self.names[name], *args)

    def command(self, name, *args):
        return run("ip", "netns", "exec", self.names[name], *args)

    def spawn(self, name, role, argv):
        log = (self.directory / f"{role}.stderr").open("w")
        self.logs.append(log)
        process = subprocess.Popen(["timeout", "--kill-after=3", "150s", "ip", "netns", "exec", self.names[name], *argv],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                                   text=True, bufsize=1, start_new_session=True)
        self.processes.append((role, process))

        def reader():
            for line in process.stdout:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    value = {"type": "error", "error": "invalid output: " + line[:300]}
                self.events.put((role, value))
            self.events.put((role, {"type": "exit"}))

        threading.Thread(target=reader, daemon=True).start()
        return process

    def wait_ready(self, role):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            actual, value = self.events.get(timeout=max(0.01, deadline - time.monotonic()))
            if actual == role and value["type"] == "ready":
                return
            if value["type"] in ["exit", "error"]:
                raise RuntimeError(f"{actual}: {value}")
        raise TimeoutError(role)

    def setup(self, modes):
        for name in self.names.values():
            run("ip", "netns", "add", name)
            self.created.append(name)
            run("ip", "-n", name, "link", "set", "lo", "up")
        self.ip("w", "link", "add", "br0", "type", "bridge")
        self.ip("w", "link", "set", "br0", "up")
        for ip in ["198.18.0.254", "198.18.0.10", "198.18.0.11"]:
            self.ip("w", "addr", "add", ip + "/24", "dev", "br0")
        for number, (end, mode) in enumerate(zip(["a", "b"], modes), 1):
            gateway = "g" + end
            self.ip(gateway, "link", "add", "wan", "type", "veth", "peer", "name", "p" + end, "netns", self.names["w"])
            self.ip("w", "link", "set", "p" + end, "master", "br0")
            self.ip("w", "link", "set", "p" + end, "up")
            self.ip(gateway, "addr", "add", f"198.18.0.{number}/24", "dev", "wan")
            self.ip(gateway, "link", "set", "wan", "up")
            self.ip(gateway, "link", "add", "lan", "type", "veth", "peer", "name", "eth0", "netns", self.names[end])
            self.ip(gateway, "addr", "add", f"10.231.{number}.1/24", "dev", "lan")
            self.ip(gateway, "link", "set", "lan", "up")
            self.ip(end, "addr", "add", f"10.231.{number}.2/24", "dev", "eth0")
            self.ip(end, "link", "set", "eth0", "up")
            self.ip(end, "route", "add", "default", "via", f"10.231.{number}.1")
            self.command(gateway, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0")
            self.spawn(gateway, gateway, [sys.executable, str(HERE / "nat_gateway.py"), "gateway",
                       "--mode", mode, "--external", f"198.18.0.{number}", "--base", str(30000 + number * 10000),
                       "--allocation", self.args.allocation, "--seed", str(self.args.seed + number)])
            self.wait_ready(gateway)
            self.ip(gateway, "link", "set", "thl-tun", "up")
            self.ip(gateway, "rule", "add", "iif", "lan", "lookup", "100")
            self.ip(gateway, "route", "add", "default", "dev", "thl-tun", "table", "100")
        self.spawn("w", "observer", [sys.executable, str(HERE / "nat_gateway.py"), "observe"])
        self.wait_ready("observer")
        probes = []
        for end, mode in zip(["a", "b"], modes):
            measured = json.loads(self.command(end, sys.executable, str(HERE / "nat_gateway.py"), "probe"))
            expected_filter = {"same": True, "otherPort": mode == "open", "otherIp": mode == "open"}
            valid = measured["sameSocketSameMapping"] == (not mode.startswith("nat4")) and measured["acceptedSources"] == expected_filter
            if mode == "nat4":
                valid = valid and len({tuple(p) for p in measured["mappings"]}) == 3
            elif mode == "nat4-address":
                valid = valid and measured["mappings"][0] == measured["mappings"][1] != measured["mappings"][2]
            if not valid:
                raise RuntimeError(f"NAT fixture does not match {mode}: {measured}")
            probes.append(measured)
        return probes

    @staticmethod
    def send(process, value):
        process.stdin.write(json.dumps(value) + "\n")
        process.stdin.flush()

    def punch(self):
        """Coordinate observation, scanning, port rotation and native socket handoff."""
        begin = time.monotonic()
        scanner = self.args.scanner
        rotator = "b" if scanner == "a" else "a"
        addresses = {"a": "198.18.0.1", "b": "198.18.0.2"}
        processes = {}
        for role, port in [("a", 32000), ("b", 33000)]:
            processes[role] = self.spawn(role, "punch-" + role, [sys.executable, str(HERE / "punch_peer.py"),
                "--role", "scan" if role == scanner else "rotate", "--port", str(port)])
            self.wait_ready("punch-" + role)

        def wait_for(role, kind):
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                actual, value = self.events.get(timeout=max(0.01, deadline - time.monotonic()))
                self.history.append({"role": actual, **value})
                if value["type"] in ["error", "exit"]:
                    raise RuntimeError(f"{actual}: {value}")
                if actual == "punch-" + role and value["type"] == kind:
                    return value
            raise TimeoutError(kind)

        observations = {}
        for role in [rotator, scanner]:
            self.send(processes[role], {"type": "observe"})
            observations[role] = wait_for(role, "observed")
        first, second = [p[1] for p in observations[scanner]["mappings"]]
        predicted = second + 1 if second == first + 1 else second - 1 if second == first - 1 else min(first, second) + abs(first - second) // 2
        self.send(processes[scanner], {"type": "scan", "ip": addresses[rotator],
                                      "center": observations[rotator]["mappings"][0][1]})
        scan = wait_for(scanner, "scanned")
        self.send(processes[rotator], {"type": "rotate", "ip": addresses[scanner], "port": predicted})
        # Either hit or rotation completion may arrive first.
        outcomes = {}
        deadline = time.monotonic() + 8
        while len(outcomes) < 2 and time.monotonic() < deadline:
            role, value = self.events.get(timeout=max(0.01, deadline - time.monotonic()))
            self.history.append({"role": role, **value})
            if value["type"] in ["error", "exit"]:
                raise RuntimeError(f"{role}: {value}")
            if value["type"] in ["hit", "rotated"]:
                outcomes[value["type"]] = value
        if len(outcomes) != 2:
            raise TimeoutError("punch feedback")
        for process in processes.values():
            self.send(process, {"type": "stop"})
            process.wait(timeout=3)
        # Exit events from the completed punch subprocesses are expected.
        details = {"scanner": scanner, "observations": observations, "scan": scan,
                   "prediction": predicted, "seconds": round(time.monotonic() - begin, 3), **outcomes}
        hit = outcomes["hit"]["hit"]
        endpoints = None if not hit else {
            scanner: {"localPort": hit["localPort"], "public": [addresses[scanner], predicted]},
            rotator: {"localPort": hit["remoteLocalPort"], "public": hit["remote"]}}
        return endpoints, details

    def exchange(self, punched=None):
        processes = {}
        for role in ["a", "b"]:
            argv = [self.args.native, "offer" if self.args.offer == role else "answer",
                    "1" if role == "a" else "0", str(self.args.packets), str(self.args.idle_seconds),
                    str(punched[role]["localPort"] if punched else 0)]
            processes[role] = self.spawn(role, role, argv)
        opened = {role: set() for role in processes}
        results, versions, states = {}, {}, []
        pending = {role: deque() for role in processes}
        remote_description = {role: False for role in processes}
        observed = {}
        coordinated = False
        begin = time.monotonic()
        deadline, started, report_sent = begin + 22, None, False
        predictions = {role: 0 for role in processes}
        data_seconds = self.args.packets * 0.016 + self.args.idle_seconds + 2

        def release_candidates():
            nonlocal coordinated
            if coordinated or not all(remote_description.values()):
                return
            if punched:
                for source, endpoint in punched.items():
                    target = "b" if source == "a" else "a"
                    ip, port = endpoint["public"]
                    self.send(processes[target], {"type": "candidate", "candidate": {
                        "candidate": f"candidate:punched 1 UDP 1678769919 {ip} {port} typ srflx raddr 0.0.0.0 rport 0", "sdpMid": "0"}})
            elif self.args.strategy == "next-port" and len(observed) == 2:
                for source, observed_value in observed.items():
                    target = "b" if source == "a" else "a"
                    c = observed_value["candidate"]
                    prediction = c["candidate"].split()
                    port = int(prediction[5]) + self.args.next_offset
                    if not 1024 <= port <= 65535:
                        raise ValueError("predicted port outside allowed range")
                    prediction[0] += "next"
                    prediction[5] = str(port)
                    self.send(processes[target], {"type": "candidate", "candidate": {
                        **c, "candidate": " ".join(prediction)}})
                    predictions[source] = 1
            else:
                return
            coordinated = True
            self.history.append({"type": "coordinated", "at": round(time.monotonic() - begin, 3),
                                 "strategy": self.args.strategy})

        while time.monotonic() < deadline:
            now = time.monotonic()
            if started and now - started >= data_seconds and not report_sent:
                for process in processes.values():
                    self.send(process, {"type": "report"})
                report_sent = True
            try:
                role, value = self.events.get(timeout=0.1)
            except queue.Empty:
                continue
            kind = value["type"]
            self.history.append({"role": role, "at": round(now - begin, 3), **({"type": kind} if kind == "description" else value)})
            if role.startswith("punch-") and kind == "exit":
                continue
            if kind in ["error", "exit"]:
                raise RuntimeError(f"{role}: {value}")
            if role not in processes:
                continue
            other = "b" if role == "a" else "a"
            if kind == "description":
                # Exchange explicitly selected public candidates after SDP negotiation.
                sdp = value["description"]["sdp"]
                value["description"]["sdp"] = "\r\n".join(line for line in sdp.splitlines()
                    if not line.startswith("a=candidate:") and line != "a=end-of-candidates") + "\r\n"
                if self.args.bad_fingerprint and role == "a":
                    altered, count = re.subn(r"(a=fingerprint:[^\s]+ )([0-9a-fA-F])",
                        lambda m: m[1] + ("1" if m[2] == "0" else "0"), value["description"]["sdp"])
                    if count != 1:
                        raise RuntimeError("expected one fingerprint for rejection trial")
                    value["description"]["sdp"] = altered
                self.send(processes[other], value)
                remote_description[other] = True
                while pending[other]:
                    self.send(processes[other], pending[other].popleft())
                release_candidates()
            elif kind == "candidate":
                candidate = value["candidate"]
                words = candidate["candidate"].split()
                if len(words) < 8 or words[7] != "srflx" or words[4] != self.addresses[role]:
                    continue
                if self.args.strategy == "next-port":
                    observed.setdefault(role, value)
                    release_candidates()
                    continue
                if remote_description[other]:
                    self.send(processes[other], value)
                else:
                    pending[other].append(value)
            elif kind == "open":
                if value["lane"] == "input":
                    valid = value.get("unordered") and value.get("unreliable")
                    if not valid or value.get("maxRetransmits") != 0:
                        raise RuntimeError("input channel reliability mismatch")
                elif value.get("unordered") or value.get("unreliable"):
                    raise RuntimeError("control channel reliability mismatch")
                opened[role].add(value["lane"])
                if not started and all(len(lanes) == 2 for lanes in opened.values()):
                    started = time.monotonic()
                    deadline = started + data_seconds + 5
                    for process in processes.values():
                        self.send(process, {"type": "start"})
            elif kind == "result":
                results[role] = value
                if len(results) == 2:
                    break
            elif kind == "ready" and "version" in value:
                versions[role] = value["version"]
            elif kind == "state":
                states.append({"role": role, "state": value["state"]})
        success = len(results) == 2 and all(
            r["inputReceived"] == self.args.packets and r["inputEchoed"] == self.args.packets
            and r["controlReceived"] == self.args.packets // 10 and r["controlEchoed"] == self.args.packets // 10
            and r["errors"] == 0 and r["orderErrors"] == 0 and r["selected"]
            for r in results.values())
        return {"success": bool(success), "connected": started is not None,
                "connectSeconds": round(started - begin, 3) if started else None,
                "predictedCandidates": predictions,
                "strategy": self.args.strategy, "nextOffset": self.args.next_offset if coordinated and not punched else None,
                "packets": self.args.packets, "idleSeconds": self.args.idle_seconds,
                "results": results, "versions": versions, "states": states}

    def close(self):
        # Stop endpoint process groups first, then their gateways and the observer.
        ordered = sorted(self.processes, key=lambda item: item[0] not in ["a", "b", "punch-a", "punch-b"])
        for role, process in ordered:
            if process.poll() is None:
                try:
                    if role in ["a", "b", "punch-a", "punch-b"]:
                        self.send(process, {"type": "stop"})
                    else:
                        os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=3)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
        for name in reversed(self.created):
            run("ip", "netns", "delete", name)
        for log in self.logs:
            log.close()
        while not self.events.empty():
            role, value = self.events.get_nowait()
            if value["type"] == "gateway-result":
                self.history.append({"role": role, **value})
        (self.directory / "events.json").write_text(json.dumps(self.history, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    parser.add_argument("--offer", choices=["a", "b"], default="b")
    parser.add_argument("--strategy", choices=["ice", "next-port", "nat22"], default="ice")
    parser.add_argument("--scanner", choices=["a", "b"], default="a")
    parser.add_argument("--bad-fingerprint", action="store_true", help="Verify peer fingerprint validation")
    parser.add_argument("--next-offset", type=int, choices=range(-16, 17), default=1)
    parser.add_argument("--packets", type=int, default=300)
    parser.add_argument("--idle-seconds", type=int, choices=range(0, 31), default=0)
    parser.add_argument("--allocation", choices=["sequential", "random"], default="sequential")
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    if not 300 <= args.packets <= 3600 or args.packets % 20:
        parser.error("packet count must be a multiple of 20 in [300, 3600]")
    if os.geteuid() != 0:
        parser.error("root is required for network namespaces and TUN")
    def interrupted(number, _frame):
        raise SystemExit(128 + number)
    for number in [signal.SIGTERM, signal.SIGHUP]:
        signal.signal(number, interrupted)
    args.output.mkdir(parents=True, exist_ok=False)
    source_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in HERE.iterdir() if p.suffix in [".py", ".cpp"] or p.name == "CMakeLists.txt"}
    native_hash = hashlib.sha256(Path(args.native).read_bytes()).hexdigest()
    results = []
    for case in args.cases:
        directory = args.output / case
        directory.mkdir()
        lab = Lab(args, directory)
        result = {"case": case, "peers": "native-native", "offer": args.offer, "allocation": args.allocation, "seed": args.seed}
        result["badFingerprint"] = args.bad_fingerprint
        result["sourceSha256"] = source_hashes
        result["nativeBinarySha256"] = native_hash
        try:
            result["probes"] = lab.setup(CASES[case])
            if args.strategy == "nat22":
                endpoints, result["punch"] = lab.punch()
                if endpoints:
                    result.update(lab.exchange(endpoints))
                else:
                    result.update({"success": False, "connected": False, "strategy": args.strategy})
            else:
                result.update(lab.exchange())
        except Exception as error:
            result.update({"success": False, "error": str(error)})
        finally:
            lab.close()
        result["gateways"] = [e for e in lab.history if e["type"] == "gateway-result"]
        if result.get("success"):
            result["wireVerified"] = len(result["gateways"]) == 2 and all(
                g["wire"]["dtlsApplication"] > 0 and g["wire"]["plaintextTestData"] == 0
                for g in result["gateways"])
            result["success"] = result["wireVerified"]
        if result.get("connected"):
            result["totalConnectSeconds"] = round(result["connectSeconds"] + result.get("punch", {}).get("seconds", 0), 3)
        results.append(result)
        (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print(json.dumps(result), flush=True)
        if "error" in result:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
