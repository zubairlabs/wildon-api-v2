#!/usr/bin/env python3
"""
JiAi Watch Simulator — acts as a live L16/L17PRO GPS watch sending IW protocol
messages to the device gateway over TCP.

The simulator now supports IPv4 or IPv6 targets, keeps an asynchronous read
loop, and auto-acknowledges outbound BP command packets with matching AP
responses so command delivery can be exercised end-to-end.

Usage:
    python3 scripts/test-watch-simulator.py [HOST] [PORT] [IMEI] [options]

Examples:
    python3 scripts/test-watch-simulator.py 127.0.0.1 9000
    python3 scripts/test-watch-simulator.py ::1 9000 359349071043325 --family ipv6
    python3 scripts/test-watch-simulator.py 127.0.0.1 9000 --duplicate-acks

Options:
    --family auto|ipv4|ipv6   Address family selection, default auto
    --model L16|L17PRO        Printed device model, default L16
    --ack-delay SECONDS       Delay before sending AP command ACK, default 0.2
    --duplicate-acks          Send command ACKs twice
    --disconnect-after N      Close and reconnect after N acknowledged commands

Test IMEIs (from seed script):
    359349071043325  359349071819609  359349070133895
    359349070838634  359349077940268  359349075423515
    359349071615593  359349074078161  359349071849598
    359349073103416
"""

import argparse
import queue
import random
import signal
import socket
import sys
import threading
import time

COMMAND_CODES = {
    "BP12",
    "BP14",
    "BP16",
    "BP17",
    "BP18",
    "BP20",
    "BP28",
    "BP31",
    "BP33",
    "BP34",
    "BP40",
    "BP76",
    "BP77",
    "BP84",
    "BP85",
    "BP86",
    "BP87",
    "BPXL",
    "BPXY",
    "BPXT",
    "BPXZ",
    "BPJZ",
}

running = True


def parse_args():
    parser = argparse.ArgumentParser(description="JiAi watch simulator")
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("port", nargs="?", type=int, default=9000)
    parser.add_argument("imei", nargs="?", default="359349071043325")
    parser.add_argument("--family", choices=["auto", "ipv4", "ipv6"], default="auto")
    parser.add_argument("--model", choices=["L16", "L17PRO"], default="L16")
    parser.add_argument("--ack-delay", type=float, default=0.2)
    parser.add_argument("--duplicate-acks", action="store_true")
    parser.add_argument("--disconnect-after", type=int, default=0)
    return parser.parse_args()


def handle_signal(sig, frame):
    del sig, frame
    global running
    running = False
    print("\nShutting down...")


signal.signal(signal.SIGINT, handle_signal)


def random_coord(base, variance=0.01):
    return base + random.uniform(-variance, variance)


def resolve_family(family_name):
    if family_name == "ipv4":
        return socket.AF_INET
    if family_name == "ipv6":
        return socket.AF_INET6
    return socket.AF_UNSPEC


class WatchConnection:
    def __init__(self, host, port, imei, model, family_name, ack_delay, duplicate_acks):
        self.host = host
        self.port = port
        self.imei = imei
        self.model = model
        self.family_name = family_name
        self.ack_delay = ack_delay
        self.duplicate_acks = duplicate_acks
        self.sock = None
        self.reader = None
        self.read_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.write_lock = threading.Lock()
        self.command_ack_count = 0

    def connect(self):
        infos = socket.getaddrinfo(
            self.host,
            self.port,
            family=resolve_family(self.family_name),
            type=socket.SOCK_STREAM,
        )
        last_error = None
        for family, socktype, proto, _, sockaddr in infos:
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(5)
                sock.connect(sockaddr)
                sock.settimeout(1)
                self.sock = sock
                self.stop_event.clear()
                self.reader = threading.Thread(target=self._reader_loop, daemon=True)
                self.reader.start()
                return sockaddr
            except OSError as exc:
                last_error = exc
        raise OSError(last_error or "unable to connect")

    def close(self):
        self.stop_event.set()
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None

    def send(self, msg, label=""):
        prefix = f"[{label}] " if label else ""
        print(f"\n{prefix}>>> SEND: {msg}")
        with self.write_lock:
            self.sock.sendall(msg.encode("ascii"))

    def wait_for_non_command(self, label="", timeout=2.0):
        prefix = f"[{label}] " if label else ""
        deadline = time.time() + timeout
        while running and time.time() < deadline:
            try:
                message = self.read_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            print(f"{prefix}<<< RECV: {message}")
            return True
        print(f"{prefix}<<< RECV: (timeout)")
        return False

    def _reader_loop(self):
        buffer = ""
        while running and not self.stop_event.is_set():
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    self.read_queue.put("(empty/disconnected)")
                    return
                buffer += chunk.decode("ascii", errors="replace")
                while "#" in buffer:
                    raw, buffer = buffer.split("#", 1)
                    if not raw:
                        continue
                    message = f"{raw}#"
                    if self._handle_server_message(message):
                        continue
                    self.read_queue.put(message)
            except socket.timeout:
                continue
            except OSError as exc:
                self.read_queue.put(f"(socket error: {exc})")
                return

    def _handle_server_message(self, message):
        if not message.startswith("IWBP"):
            return False

        body = message[2:-1]
        command_code = body[:4]
        if command_code not in COMMAND_CODES:
            return False

        parts = body.split(",")
        journal_number = parts[2] if len(parts) > 2 else "0001"
        ack_code = command_code.replace("BP", "AP", 1)
        ack_message = f"IW{ack_code},{journal_number},OK#"

        print(f"\n[COMMAND] <<< RECV: {message}")
        time.sleep(self.ack_delay)
        with self.write_lock:
            self.sock.sendall(ack_message.encode("ascii"))
        self.command_ack_count += 1
        print(f"[COMMAND] >>> ACK:  {ack_message}")

        if self.duplicate_acks:
            time.sleep(min(self.ack_delay, 0.5))
            with self.write_lock:
                self.sock.sendall(ack_message.encode("ascii"))
            print(f"[COMMAND] >>> ACK:  {ack_message} (duplicate)")

        return True


def send_and_log(connection, msg, label="", timeout=2.0):
    connection.send(msg, label)
    return connection.wait_for_non_command(label=label, timeout=timeout)


def run_session(args):
    print("=" * 60)
    print(f"  JiAi {args.model} Watch Simulator")
    print(f"  IMEI: {args.imei}")
    print(f"  Server: {args.host}:{args.port}")
    print(f"  Family: {args.family}")
    print("=" * 60)

    connection = WatchConnection(
        args.host,
        args.port,
        args.imei,
        args.model,
        args.family,
        args.ack_delay,
        args.duplicate_acks,
    )

    sockaddr = connection.connect()
    print(f"\nConnected to {sockaddr}")

    print("\n--- LOGIN ---")
    if not send_and_log(connection, f"IWAP00{args.imei}#", "LOGIN"):
        connection.close()
        return

    time.sleep(1)

    print("\n--- INITIAL LOCATION ---")
    lat_base = 43.8561
    lng_base = -79.3370
    now = time.strftime("%H%M%S")
    date = time.strftime("%d%m%y")

    lat_nmea = f"{int(lat_base):02d}{(lat_base % 1) * 60:07.4f}"
    lng_nmea = f"{int(abs(lng_base)):03d}{(abs(lng_base) % 1) * 60:07.4f}"
    lng_dir = "W" if lng_base < 0 else "E"

    send_and_log(
        connection,
        f"IWAP01,{now},A,{lat_nmea},N,{lng_nmea},{lng_dir},002.5,{now},{date},"
        f"08000908000102,302,0,9520,3671,0#",
        "LOCATION",
    )

    time.sleep(1)

    print("\n--- HEARTBEAT ---")
    send_and_log(connection, "IWAP03,08000908000102,0,80#", "HEARTBEAT")

    time.sleep(1)

    print("\n--- HEALTH DATA ---")
    hr = random.randint(65, 85)
    spo2 = random.randint(95, 99)
    sbp = random.randint(110, 135)
    dbp = random.randint(65, 85)
    temp = round(random.uniform(36.2, 37.0), 1)

    send_and_log(connection, f"IWAP49,{hr}#", "HEART RATE")
    time.sleep(0.5)
    send_and_log(
        connection,
        f"IWAPHP,{hr},{sbp},{dbp},{spo2},95,{temp},,,,,,,#",
        "HEALTH",
    )
    time.sleep(0.5)
    send_and_log(connection, f"IWAP50,{temp},85#", "TEMPERATURE")

    print("\n--- CONTINUOUS MODE (Ctrl+C to stop) ---")
    print("Sending heartbeat every 30s, location every 60s, health every 120s...")

    cycle = 0
    steps = 0
    while running:
        cycle += 1
        time.sleep(10)
        if not running:
            break

        if args.disconnect_after and connection.command_ack_count >= args.disconnect_after:
            print("\n--- RECONNECT SCENARIO ---")
            print(f"Disconnecting after {connection.command_ack_count} acknowledged commands")
            connection.close()
            time.sleep(3)
            connection = WatchConnection(
                args.host,
                args.port,
                args.imei,
                args.model,
                args.family,
                args.ack_delay,
                args.duplicate_acks,
            )
            sockaddr = connection.connect()
            print(f"Reconnected to {sockaddr}")
            send_and_log(connection, f"IWAP00{args.imei}#", "LOGIN")
            connection.command_ack_count = 0

        if cycle % 3 == 0:
            steps += random.randint(20, 80)
            bat = max(10, 90 - cycle)
            send_and_log(
                connection,
                f"IWAP03,08000908000102,{steps},{bat}#",
                "HEARTBEAT",
            )

        if cycle % 6 == 0:
            lat = random_coord(lat_base, 0.002)
            lng = random_coord(lng_base, 0.002)
            now = time.strftime("%H%M%S")
            date = time.strftime("%d%m%y")
            lat_nmea = f"{int(lat):02d}{(lat % 1) * 60:07.4f}"
            lng_nmea = f"{int(abs(lng)):03d}{(abs(lng) % 1) * 60:07.4f}"
            speed = f"{random.uniform(0, 5):05.1f}"

            send_and_log(
                connection,
                f"IWAP01,{now},A,{lat_nmea},N,{lng_nmea},{lng_dir},{speed},{now},{date},"
                f"08000908000102,302,0,9520,3671,0#",
                "LOCATION",
            )

        if cycle % 12 == 0:
            hr = random.randint(65, 85)
            temp = round(random.uniform(36.2, 37.0), 1)
            send_and_log(connection, f"IWAP49,{hr}#", "HEART RATE")
            time.sleep(0.3)
            send_and_log(connection, f"IWAP50,{temp},{max(10, 90 - cycle)}#", "TEMPERATURE")

    connection.close()
    print("\nDisconnected.")


def main():
    args = parse_args()
    while running:
        try:
            run_session(args)
            break
        except OSError as exc:
            if not running:
                break
            print(f"\nConnection failed: {exc}")
            print("Retrying in 5 seconds...")
            time.sleep(5)
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()
