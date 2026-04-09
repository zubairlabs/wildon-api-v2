#!/usr/bin/env python3
"""
Wildon Fleet Simulator — runs a fleet of simulated L16/L17PRO GPS watches
across the Greater Toronto Area with realistic movement, vitals, and command
acknowledgements.

Usage:
    python3 scripts/fleet-simulator.py [HOST] [PORT] [options]

Examples:
    python3 scripts/fleet-simulator.py 127.0.0.1 9000 --count 3
    python3 scripts/fleet-simulator.py ::1 9000 --family ipv6 --duplicate-acks
    python3 scripts/fleet-simulator.py 127.0.0.1 9000 --stale-after 120
"""

import argparse
import math
import queue
import random
import signal
import socket
import threading
import time

DEVICES = [
    {"imei": "359349071043325", "lat": 43.6532, "lng": -79.3832, "name": "CN Tower, Downtown Toronto", "model": "L16"},
    {"imei": "359349071819609", "lat": 43.7735, "lng": -79.3390, "name": "North York Centre", "model": "L17PRO"},
    {"imei": "359349070133895", "lat": 43.5890, "lng": -79.6441, "name": "Square One, Mississauga", "model": "L16"},
    {"imei": "359349070838634", "lat": 43.8561, "lng": -79.3370, "name": "Markham Civic Centre", "model": "L17PRO"},
    {"imei": "359349077940268", "lat": 43.6830, "lng": -79.7590, "name": "Brampton City Hall", "model": "L16"},
    {"imei": "359349075423515", "lat": 43.8971, "lng": -79.4428, "name": "Vaughan Mills Mall", "model": "L17PRO"},
    {"imei": "359349071615593", "lat": 43.7960, "lng": -79.2710, "name": "Scarborough Town Centre", "model": "L16"},
    {"imei": "359349074078161", "lat": 43.7315, "lng": -79.7624, "name": "Brampton Shoppers World", "model": "L17PRO"},
    {"imei": "359349071849598", "lat": 43.8450, "lng": -79.0230, "name": "Pickering Town Centre", "model": "L16"},
    {"imei": "359349073103416", "lat": 43.6680, "lng": -79.3950, "name": "Little Italy, Toronto", "model": "L17PRO"},
]

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

EARTH_RADIUS_M = 6_371_000
running = True


def parse_args():
    parser = argparse.ArgumentParser(description="Wildon fleet simulator")
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("port", nargs="?", type=int, default=9000)
    parser.add_argument("--count", type=int, default=len(DEVICES))
    parser.add_argument("--family", choices=["auto", "ipv4", "ipv6"], default="auto")
    parser.add_argument("--ack-delay", type=float, default=0.2)
    parser.add_argument("--duplicate-acks", action="store_true")
    parser.add_argument("--stale-after", type=int, default=0)
    parser.add_argument("--reconnect-after", type=int, default=0)
    return parser.parse_args()


def handle_signal(sig, frame):
    del sig, frame
    global running
    running = False
    print("\n[FLEET] Shutting down all watches...")


signal.signal(signal.SIGINT, handle_signal)


def resolve_family(family_name):
    if family_name == "ipv4":
        return socket.AF_INET
    if family_name == "ipv6":
        return socket.AF_INET6
    return socket.AF_UNSPEC


def offset_position(lat, lng, bearing_deg, distance_m):
    lat_r = math.radians(lat)
    lng_r = math.radians(lng)
    bearing = math.radians(bearing_deg)
    delta = distance_m / EARTH_RADIUS_M

    new_lat = math.asin(
        math.sin(lat_r) * math.cos(delta)
        + math.cos(lat_r) * math.sin(delta) * math.cos(bearing)
    )
    new_lng = lng_r + math.atan2(
        math.sin(bearing) * math.sin(delta) * math.cos(lat_r),
        math.cos(delta) - math.sin(lat_r) * math.sin(new_lat),
    )
    return math.degrees(new_lat), math.degrees(new_lng)


def to_nmea_lat(lat):
    degrees = int(abs(lat))
    minutes = (abs(lat) - degrees) * 60
    return f"{degrees:02d}{minutes:07.4f}", "N" if lat >= 0 else "S"


def to_nmea_lng(lng):
    degrees = int(abs(lng))
    minutes = (abs(lng) - degrees) * 60
    return f"{degrees:03d}{minutes:07.4f}", "E" if lng >= 0 else "W"


class WatchSocket:
    def __init__(self, host, port, family_name, tag, ack_delay, duplicate_acks):
        self.host = host
        self.port = port
        self.family_name = family_name
        self.tag = tag
        self.ack_delay = ack_delay
        self.duplicate_acks = duplicate_acks
        self.sock = None
        self.reader = None
        self.stop_event = threading.Event()
        self.queue = queue.Queue()
        self.write_lock = threading.Lock()
        self.command_acks = 0

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
                sock.settimeout(8)
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

    def send(self, message, label="", timeout=2.0):
        with self.write_lock:
            self.sock.sendall(message.encode("ascii"))
        deadline = time.time() + timeout
        while running and time.time() < deadline:
            try:
                response = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            print(f"  {self.tag} {label} -> {response}")
            return True
        print(f"  {self.tag} {label} -> (timeout)")
        return True

    def _reader_loop(self):
        buffer = ""
        while running and not self.stop_event.is_set():
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    self.queue.put("(empty/disconnected)")
                    return
                buffer += chunk.decode("ascii", errors="replace")
                while "#" in buffer:
                    raw, buffer = buffer.split("#", 1)
                    if not raw:
                        continue
                    message = f"{raw}#"
                    if self._handle_server_message(message):
                        continue
                    self.queue.put(message)
            except socket.timeout:
                continue
            except OSError as exc:
                self.queue.put(f"(socket error: {exc})")
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

        print(f"  {self.tag} COMMAND <- {message}")
        time.sleep(self.ack_delay)
        with self.write_lock:
            self.sock.sendall(ack_message.encode("ascii"))
        self.command_acks += 1
        print(f"  {self.tag} COMMAND -> {ack_message}")

        if self.duplicate_acks:
            time.sleep(min(self.ack_delay, 0.5))
            with self.write_lock:
                self.sock.sendall(ack_message.encode("ascii"))
            print(f"  {self.tag} COMMAND -> {ack_message} (duplicate)")

        return True


def run_watch(device, index, args):
    global running

    imei = device["imei"]
    home_lat = device["lat"]
    home_lng = device["lng"]
    name = device["name"]
    model = device["model"]
    tag = f"[W{index + 1:02d} {imei[-6:]} {model}]"

    hr_base = random.randint(66, 80)
    spo2_base = random.randint(96, 99)
    sbp_base = random.randint(115, 130)
    dbp_base = random.randint(68, 82)
    temp_base = round(random.uniform(36.3, 36.8), 1)
    battery = random.randint(82, 98)

    cur_lat = home_lat
    cur_lng = home_lng
    steps = 0
    cycle = 0
    last_sent_at = time.monotonic()
    next_move_cycle = random.randint(60, 180)

    while running:
        print(f"{tag} Connecting to {args.host}:{args.port} — {name}")
        watch = WatchSocket(
            args.host,
            args.port,
            args.family,
            tag,
            args.ack_delay,
            args.duplicate_acks,
        )

        try:
            sockaddr = watch.connect()
            print(f"{tag} Connected via {sockaddr}")
        except OSError as exc:
            print(f"{tag} Connection failed: {exc} — retrying in 10s")
            time.sleep(10)
            continue

        print(f"  {tag} LOGIN handshake: IWAP00{imei}#")
        if not watch.send(f"IWAP00{imei}#", "LOGIN"):
            watch.close()
            time.sleep(5)
            continue

        time.sleep(0.5)

        now_str = time.strftime("%H%M%S")
        date_str = time.strftime("%d%m%y")
        lat_nmea, lat_dir = to_nmea_lat(cur_lat)
        lng_nmea, lng_dir = to_nmea_lng(cur_lng)
        watch.send(
            f"IWAP01,{now_str},A,{lat_nmea},{lat_dir},{lng_nmea},{lng_dir},000.0,{now_str},{date_str},"
            f"08000908000102,302,0,9520,3671,0#",
            "LOCATION",
        )
        time.sleep(0.3)
        watch.send(f"IWAP03,08000908000102,{steps},{battery}#", "HEARTBEAT")
        time.sleep(0.3)
        watch.send(f"IWAP49,{hr_base}#", "HR")
        watch.send(
            f"IWAPHP,{hr_base},{sbp_base},{dbp_base},{spo2_base},95,{temp_base},,,,,,,#",
            "HEALTH",
        )

        print(f"{tag} Initialized — entering continuous mode")

        try:
            while running:
                time.sleep(10)
                if not running:
                    break
                cycle += 1

                if args.reconnect_after and watch.command_acks >= args.reconnect_after:
                    print(f"{tag} Reconnect scenario triggered after {watch.command_acks} command ACKs")
                    break

                if args.stale_after and time.monotonic() - last_sent_at >= args.stale_after:
                    print(f"{tag} Simulating stale session for {args.stale_after}s")
                    time.sleep(args.stale_after)
                    last_sent_at = time.monotonic()

                if cycle % 3 == 0:
                    steps += random.randint(15, 60)
                    battery = max(5, battery - random.choice([0, 0, 0, 1]))
                    if not watch.send(
                        f"IWAP03,08000908000102,{steps},{battery}#",
                        "HB",
                    ):
                        break
                    last_sent_at = time.monotonic()

                if cycle % 12 == 0:
                    hr = hr_base + random.randint(-5, 5)
                    spo2 = min(99, max(94, spo2_base + random.randint(-1, 1)))
                    temp = round(temp_base + random.uniform(-0.3, 0.3), 1)
                    watch.send(f"IWAP49,{hr}#", "HR")
                    time.sleep(0.2)
                    watch.send(f"IWAP50,{temp},{battery}#", "TEMP")
                    time.sleep(0.2)
                    watch.send(
                        f"IWAPHP,{hr},{sbp_base},{dbp_base},{spo2},95,{temp},,,,,,,#",
                        "HEALTH",
                    )
                    last_sent_at = time.monotonic()

                if cycle >= next_move_cycle:
                    bearing = random.uniform(0, 360)
                    distance = random.uniform(10, 100)
                    cur_lat, cur_lng = offset_position(home_lat, home_lng, bearing, distance)

                    now_str = time.strftime("%H%M%S")
                    date_str = time.strftime("%d%m%y")
                    lat_nmea, lat_dir = to_nmea_lat(cur_lat)
                    lng_nmea, lng_dir = to_nmea_lng(cur_lng)
                    speed = f"{random.uniform(0.5, 3.0):05.1f}"

                    if not watch.send(
                        f"IWAP01,{now_str},A,{lat_nmea},{lat_dir},{lng_nmea},{lng_dir},{speed},{now_str},{date_str},"
                        f"08000908000102,302,0,9520,3671,0#",
                        f"MOVE {distance:.0f}m @{bearing:.0f}deg",
                    ):
                        break

                    last_sent_at = time.monotonic()
                    next_move_cycle = cycle + random.randint(60, 180)

        except Exception as exc:
            print(f"{tag} Error in loop: {exc}")

        watch.close()
        if running:
            print(f"{tag} Disconnected — reconnecting in 5s")
            time.sleep(5)

    print(f"{tag} Stopped")


def main():
    args = parse_args()
    devices_to_run = DEVICES[: args.count]

    print("=" * 64)
    print("  Wildon Fleet Simulator")
    print(f"  Server: {args.host}:{args.port}")
    print(f"  Watches: {len(devices_to_run)}")
    print(f"  Family: {args.family}")
    print("=" * 64)
    print()
    for index, device in enumerate(devices_to_run):
        print(f"  W{index + 1:02d}: {device['imei']} — {device['name']} ({device['model']})")
    print()
    print("  Movement: 10-100m drift every 10-30 minutes")
    print("  Heartbeat: every 30s | Health: every 2min")
    print("  Press Ctrl+C to stop all watches")
    print("=" * 64)
    print()

    threads = []
    for index, device in enumerate(devices_to_run):
        thread = threading.Thread(
            target=run_watch,
            args=(device, index, args),
            name=f"watch-{device['imei'][-6:]}",
            daemon=True,
        )
        threads.append(thread)
        thread.start()
        time.sleep(0.5)

    try:
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    print("\n[FLEET] Waiting for watches to disconnect...")
    for thread in threads:
        thread.join(timeout=5)

    print("[FLEET] All watches stopped.")


if __name__ == "__main__":
    main()
