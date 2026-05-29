"""Launch the phone-as-scanner Flask server.

Usage
-----
  py scripts\serve_scan.py --mode private --known-seed 7ef1eaa3...
  py scripts\serve_scan.py --mode verify  --spinor <128hex>
  py scripts\serve_scan.py --mode sas     --spinor <128hex>
  py scripts\serve_scan.py --mode enroll
  py scripts\serve_scan.py --mode genesis
  py scripts\serve_scan.py --port 8800

Once started, point any phone (on the same Wi-Fi) at the QR code shown
in the terminal or at http://<PC-LAN-IP>:8765/. From the phone browser,
go to /scan, tap "Capturer", and the result appears both on the phone
and on the PC dashboard.

Firewall note (Windows)
-----------------------
The first run will typically trigger a Windows Defender Firewall prompt
asking whether Python can listen on private networks. Allow PRIVATE
networks (your home Wi-Fi); deny PUBLIC unless you really mean it.
"""

from __future__ import annotations

import argparse
import socket
import sys

from eopx.server.app import (
    create_app, ServerConfig, detect_lan_ip, DEFAULT_PORT,
)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="serve_scan")
    p.add_argument("--mode",
                   choices=("private", "verify", "sas", "enroll", "genesis"),
                   default="private")
    p.add_argument("--spinor", help="64-byte spinor_hash in hex (verify/sas)")
    p.add_argument("--known-seed",
                   help="hex seed, for self-check in mode private")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--host", default="0.0.0.0",
                   help="bind address (default 0.0.0.0 = all interfaces)")
    args = p.parse_args(argv[1:])

    if args.mode in ("verify", "sas") and not args.spinor:
        raise SystemExit(f"--spinor is required for mode {args.mode}")

    cfg = ServerConfig(
        mode=args.mode,
        spinor_hex=args.spinor,
        known_seed_hex=args.known_seed,
    )
    app = create_app(cfg, port=args.port)

    lan = detect_lan_ip()
    print("=" * 64)
    print(" Esoptron phone-as-scanner server")
    print("=" * 64)
    print(f"   mode         : {cfg.mode}")
    print(f"   host         : {args.host}")
    print(f"   port         : {args.port}")
    print(f"   PC dashboard : http://{lan}:{args.port}/")
    print(f"   phone URL    : http://{lan}:{args.port}/scan")
    print()
    print(" In a Windows Defender prompt, allow PRIVATE network access.")
    print(" Stop the server with Ctrl+C.")
    print("=" * 64)
    print()
    # use_reloader=False so the ArUco detector is created once.
    app.run(host=args.host, port=args.port,
             debug=False, use_reloader=False, threaded=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
