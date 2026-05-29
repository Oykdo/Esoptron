"""Launch the Esoptron PWA REST API on localhost.

Usage
-----
    py scripts/serve_pwa_api.py --port 8765
    py scripts/serve_pwa_api.py --port 8765 --cors http://localhost:5173

The CORS flag is required when the PWA dev server (Vite on :5173 by
default) runs on a different origin than the API.

Endpoints
---------
* GET  /api/v1/health
* GET  /api/v1/info
* POST /api/v1/scan
"""

from __future__ import annotations

import argparse
import logging
import sys

from eopx.server.pwa_api import create_app


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--cors", action="append", default=[],
        help="allow this origin (repeatable). Typical: http://localhost:5173",
    )
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    )

    try:
        app = create_app(allow_origins=args.cors or None)
    except ValueError as exc:
        print(f"error: invalid --cors origin: {exc}", file=sys.stderr)
        return 2
    print(f"Esoptron PWA API listening on http://{args.host}:{args.port}")
    print("Endpoints:")
    print(f"  GET  http://{args.host}:{args.port}/api/v1/health")
    print(f"  GET  http://{args.host}:{args.port}/api/v1/info")
    print(f"  POST http://{args.host}:{args.port}/api/v1/scan")
    if args.cors:
        print(f"CORS origins: {', '.join(args.cors)}")
    app.run(host=args.host, port=args.port, debug=args.debug,
             use_reloader=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
