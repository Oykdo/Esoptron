r"""Real-time webcam scan of a printed (or screen-displayed) Metatron sheet.

No file transfer, no manual clicking. The four corner ArUco markers
(DICT_4X4_50, IDs 0..3) are detected each frame; once all four are
visible the page is rectified to its canonical 2480x3508 A4 frame, the
cube area is cropped, the 91 F_13 symbols are extracted, and the chosen
vault protocol is executed.

Stability gate: a decode result is only accepted after K (=3 by default)
consecutive frames produce the SAME result, to avoid latching on a
transient mis-classification.

Usage
-----
  py scripts\live_scan.py --mode private --known-seed <hex>
  py scripts\live_scan.py --mode verify  --spinor <hex>
  py scripts\live_scan.py --mode sas     --spinor <hex>
  py scripts\live_scan.py --mode enroll
  py scripts\live_scan.py --camera 1     # pick a different webcam

Hotkeys (focus the camera window):
  q / Esc : quit
  s       : save the current rectified A4 frame to out/live_rectified.png
  r       : reset the stability gate
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

import cv2
import numpy as np
from PIL import Image

from eopx.metatron import (
    extract_canonical, erasures_from_confidences,
)
from eopx.vault import (
    unlock_from_private_symbols, verify_card,
    new_challenge, respond, verify_response,
    enroll_from_card, card_fingerprint,
)

# Match constants from scripts/print_sheet.py
sys.path.insert(0, str(Path(__file__).parent))
from print_sheet import (  # type: ignore  # noqa: E402
    PAGE_W, PAGE_H, ARUCO_DICT_NAME, ARUCO_IDS,
    aruco_outer_corners, cube_rect_in_page,
)


STABILITY_FRAMES = 3
CUBE_DST_SIZE = 1024  # side of the canonical cube image fed to extract_canonical


def open_camera(index: int) -> cv2.VideoCapture:
    """Open a webcam with reasonable defaults on Windows (CAP_DSHOW)."""
    cap = cv2.VideoCapture(index, cv2.CAP_DSHOW)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH,  1280)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
    if not cap.isOpened():
        cap = cv2.VideoCapture(index)
    if not cap.isOpened():
        raise SystemExit(f"could not open camera index {index}")
    return cap


def make_aruco_detector():
    aruco = cv2.aruco
    dictionary = aruco.getPredefinedDictionary(getattr(aruco, ARUCO_DICT_NAME))
    params = aruco.DetectorParameters()
    params.cornerRefinementMethod = aruco.CORNER_REFINE_SUBPIX
    return aruco.ArucoDetector(dictionary, params)


def detect_aruco_corners(detector, frame_bgr) -> Optional[dict]:
    """Return {id: (x, y)} for the 4 OUTER corners of IDs 0..3, or None."""
    corners, ids, _rej = detector.detectMarkers(frame_bgr)
    if ids is None:
        return None
    ids = ids.flatten().tolist()
    needed = {0, 1, 2, 3}
    found = {}
    for marker_corners, mid in zip(corners, ids):
        if mid not in needed:
            continue
        # marker_corners shape: (1, 4, 2), order = TL, TR, BR, BL (CW from TL).
        c = marker_corners.reshape(4, 2)
        # We want the OUTER corner of each ArUco (the corner facing the page
        # edge), which corresponds to a specific index in `c` per marker id:
        #   ID 0 (page TL) -> marker TL -> index 0
        #   ID 1 (page TR) -> marker TR -> index 1
        #   ID 2 (page BR) -> marker BR -> index 2
        #   ID 3 (page BL) -> marker BL -> index 3
        found[mid] = tuple(c[mid])
    if found.keys() != needed:
        return None
    return found


def homography_to_a4(found_corners: dict) -> np.ndarray:
    """4-point homography from photo coords to canonical A4 (2480x3508) px."""
    dst_outer = aruco_outer_corners()
    src = np.array([found_corners[i] for i in range(4)], dtype=np.float32)
    dst = np.array([dst_outer[i] for i in range(4)], dtype=np.float32)
    H, _mask = cv2.findHomography(src, dst, method=0)  # 4 points -> exact
    return H


def rectify_a4(frame_bgr: np.ndarray, H: np.ndarray) -> np.ndarray:
    return cv2.warpPerspective(frame_bgr, H, (PAGE_W, PAGE_H))


def crop_cube(a4_bgr: np.ndarray, size_out: int = CUBE_DST_SIZE) -> Image.Image:
    x, y, side = cube_rect_in_page()
    sub = a4_bgr[y:y + side, x:x + side]
    if sub.size == 0:
        return Image.new("RGB", (size_out, size_out), (0, 0, 0))
    sub_rgb = cv2.cvtColor(sub, cv2.COLOR_BGR2RGB)
    img = Image.fromarray(sub_rgb)
    if img.size != (size_out, size_out):
        img = img.resize((size_out, size_out), Image.Resampling.BICUBIC)
    return img


def run_protocol(symbols, dists, args):
    """Execute the selected vault protocol and return a dict for display."""
    erasures = erasures_from_confidences(dists)
    out = {"erasures": len(erasures)}

    if args.mode == "private":
        try:
            seed, master = unlock_from_private_symbols(symbols, erasures=erasures)
        except Exception as e:
            out["status"] = "DECODE_FAIL"
            out["detail"] = str(e)
            return out
        out["status"] = "OK"
        out["seed"] = seed.hex()
        out["master_key"] = master.hex()
        if args.known_seed:
            out["seed_match"] = (seed.hex().lower() == args.known_seed.lower())
        return out

    if args.mode == "verify":
        ok = verify_card(symbols, bytes.fromhex(args.spinor))
        out["status"] = "OK" if ok else "MISMATCH"
        return out

    if args.mode == "sas":
        spinor = bytes.fromhex(args.spinor)
        vault_id = hashlib.sha3_256(spinor).digest()
        ch = new_challenge(vault_id)
        try:
            resp = respond(symbols, spinor, ch)
            sk = verify_response(resp, spinor, symbols)
        except ValueError as e:
            out["status"] = "REJECTED"
            out["detail"] = str(e)
            return out
        out["status"] = "OK" if sk else "VERIFY_FAIL"
        if sk:
            out["session_key"] = sk.hex()
        return out

    if args.mode == "enroll":
        rec = enroll_from_card(symbols)
        out["status"] = "ENROLLED"
        out["card_fp"] = rec.card_fp.hex()
        out["public_tag"] = rec.public_tag.hex()
        return out

    out["status"] = "UNKNOWN_MODE"
    return out


def overlay_status(frame: np.ndarray, found, gate_count: int,
                   last_result: Optional[dict]) -> np.ndarray:
    """Draw HUD onto the live BGR frame."""
    h, w = frame.shape[:2]
    bar_h = 70
    overlay = frame.copy()
    cv2.rectangle(overlay, (0, 0), (w, bar_h), (20, 20, 30), -1)
    cv2.addWeighted(overlay, 0.75, frame, 0.25, 0, frame)

    if found is None:
        cv2.putText(frame, "searching 4 ArUco markers...",
                    (12, 28), cv2.FONT_HERSHEY_SIMPLEX, 0.7,
                    (50, 200, 255), 2)
    else:
        for mid, (x, y) in found.items():
            cv2.circle(frame, (int(x), int(y)), 8, (0, 255, 0), 2)
            cv2.putText(frame, str(mid), (int(x) + 10, int(y) - 10),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
        cv2.putText(frame, f"locked  stability={gate_count}/{STABILITY_FRAMES}",
                    (12, 28), cv2.FONT_HERSHEY_SIMPLEX, 0.7,
                    (50, 255, 100), 2)

    if last_result is not None:
        y = bar_h + 25
        status = last_result.get("status", "?")
        color = (50, 255, 100) if status == "OK" or status == "ENROLLED" else (50, 80, 255)
        cv2.putText(frame, f"status: {status}", (12, y),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, color, 2)
        y += 28
        if "seed" in last_result:
            txt = "seed: " + last_result["seed"][:32] + "..."
            cv2.putText(frame, txt, (12, y),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.55, (240, 240, 240), 1)
            y += 22
        if "seed_match" in last_result:
            tag = "self-check OK" if last_result["seed_match"] else "self-check DIFFERS"
            c = (50, 255, 100) if last_result["seed_match"] else (50, 80, 255)
            cv2.putText(frame, tag, (12, y),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, c, 2)
            y += 22
        if "session_key" in last_result:
            cv2.putText(frame, "session: " + last_result["session_key"][:32] + "...",
                        (12, y), cv2.FONT_HERSHEY_SIMPLEX, 0.55,
                        (240, 240, 240), 1)
            y += 22
        if "card_fp" in last_result:
            cv2.putText(frame, "card_fp: " + last_result["card_fp"][:32] + "...",
                        (12, y), cv2.FONT_HERSHEY_SIMPLEX, 0.55,
                        (240, 240, 240), 1)
            y += 22
        if "erasures" in last_result:
            cv2.putText(frame, f"erasures={last_result['erasures']}/91",
                        (12, y), cv2.FONT_HERSHEY_SIMPLEX, 0.55,
                        (180, 180, 220), 1)
    return frame


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="live_scan")
    p.add_argument("--mode", choices=("private", "verify", "sas", "enroll"),
                   default="private")
    p.add_argument("--spinor", help="64-byte spinor_hash hex (verify/sas)")
    p.add_argument("--known-seed", help="hex; self-check against this seed")
    p.add_argument("--camera", type=int, default=0,
                   help="webcam index (try 0, 1, 2... if you have multiple)")
    args = p.parse_args(argv[1:])

    if args.mode in ("verify", "sas") and not args.spinor:
        raise SystemExit(f"--spinor required for mode {args.mode}")

    cap = open_camera(args.camera)
    detector = make_aruco_detector()
    win = "Esoptron live scan -- press q to quit, s to save, r to reset"
    cv2.namedWindow(win, cv2.WINDOW_NORMAL)

    last_result: Optional[dict] = None
    stable_count = 0
    stable_sig: Optional[bytes] = None

    print("live scan started, mode =", args.mode)
    print("point the camera at the printed (or screen-displayed) Metatron sheet.")

    try:
        while True:
            ok, frame = cap.read()
            if not ok:
                print("camera read failed")
                break

            found = detect_aruco_corners(detector, frame)
            rectified_a4 = None
            if found is not None:
                H = homography_to_a4(found)
                rectified_a4 = rectify_a4(frame, H)
                cube_img = crop_cube(rectified_a4, size_out=CUBE_DST_SIZE)
                symbols, dists = extract_canonical(cube_img)
                sig = bytes(symbols)
                if sig == stable_sig:
                    stable_count = min(stable_count + 1, STABILITY_FRAMES)
                else:
                    stable_count = 1
                    stable_sig = sig
                if stable_count >= STABILITY_FRAMES and (
                    last_result is None
                    or last_result.get("_sig") != sig
                ):
                    res = run_protocol(symbols, dists, args)
                    res["_sig"] = sig
                    last_result = res
                    print()
                    print("=" * 64)
                    for k, v in res.items():
                        if k.startswith("_"):
                            continue
                        print(f"  {k:14s}: {v}")
                    print("=" * 64)
            else:
                stable_count = 0
                stable_sig = None

            frame = overlay_status(frame, found, stable_count, last_result)
            cv2.imshow(win, frame)
            key = cv2.waitKey(1) & 0xFF
            if key in (ord("q"), 27):
                break
            if key == ord("r"):
                last_result = None
                stable_count = 0
                stable_sig = None
                print("reset.")
            if key == ord("s") and rectified_a4 is not None:
                Path("out").mkdir(exist_ok=True)
                cv2.imwrite("out/live_rectified.png", rectified_a4)
                print("saved out/live_rectified.png")
    finally:
        cap.release()
        cv2.destroyAllWindows()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
