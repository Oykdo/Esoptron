"""Interactive 6-click decoder for a photographed Metatron sheet.

You point this tool at a photo, click the 6 outer-hexagon vertices in
order, and it runs the full chain:

    rectify -> extract symbols -> RS decode -> derive master_key

Usage
-----
    py scripts/pick_and_decode.py path\to\photo.jpg

Optional arguments
------------------
    --mode private|verify|sas    default: private
    --spinor <128hex>            required for verify/sas
    --known-seed <64hex>         compare recovered seed for self-test
    --save-rectified out.png     save the rectified canonical-frame image

Click order (THIS IS IMPORTANT — match the labels shown in the window):
    1. V[7]   top-RIGHT       (1 o'clock)
    2. V[8]   TOP             (12 o'clock)
    3. V[9]   top-LEFT        (11 o'clock)
    4. V[10]  bottom-LEFT     (7 o'clock)
    5. V[11]  BOTTOM          (6 o'clock)
    6. V[12]  bottom-RIGHT    (5 o'clock)

Right-click or press Backspace to undo the last point.
Press Enter once 6 points are placed to run the decoder.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox
from typing import List, Optional, Tuple

from PIL import Image, ImageDraw, ImageTk

from eopx.metatron import (
    extract_from_photo, erasures_from_confidences,
)
from eopx.vault import (
    unlock_from_private_symbols, verify_card,
    new_challenge, respond, verify_response,
)


VERTEX_LABELS = [
    ("V[7]",  "top-RIGHT   (1 o'clock)"),
    ("V[8]",  "TOP         (12 o'clock)"),
    ("V[9]",  "top-LEFT    (11 o'clock)"),
    ("V[10]", "bottom-LEFT (7 o'clock)"),
    ("V[11]", "BOTTOM      (6 o'clock)"),
    ("V[12]", "bottom-RIGHT (5 o'clock)"),
]

MARKER_COLORS = ["#ff3030", "#ffa030", "#ffe030",
                 "#30c030", "#3080ff", "#a030ff"]


class Picker:
    def __init__(self, photo_path: Path, args):
        self.photo_path = photo_path
        self.args = args
        self.original = Image.open(photo_path).convert("RGB")
        self.points: List[Tuple[float, float]] = []  # in ORIGINAL pixel coords

        self.root = tk.Tk()
        self.root.title(f"Metatron picker — {photo_path.name}")

        # Scale the image to fit ~85 % of the screen.
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        max_w = int(sw * 0.85)
        max_h = int(sh * 0.80)
        ow, oh = self.original.size
        scale = min(max_w / ow, max_h / oh, 1.0)
        self.scale = scale
        self.disp_w = int(ow * scale)
        self.disp_h = int(oh * scale)
        self.disp_img = self.original.resize(
            (self.disp_w, self.disp_h), Image.Resampling.BILINEAR,
        )

        # Layout: status bar on top, canvas below.
        self.status = tk.Label(self.root, font=("Segoe UI", 12), pady=6,
                                fg="#202020", bg="#f7f7f7")
        self.status.pack(fill=tk.X)
        self.canvas = tk.Canvas(self.root, width=self.disp_w,
                                 height=self.disp_h, bg="#202020",
                                 highlightthickness=0)
        self.canvas.pack()

        self.tk_img = ImageTk.PhotoImage(self.disp_img)
        self.canvas.create_image(0, 0, image=self.tk_img, anchor=tk.NW)

        # Bindings.
        self.canvas.bind("<Button-1>", self.on_click)
        self.canvas.bind("<Button-3>", self.on_undo)
        self.root.bind("<BackSpace>", self.on_undo)
        self.root.bind("<Return>", self.on_decode)
        self.root.bind("<Escape>", lambda _e: self.root.destroy())

        self.update_status()

    def update_status(self):
        n = len(self.points)
        if n < 6:
            label, hint = VERTEX_LABELS[n]
            self.status.config(
                text=(f"Click {n + 1}/6 -> {label}   {hint}"
                      "    [right-click / Backspace = undo, Esc = quit]"),
            )
        else:
            self.status.config(
                text=("All 6 points placed. Press ENTER to decode, "
                      "right-click / Backspace to redo last."),
            )

    def on_click(self, event):
        if len(self.points) >= 6:
            return
        # Map display coords back to original pixel coords.
        x_orig = event.x / self.scale
        y_orig = event.y / self.scale
        self.points.append((x_orig, y_orig))
        color = MARKER_COLORS[len(self.points) - 1]
        r = 7
        self.canvas.create_oval(event.x - r, event.y - r,
                                  event.x + r, event.y + r,
                                  outline=color, width=3, tags="marker")
        self.canvas.create_text(event.x + 12, event.y - 12,
                                 text=str(len(self.points)),
                                 fill=color,
                                 font=("Consolas", 14, "bold"),
                                 tags="marker")
        self.update_status()

    def on_undo(self, _event=None):
        if not self.points:
            return
        self.points.pop()
        # Redraw all markers from scratch (simpler than tracking ids).
        self.canvas.delete("marker")
        for i, (xo, yo) in enumerate(self.points):
            color = MARKER_COLORS[i]
            x = xo * self.scale
            y = yo * self.scale
            r = 7
            self.canvas.create_oval(x - r, y - r, x + r, y + r,
                                      outline=color, width=3, tags="marker")
            self.canvas.create_text(x + 12, y - 12, text=str(i + 1),
                                     fill=color,
                                     font=("Consolas", 14, "bold"),
                                     tags="marker")
        self.update_status()

    def on_decode(self, _event=None):
        if len(self.points) != 6:
            return
        self.status.config(text="Decoding... (rectifying + extracting symbols)")
        self.root.update_idletasks()
        try:
            result = self.run_pipeline()
        except Exception as e:
            messagebox.showerror("Decode failure", str(e))
            self.status.config(text=f"Failed: {e}")
            return
        self.show_result(result)

    def run_pipeline(self):
        symbols, dists, rect = extract_from_photo(self.original, self.points)
        erasures = erasures_from_confidences(dists)
        out = {
            "n_symbols": len(symbols),
            "n_erasures": len(erasures),
            "rectified": rect,
            "symbols": symbols,
            "erasures": erasures,
        }
        mode = self.args.mode
        if mode == "private":
            seed, master_key = unlock_from_private_symbols(symbols,
                                                            erasures=erasures)
            out["seed"] = seed.hex()
            out["master_key"] = master_key.hex()
            if self.args.known_seed:
                out["seed_match"] = (seed.hex().lower()
                                     == self.args.known_seed.lower())
        else:
            if not self.args.spinor:
                raise ValueError("--spinor required for verify/sas")
            spinor = bytes.fromhex(self.args.spinor.strip())
            if mode == "verify":
                out["verify"] = verify_card(symbols, spinor)
            elif mode == "sas":
                vault_id = hashlib.sha3_256(spinor).digest()
                ch = new_challenge(vault_id)
                try:
                    resp = respond(symbols, spinor, ch)
                    session = verify_response(resp, spinor, symbols)
                    out["session_key"] = session.hex() if session else None
                except ValueError as e:
                    out["sas_error"] = str(e)
        if self.args.save_rectified:
            rect.save(self.args.save_rectified, format="PNG")
            out["rectified_path"] = self.args.save_rectified
        return out

    def show_result(self, r):
        lines = [
            f"symbols extracted : {r['n_symbols']}",
            f"erasures flagged  : {r['n_erasures']} / 91",
        ]
        if "seed" in r:
            lines.append(f"seed (hex)        : {r['seed']}")
            lines.append(f"master_key        : {r['master_key']}")
            if "seed_match" in r:
                tag = "MATCHES known seed" if r["seed_match"] else "DIFFERS from known seed"
                lines.append(f"self-check        : {tag}")
        if "verify" in r:
            lines.append(f"card matches local vault: {r['verify']}")
        if "sas_error" in r:
            lines.append(f"SAS rejected: {r['sas_error']}")
        if "session_key" in r:
            lines.append(f"session_key       : {r['session_key']}")
        if "rectified_path" in r:
            lines.append(f"rectified saved   : {r['rectified_path']}")

        msg = "\n".join(lines)
        print()
        print("=" * 72)
        print(msg)
        print("=" * 72)
        messagebox.showinfo("Result", msg)

    def run(self):
        self.root.mainloop()


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="pick_and_decode")
    p.add_argument("photo")
    p.add_argument("--mode", choices=("private", "verify", "sas"),
                   default="private")
    p.add_argument("--spinor")
    p.add_argument("--known-seed",
                   help="hex; compare against the recovered seed")
    p.add_argument("--save-rectified")
    args = p.parse_args(argv[1:])

    photo = Path(args.photo)
    if not photo.exists():
        raise SystemExit(f"photo not found: {photo}")
    Picker(photo, args).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
