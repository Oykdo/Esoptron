"""Local Flask server that lets a phone scan a Metatron sheet through its
own native camera. The phone uploads each shot to the PC server, which
runs the ArUco -> homography -> decode pipeline and returns the result.

No phone app required, no HTTPS gymnastics, no camera attached to the PC.
"""

from .app import create_app
from .pwa_api import create_app as create_pwa_app, create_pwa_api

__all__ = ["create_app", "create_pwa_app", "create_pwa_api"]
