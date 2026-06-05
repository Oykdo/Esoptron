import { useEffect, useRef } from "react";
import * as THREE from "three";
import { sha3_256 } from "@noble/hashes/sha3";
import { GoldenEggDTO } from "../lib/api";

/**
 * A timeless golden egg, rendered in 3D. The shell is gold; the tier tints
 * its inner glow and halo; fine filigree meridians are derived from the
 * egg's hash so every egg is unique yet reproducible. Slow, weightless
 * rotation — a relic meant to be *kept*, not skimmed.
 */

interface Props {
  egg: GoldenEggDTO;
  size?: number;
}

const TIER_HUE: Record<string, number> = {
  Cosmic: 282, // violet
  Stellar: 46, // gold
  Lunar: 212, // pale blue
  Crystal: 188, // cyan
  Stone: 34, // warm bronze
};

/** Egg profile: an ellipsoid tapered toward the top → a real egg silhouette. */
function eggify(geo: THREE.SphereGeometry): THREE.SphereGeometry {
  const pos = geo.attributes.position as THREE.BufferAttribute;
  for (let i = 0; i < pos.count; i++) {
    const x = pos.getX(i);
    const y = pos.getY(i);
    const z = pos.getZ(i);
    const yn = y; // sphere radius 1 → y in [-1, 1]
    const taper = 1 - 0.18 * (yn + 1) * 0.5; // narrower toward +y
    pos.setX(i, x * taper);
    pos.setZ(i, z * taper);
    pos.setY(i, y * 1.32); // elongate
  }
  pos.needsUpdate = true;
  geo.computeVertexNormals();
  return geo;
}

export function EggViewer({ egg, size = 340 }: Props) {
  const mountRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const seed = sha3_256(new TextEncoder().encode(egg.egg_hash || egg.egg_id));
    const hue = TIER_HUE[egg.tier] ?? 46;
    const tierColor = new THREE.Color(`hsl(${hue}, 80%, 60%)`);
    const gold = new THREE.Color("hsl(44, 70%, 55%)");

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 100);
    camera.position.set(0, 0, 6);

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    } catch {
      mount.innerHTML =
        '<p style="color:#8d8fa6;font-size:13px">WebGL unavailable.</p>';
      return;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(size, size);
    mount.appendChild(renderer.domElement);

    const group = new THREE.Group();
    scene.add(group);
    const disposables: Array<{ dispose: () => void }> = [];

    // --- the egg shell (gold, metallic, tier-tinted emissive) ---
    const shellGeo = eggify(new THREE.SphereGeometry(1, 96, 96));
    const shellMat = new THREE.MeshStandardMaterial({
      color: gold,
      metalness: 0.92,
      roughness: 0.22,
      emissive: tierColor,
      emissiveIntensity: 0.18,
    });
    disposables.push(shellGeo, shellMat);
    group.add(new THREE.Mesh(shellGeo, shellMat));

    // --- filigree meridians, count + phase derived from the hash ---
    const ringCount = 5 + (seed[0] % 6); // 5..10 unique bands
    for (let k = 0; k < ringCount; k++) {
      const torusGeo = new THREE.TorusGeometry(1.005, 0.006, 8, 96);
      const torusMat = new THREE.MeshBasicMaterial({
        color: tierColor,
        transparent: true,
        opacity: 0.5,
      });
      disposables.push(torusGeo, torusMat);
      const ring = new THREE.Mesh(torusGeo, torusMat);
      ring.scale.y = 1.32; // follow the egg elongation
      const phase = (seed[(k % 28) + 1] / 255) * Math.PI;
      ring.rotation.y = phase + (k / ringCount) * Math.PI;
      group.add(ring);
    }

    // --- inner glow + outer halo (additive) ---
    const coreGeo = eggify(new THREE.SphereGeometry(0.86, 48, 48));
    const coreMat = new THREE.MeshBasicMaterial({
      color: tierColor,
      transparent: true,
      opacity: 0.12,
      blending: THREE.AdditiveBlending,
    });
    disposables.push(coreGeo, coreMat);
    group.add(new THREE.Mesh(coreGeo, coreMat));

    const haloGeo = eggify(new THREE.SphereGeometry(1.25, 48, 48));
    const haloMat = new THREE.MeshBasicMaterial({
      color: tierColor,
      transparent: true,
      opacity: 0.06,
      blending: THREE.AdditiveBlending,
      side: THREE.BackSide,
    });
    disposables.push(haloGeo, haloMat);
    group.add(new THREE.Mesh(haloGeo, haloMat));

    // --- lights ---
    const ambient = new THREE.AmbientLight(0xffffff, 0.45);
    const key = new THREE.PointLight(0xfff3d0, 1.6, 40);
    key.position.set(3, 4, 5);
    const rim = new THREE.PointLight(tierColor.getHex(), 1.1, 40);
    rim.position.set(-3, -2, 3);
    scene.add(ambient, key, rim);

    group.rotation.x = -0.15;
    let raf = 0;
    let last = 0;
    let mounted = true;
    const tick = (t: number) => {
      if (!mounted) return;
      const dt = last ? (t - last) / 1000 : 0;
      last = t;
      group.rotation.y += dt * 0.35; // slow, weightless
      renderer.render(scene, camera);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);

    return () => {
      mounted = false;
      cancelAnimationFrame(raf);
      for (const d of disposables) d.dispose();
      renderer.dispose();
      if (renderer.domElement.parentNode === mount) {
        mount.removeChild(renderer.domElement);
      }
    };
  }, [egg.egg_hash, egg.egg_id, egg.tier, size]);

  return <div className="egg-canvas" ref={mountRef} aria-hidden="true" />;
}
