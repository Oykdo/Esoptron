import { useEffect, useRef } from "react";
import * as THREE from "three";
import { sha3_512 } from "@noble/hashes/sha3";
import { CodexRelicDTO } from "../lib/api";

/**
 * A 3D representation of a relic, driven by the SAME spinor seed as its 2D
 * badge — so the holographic view and the printed Metatron cube stay
 * coherent. The seed is recomputed client-side (sha3_512 of the relic key
 * under the frozen Codex domain), exactly as the Python `Relic.spinor_seed`.
 *
 * It renders Metatron's Cube — 13 vertices, all 78 edges (the F₁₃ structure)
 * — with the EPX-H hexagram seal emerging in the relic's seal colour. This
 * is the BRAND layer (beauty / recognition), never security: the trust still
 * lives in the 91 symbols + signature + ledger.
 */

interface Props {
  relic: CodexRelicDTO;
  size?: number;
}

const CODEX_DOMAIN = "esoptron.codex.v1";

function spinorSeed(key: string): Uint8Array {
  return sha3_512(new TextEncoder().encode(`${CODEX_DOMAIN}|spinor|${key}`));
}

/** Deterministic PRNG seeded from 4 seed bytes (mulberry32). */
function rng(seed: Uint8Array, offset = 0) {
  let a =
    ((seed[offset] << 24) |
      (seed[offset + 1] << 16) |
      (seed[offset + 2] << 8) |
      seed[offset + 3]) >>>
    0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** The 13 points of Metatron's Cube, given holographic depth per ring. */
function metatronPoints(depth: number): THREE.Vector3[] {
  const pts: THREE.Vector3[] = [new THREE.Vector3(0, 0, 0)];
  const R1 = 1.0;
  const R2 = Math.sqrt(3) * R1;
  for (let k = 0; k < 6; k++) {
    const a = (k * Math.PI) / 3;
    pts.push(new THREE.Vector3(Math.cos(a) * R1, Math.sin(a) * R1, depth));
  }
  for (let k = 0; k < 6; k++) {
    const a = Math.PI / 6 + (k * Math.PI) / 3;
    pts.push(new THREE.Vector3(Math.cos(a) * R2, Math.sin(a) * R2, -depth));
  }
  return pts;
}

const ELEMENT_HUE: Record<string, number> = {
  Fire: 8,
  Water: 210,
  Air: 48,
  Earth: 132,
};

export function RelicCanvas({ relic, size = 320 }: Props) {
  const mountRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const seed = spinorSeed(relic.key);
    const rand = rng(seed, 8);
    const hue = relic.seal_hue || ELEMENT_HUE[relic.element] || 200;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
    camera.position.set(0, 0, 6.2);

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    } catch {
      mount.innerHTML =
        '<p style="color:#8d8fa6;font-size:13px">WebGL unavailable on this device.</p>';
      return;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(size, size);
    mount.appendChild(renderer.domElement);

    const group = new THREE.Group();
    scene.add(group);

    const depth = 0.25 + rand() * 0.35;
    const pts = metatronPoints(depth);

    const sealColor = new THREE.Color(`hsl(${hue}, 75%, 58%)`);
    const fireColor = new THREE.Color(`hsl(${(hue + 20) % 360}, 85%, 60%)`);
    const waterColor = new THREE.Color(`hsl(${(hue + 200) % 360}, 80%, 60%)`);
    const edgeColor = new THREE.Color(`hsl(${hue}, 30%, 70%)`);

    const disposables: Array<{ dispose: () => void }> = [];

    // --- vertices: 13 small glowing spheres ---
    const sphereGeo = new THREE.SphereGeometry(0.07, 16, 16);
    const vertMat = new THREE.MeshStandardMaterial({
      color: 0x14142a,
      emissive: sealColor,
      emissiveIntensity: 0.55,
      roughness: 0.4,
    });
    disposables.push(sphereGeo, vertMat);
    for (const p of pts) {
      const m = new THREE.Mesh(sphereGeo, vertMat);
      m.position.copy(p);
      group.add(m);
    }

    // --- 78 edges: every pair of the 13 vertices (the F₁₃ structure) ---
    const edgePositions: number[] = [];
    for (let i = 0; i < pts.length; i++) {
      for (let j = i + 1; j < pts.length; j++) {
        edgePositions.push(pts[i].x, pts[i].y, pts[i].z);
        edgePositions.push(pts[j].x, pts[j].y, pts[j].z);
      }
    }
    const edgeGeo = new THREE.BufferGeometry();
    edgeGeo.setAttribute(
      "position",
      new THREE.Float32BufferAttribute(edgePositions, 3),
    );
    const edgeMat = new THREE.LineBasicMaterial({
      color: edgeColor,
      transparent: true,
      opacity: 0.28,
    });
    disposables.push(edgeGeo, edgeMat);
    group.add(new THREE.LineSegments(edgeGeo, edgeMat));

    // --- the EPX-H hexagram seal: two emissive triangles from outer points ---
    const outer = pts.slice(7); // 6 outer vertices
    const triangle = (a: THREE.Vector3, b: THREE.Vector3, c: THREE.Vector3) =>
      [a, b, c, a].flatMap((v) => [v.x, v.y, v.z * 0.4 + 0.18]);
    const triA = triangle(outer[0], outer[2], outer[4]);
    const triB = triangle(outer[1], outer[3], outer[5]);
    for (const [verts, col] of [
      [triA, fireColor],
      [triB, waterColor],
    ] as const) {
      const g = new THREE.BufferGeometry();
      g.setAttribute("position", new THREE.Float32BufferAttribute(verts, 3));
      const m = new THREE.LineBasicMaterial({ color: col });
      disposables.push(g, m);
      group.add(new THREE.Line(g, m));
    }

    // --- lights ---
    const ambient = new THREE.AmbientLight(0xffffff, 0.5);
    const point = new THREE.PointLight(sealColor, 1.4, 50);
    point.position.set(2.5, 3, 4);
    scene.add(ambient, point);

    // tilt by the seed so each relic sits at its own angle
    group.rotation.x = -0.5 + rand() * 0.4;
    const spin = 0.15 + rand() * 0.25;

    let raf = 0;
    let last = 0;
    let mounted = true;
    const tick = (t: number) => {
      if (!mounted) return;
      const dt = last ? (t - last) / 1000 : 0;
      last = t;
      group.rotation.y += dt * spin;
      group.rotation.z += dt * spin * 0.12;
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
  }, [relic.key, relic.element, relic.seal_hue, size]);

  return <div className="relic-canvas" ref={mountRef} aria-hidden="true" />;
}
