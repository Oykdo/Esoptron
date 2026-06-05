/**
 * Typed client for the Esoptron PWA REST API (/api/v1).
 *
 * Mirrors the JSON shape produced by `eopx.server.serialization` on the
 * Python side. When the wire format evolves, both sides must bump
 * together.
 */

export type Intent =
  | "enroll"
  | "recover"
  | "verify"
  | "unlock"
  | "unlock_private"
  | "genesis";

export interface EnrollmentDTO {
  vault_fp_hex: string;
  enrollment_fp_hex: string;
  public_tag_hex: string;
  shadow_hologram_hex: string;
  device_secret_hex?: string;
}

export interface GenesisVaultDTO {
  ceremony_fp_hex: string;
  vault_fp_hex: string;
  vault_seed_hex?: string;
  master_key_hex?: string;
  device_entropy_hex?: string;
}

export interface ScanResultDTO {
  success: boolean;
  intent: Intent | null;
  card_fingerprint_hex: string | null;
  detection_method: string | null;
  markers_used: number | null;
  errors: string[];
  verify_ok?: boolean;
  recovery_phrase?: string[];
  enrollment?: EnrollmentDTO;
  genesis_vault?: GenesisVaultDTO;
  session_key_hex?: string;
  vault_master_key_hex?: string;
  vault_seed_hex?: string;
  symbols?: number[];
}

export interface InfoDTO {
  version: string;
  intents: Intent[];
  max_image_bytes: number;
  secret_reveal_header: string;
}

export interface ExtractResultDTO {
  success: boolean;
  card_fingerprint_hex: string | null;
  symbols: number[] | null;
  detection_method: string | null;
  markers_used: number | null;
  errors: string[];
}

export interface CodexRelicDTO {
  rank: number;
  key: string;
  name: string;
  title: string;
  element: "Fire" | "Water" | "Air" | "Earth";
  seal_hue: number;
  myth_echo: string;
  mechanism: string;
  lore: string;
  lore_fr: string;
  is_founder: boolean;
  /** Present from Codex v2: lets a scanned card map back to its relic. */
  artifact_id_hex?: string;
  card_fingerprint_hex?: string;
}

export interface CodexDistributionDTO {
  rank: number;
  key: string;
  vault_sequence: number;
  placement: "founder" | "derived";
}

export interface CodexManifestDTO {
  codex_version: number;
  catalog_commitment_hex: string;
  count: number;
  relics: CodexRelicDTO[];
  btc_block_hash_hex?: string;
  btc_block_height?: number;
  distribution?: CodexDistributionDTO[];
}

/** A golden egg's public identity (EPX golden-egg legend). */
export interface GoldenEggDTO {
  egg_number: number;
  position: number;
  tier: string;
  glyph: string;
  name: string;
  egg_id: string;
  egg_hash: string;
}

export interface EggResponseDTO {
  vault_fp_hex: string;
  egg: GoldenEggDTO;
  btc_block_height: number;
  committed: boolean;
}

/** Authoritative ledger state of a titled artifact (EPX-T §3.2). */
export interface ArtifactStateDTO {
  artifact_id_hex: string;
  seq: number;
  controller_pub_hex: string;
  content_commit_hex: string;
  issuer_fp_hex: string;
  updated_at: string;
}

export interface ScanRequest {
  image: Blob;
  intent: Intent;
  deviceEntropyHex?: string;
  recoveryPhrase?: string[];
  spinorHashHex?: string;
  challengeVaultIdHex?: string;
  challengeNonceHex?: string;
  challengeIssuedAt?: number;
  revealSecrets?: boolean;
}

// Base of the PWA API (scan / codex / egg). Same-origin by default; set
// VITE_API_BASE at build time for a path-mounted deploy (e.g. "/pwa/api/v1").
const DEFAULT_BASE: string =
  (import.meta.env?.VITE_API_BASE as string | undefined)?.replace(/\/$/, "") ??
  "/api/v1";

export class EsoptronApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = "EsoptronApiError";
  }
}

/**
 * Base URL of the titled-artifact anchor (EPX-T). It may be a different
 * origin from the PWA API (the anchor is its own service). Configure via
 * ``VITE_ANCHOR_URL``; defaults to same-origin ``/api/v1``.
 */
const ANCHOR_BASE: string =
  (import.meta.env?.VITE_ANCHOR_URL as string | undefined)?.replace(/\/$/, "") ??
  DEFAULT_BASE;

export class EsoptronApi {
  constructor(
    private readonly baseUrl: string = DEFAULT_BASE,
    private readonly anchorBaseUrl: string = ANCHOR_BASE,
  ) {}

  /**
   * Current ledger state of a titled artifact. Throws on 404 (not minted)
   * or transport failure; callers treat that as "ownership unknown".
   */
  async getArtifact(artifactIdHex: string): Promise<ArtifactStateDTO> {
    const r = await fetch(`${this.anchorBaseUrl}/artifact/${artifactIdHex}`);
    if (!r.ok)
      throw new EsoptronApiError(
        r.status,
        `artifact lookup failed (${r.status})`,
      );
    return (await r.json()) as ArtifactStateDTO;
  }

  /** Claim a huntable relic (EPX-V). ``proof`` is a ClaimProof dict. */
  async claimRelic(
    artifactIdHex: string,
    proof: unknown,
  ): Promise<{ seq: number; entry: ArtifactStateDTO }> {
    const r = await fetch(
      `${this.anchorBaseUrl}/artifact/${artifactIdHex}/claim`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(proof),
      },
    );
    if (!r.ok) {
      const body = await r.text();
      throw new EsoptronApiError(r.status, `claim failed (${r.status}): ${body}`);
    }
    return (await r.json()) as { seq: number; entry: ArtifactStateDTO };
  }

  async health(): Promise<{ status: string; version: string }> {
    return this.getJson("/health");
  }

  async info(): Promise<InfoDTO> {
    return this.getJson("/info");
  }

  /** Public Codex manifest: the curated relic catalog + (if committed) distribution. */
  async codex(): Promise<CodexManifestDTO> {
    return this.getJson("/codex");
  }

  /** The golden egg attributed to a vault (public record; no secrets). */
  async getEgg(vaultIdHex: string): Promise<EggResponseDTO> {
    return this.getJson(`/egg/${vaultIdHex}`);
  }

  /**
   * Detection-only call. The server runs ArUco + Reed-Solomon and
   * returns the 91 public symbols plus a stable card fingerprint, but
   * never sees ``device_entropy`` or any derived secret. Use this when
   * the enrollment crypto runs on-device via ``enrollFromCard``.
   */
  async extract(image: Blob): Promise<ExtractResultDTO> {
    const form = new FormData();
    form.append("image", image, "scan.jpg");
    const r = await fetch(`${this.baseUrl}/extract`, {
      method: "POST",
      body: form,
    });
    if (!r.ok) {
      const body = await r.text();
      throw new EsoptronApiError(
        r.status,
        `extract failed (${r.status}): ${body}`,
      );
    }
    return (await r.json()) as ExtractResultDTO;
  }

  async scan(req: ScanRequest): Promise<ScanResultDTO> {
    const form = new FormData();
    form.append("image", req.image, "scan.jpg");
    form.append("intent", req.intent);
    if (req.deviceEntropyHex)
      form.append("device_entropy_hex", req.deviceEntropyHex);
    if (req.recoveryPhrase && req.recoveryPhrase.length > 0)
      form.append("recovery_phrase", req.recoveryPhrase.join(" "));
    if (req.spinorHashHex) form.append("spinor_hash_hex", req.spinorHashHex);
    if (req.challengeVaultIdHex)
      form.append("challenge_vault_id_hex", req.challengeVaultIdHex);
    if (req.challengeNonceHex)
      form.append("challenge_nonce_hex", req.challengeNonceHex);
    if (req.challengeIssuedAt !== undefined)
      form.append("challenge_issued_at", String(req.challengeIssuedAt));

    const headers: Record<string, string> = {};
    if (req.revealSecrets) headers["X-Esoptron-Reveal-Secrets"] = "1";

    const r = await fetch(`${this.baseUrl}/scan`, {
      method: "POST",
      body: form,
      headers,
    });
    if (!r.ok) {
      const body = await r.text();
      throw new EsoptronApiError(
        r.status,
        `scan failed (${r.status}): ${body}`,
      );
    }
    return (await r.json()) as ScanResultDTO;
  }

  private async getJson<T>(path: string): Promise<T> {
    const r = await fetch(`${this.baseUrl}${path}`);
    if (!r.ok)
      throw new EsoptronApiError(r.status, `GET ${path} failed (${r.status})`);
    return (await r.json()) as T;
  }
}

export function randomEntropyHex(bytes = 32): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}
