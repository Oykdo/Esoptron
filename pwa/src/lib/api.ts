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

const DEFAULT_BASE = "/api/v1";

export class EsoptronApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = "EsoptronApiError";
  }
}

export class EsoptronApi {
  constructor(private readonly baseUrl: string = DEFAULT_BASE) {}

  async health(): Promise<{ status: string; version: string }> {
    return this.getJson("/health");
  }

  async info(): Promise<InfoDTO> {
    return this.getJson("/info");
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
