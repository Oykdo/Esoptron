/**
 * IndexedDB-backed secret storage, encrypted at rest with AES-GCM.
 *
 * The encryption key is derived from a user-supplied passphrase via
 * PBKDF2-SHA-256 with a random per-installation salt. The salt is stored
 * unencrypted alongside the ciphertext; the passphrase never is.
 *
 * Threat model
 * ------------
 * * An attacker reading the browser's IndexedDB without the passphrase
 *   sees only ciphertext + salt + iteration count.
 * * An attacker who phishes the passphrase obtains all stored material.
 * * This is NOT a substitute for a hardware-backed keystore (which is
 *   what the future native app will use via Keychain / Keystore).
 */

const DB_NAME = "esoptron-secrets";
const DB_VERSION = 1;
const STORE = "secrets";
const META_STORE = "meta";

const PBKDF2_ITERATIONS = 600_000;
const SALT_LEN = 16;
const IV_LEN = 12;

// ---------------------------------------------------------------------------
// Low-level IDB plumbing
// ---------------------------------------------------------------------------

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE))
        db.createObjectStore(STORE, { keyPath: "id" });
      if (!db.objectStoreNames.contains(META_STORE))
        db.createObjectStore(META_STORE, { keyPath: "id" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet<T>(store: string, id: string): Promise<T | undefined> {
  const db = await openDb();
  return await new Promise<T | undefined>((resolve, reject) => {
    const tx = db.transaction(store, "readonly");
    const req = tx.objectStore(store).get(id);
    req.onsuccess = () => resolve(req.result as T | undefined);
    req.onerror = () => reject(req.error);
  });
}

async function idbPut(store: string, value: object): Promise<void> {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).put(value);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbDelete(store: string, id: string): Promise<void> {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/** Force a Uint8Array onto a plain ArrayBuffer view so it satisfies the
 *  DOM ``BufferSource`` typing introduced by recent TypeScript releases. */
function toBufferSource(u: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(u.byteLength);
  new Uint8Array(ab).set(u);
  return ab;
}

async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    toBufferSource(new TextEncoder().encode(passphrase)),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: toBufferSource(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function b64encode(buf: ArrayBuffer | Uint8Array): string {
  const bytes =
    buf instanceof Uint8Array ? buf : new Uint8Array(buf as ArrayBuffer);
  let bin = "";
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface StoredEnrollment {
  vault_fp_hex: string;
  enrollment_fp_hex: string;
  public_tag_hex: string;
  device_secret_hex: string;
  /** ISO-8601 timestamp set at write time. */
  created_at: string;
  /**
   * Kyber1024 secret key for the "self-contact" recovery slot, present
   * only when Holographic Recovery is configured. In MVP the user is
   * their own recovery contact; this sk lives encrypted at rest in
   * IndexedDB. Phase 6 will replace it with a real friend's pk and
   * delete the local sk.
   */
  contact_kyber_sk_hex?: string;
  /**
   * Group ID of the active recovery package. Lets the UI confirm a
   * downloaded package matches the local enrollment.
   */
  recovery_group_id?: string;
}

interface EnvelopeRecord {
  id: string;
  iv: string; // base64
  ciphertext: string; // base64
}

interface MetaRecord {
  id: "vault";
  salt: string; // base64
  iterations: number;
}

async function ensureSalt(): Promise<Uint8Array> {
  const existing = await idbGet<MetaRecord>(META_STORE, "vault");
  if (existing) return b64decode(existing.salt);
  const salt = new Uint8Array(SALT_LEN);
  crypto.getRandomValues(salt);
  await idbPut(META_STORE, {
    id: "vault",
    salt: b64encode(salt),
    iterations: PBKDF2_ITERATIONS,
  } satisfies MetaRecord);
  return salt;
}

export async function hasStoredEnrollment(): Promise<boolean> {
  const r = await idbGet<EnvelopeRecord>(STORE, "default");
  return r !== undefined;
}

export async function storeEnrollment(
  enrollment: StoredEnrollment,
  passphrase: string,
): Promise<void> {
  if (!passphrase || passphrase.length < 8)
    throw new Error("passphrase must be at least 8 characters");
  const salt = await ensureSalt();
  const key = await deriveKey(passphrase, salt);
  const iv = new Uint8Array(IV_LEN);
  crypto.getRandomValues(iv);
  const plaintext = new TextEncoder().encode(JSON.stringify(enrollment));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toBufferSource(iv) },
    key,
    toBufferSource(plaintext),
  );
  await idbPut(STORE, {
    id: "default",
    iv: b64encode(iv),
    ciphertext: b64encode(ct),
  } satisfies EnvelopeRecord);
}

export async function loadEnrollment(
  passphrase: string,
): Promise<StoredEnrollment | null> {
  const env = await idbGet<EnvelopeRecord>(STORE, "default");
  if (!env) return null;
  const meta = await idbGet<MetaRecord>(META_STORE, "vault");
  if (!meta) throw new Error("storage corrupted: missing salt");
  const key = await deriveKey(passphrase, b64decode(meta.salt));
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toBufferSource(b64decode(env.iv)) },
      key,
      toBufferSource(b64decode(env.ciphertext)),
    );
    return JSON.parse(new TextDecoder().decode(pt)) as StoredEnrollment;
  } catch {
    throw new Error("bad passphrase or corrupted store");
  }
}

export async function clearStoredEnrollment(): Promise<void> {
  await idbDelete(STORE, "default");
  await idbDelete(META_STORE, "vault");
}

// ---------------------------------------------------------------------------
// Relic claims (EPX-C) — PUBLIC data, not encrypted
// ---------------------------------------------------------------------------
//
// When a vault claims a relic it keeps a public record of the controller it
// holds for that artifact. Possession is then a string comparison against the
// anchor's current controller (see RelicsGallery): no secret is involved, so
// these live in localStorage rather than the encrypted enrollment store. The
// controller *secret* stays sealed to the vault and is never persisted here.

const RELIC_CLAIMS_KEY = "esoptron.relic-claims.v1";

export interface RelicClaim {
  /** Codex relic key (e.g. "scintilla"). */
  key: string;
  /** EPX-T artifact id (hex). */
  artifact_id_hex: string;
  /** Public controller the vault holds for this artifact (hex). */
  controller_pub_hex: string;
  /** ISO-8601 timestamp set at claim time. */
  claimed_at: string;
}

export function loadRelicClaims(): RelicClaim[] {
  try {
    const raw = localStorage.getItem(RELIC_CLAIMS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as RelicClaim[]) : [];
  } catch {
    return [];
  }
}

export function storeRelicClaim(claim: RelicClaim): void {
  const claims = loadRelicClaims().filter((c) => c.key !== claim.key);
  claims.push(claim);
  localStorage.setItem(RELIC_CLAIMS_KEY, JSON.stringify(claims));
}

export function clearRelicClaims(): void {
  localStorage.removeItem(RELIC_CLAIMS_KEY);
}
