/**
 * Holographic Recovery — TypeScript port of ``eopx.recovery``.
 *
 * Wire format is frozen at ``schema_version = 1``; envelopes serialise
 * to the exact same JSON shape Python produces, so a package generated
 * by either side opens on the other.
 */

import { argon2id } from "@noble/hashes/argon2";
import { hkdf } from "@noble/hashes/hkdf";
import { sha3_256 } from "@noble/hashes/sha3";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem";

import { fromHex, toHex } from "./crypto";
import { combine as shamirCombine, split as shamirSplit, Share } from "./shamir";

export const SCHEMA_VERSION = 1;
export const DEFAULT_THRESHOLD = 2;
export const DEFAULT_TOTAL = 3;

const NONCE_LEN = 12;
const SALT_LEN = 16;
const AEAD_KEY_LEN = 32;
const AEAD_INFO_KYBER = new TextEncoder().encode(
  "esoptron.recovery.kyber.aead.v1",
);

/**
 * Argon2id parameter tiers.
 *
 * - `workstation` (default): mirrors the Python `ARGON2_PROFILES["workstation"]`
 *   constants. ~1-2s card PIN / ~4-8s passphrase on a laptop.
 * - `mobile`: lighter parameters for mid-range phones (~3-5s / ~8-12s). The
 *   wire format records the actual parameters used at seal time, so a package
 *   created in either profile can be opened in the other.
 *
 * Override at session level by setting `window.__ESOPTRON_ARGON2_PROFILE__`
 * before the recovery module loads, or by passing `{profile: "mobile"}` to
 * `setupRecovery` / `setupRecoveryFlexible`.
 */
export const ARGON2_PROFILES = {
  workstation: {
    card_pin:   { t: 3, m: 64  * 1024, p: 1, dkLen: AEAD_KEY_LEN },
    passphrase: { t: 4, m: 128 * 1024, p: 1, dkLen: AEAD_KEY_LEN },
  },
  mobile: {
    card_pin:   { t: 3, m: 32 * 1024, p: 1, dkLen: AEAD_KEY_LEN },
    passphrase: { t: 3, m: 64 * 1024, p: 1, dkLen: AEAD_KEY_LEN },
  },
} as const;

export type Argon2Profile = keyof typeof ARGON2_PROFILES;

function activeProfile(): Argon2Profile {
  const w = (globalThis as any).__ESOPTRON_ARGON2_PROFILE__;
  if (w === "mobile" || w === "workstation") return w;
  return "workstation";
}

function argon2ParamsFor(kind: "card_pin" | "passphrase", profile?: Argon2Profile) {
  const p = profile ?? activeProfile();
  return ARGON2_PROFILES[p][kind];
}

function kdfParamsStr(kind: "card_pin" | "passphrase", profile?: Argon2Profile): string {
  const p = argon2ParamsFor(kind, profile);
  return `argon2id-m${p.m / 1024}-t${p.t}-p${p.p}`;
}

function parseKdfParams(kdf: string, kind: "card_pin" | "passphrase") {
  try {
    const [prefix, ...parts] = kdf.split("-");
    if (prefix !== "argon2id") throw new Error("not argon2id");
    let t = 0, m = 0, p = 0;
    for (const part of parts) {
      const tag = part[0];
      const v = parseInt(part.slice(1), 10);
      if (Number.isNaN(v)) throw new Error("bad number");
      if (tag === "m") m = v * 1024;
      else if (tag === "t") t = v;
      else if (tag === "p") p = v;
      else throw new Error("bad tag");
    }
    if (!t || !m || !p) throw new Error("missing field");
    return { t, m, p, dkLen: AEAD_KEY_LEN };
  } catch {
    return argon2ParamsFor(kind);
  }
}

// Back-compat: legacy `ARGON2_CARD` / `ARGON2_CLOUD` references in tests etc.
// Exported so they remain available to importers (and don't trip
// noUnusedLocals as module-private constants).
export const ARGON2_CARD = ARGON2_PROFILES.workstation.card_pin;
export const ARGON2_CLOUD = ARGON2_PROFILES.workstation.passphrase;
export const KDF_CARD_STR = kdfParamsStr("card_pin", "workstation");
export const KDF_CLOUD_STR = kdfParamsStr("passphrase", "workstation");

const utf8 = (s: string) => new TextEncoder().encode(s);

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

function aadForShare(
  groupId: string,
  index: number,
  kind: ShareKind,
  threshold: number,
  total: number,
): Uint8Array {
  return utf8(
    ["esoptron.recovery.v1", groupId, String(index), kind,
      String(threshold), String(total)].join("|"),
  );
}

function kyberKdf(ss: Uint8Array): Uint8Array {
  // Match Python: HKDF-SHA3-256 with salt=zeros, info=AEAD_INFO_KYBER, len=32.
  return hkdf(sha3_256, ss, new Uint8Array(32), AEAD_INFO_KYBER, AEAD_KEY_LEN);
}

function sha3Fingerprint(pk: Uint8Array): Uint8Array {
  return sha3_256(pk);
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ShareKind = "card_pin" | "kyber_pk" | "passphrase";

export interface CardPinShareEnvelope {
  index: number;
  kind: "card_pin";
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  salt: Uint8Array;
  kdf: string;
}

export interface KyberShareEnvelope {
  index: number;
  kind: "kyber_pk";
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  recipientFp: Uint8Array;
  kemCiphertext: Uint8Array;
}

export interface PassphraseShareEnvelope {
  index: number;
  kind: "passphrase";
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  salt: Uint8Array;
  kdf: string;
}

export type ShareEnvelope =
  | CardPinShareEnvelope
  | KyberShareEnvelope
  | PassphraseShareEnvelope;

export interface RecoveryPackage {
  schemaVersion: number;
  groupId: string;
  threshold: number;
  total: number;
  vaultFpHex: string;
  createdAt: string;
  shares: ShareEnvelope[];
}

export interface RecoveryCredentials {
  cardPin?: string;
  contactKyberSk?: Uint8Array;
  cloudPassphrase?: string;
}

// ---------------------------------------------------------------------------
// JSON serialization — mirrors Python field-for-field
// ---------------------------------------------------------------------------

interface JsonShareCommon {
  index: number;
  kind: ShareKind;
  nonce_hex: string;
  ciphertext_hex: string;
}
interface JsonCardPin extends JsonShareCommon {
  kind: "card_pin";
  salt_hex: string;
  kdf: string;
}
interface JsonKyber extends JsonShareCommon {
  kind: "kyber_pk";
  recipient_fp_hex: string;
  kem_ciphertext_hex: string;
}
interface JsonPass extends JsonShareCommon {
  kind: "passphrase";
  salt_hex: string;
  kdf: string;
}
type JsonShare = JsonCardPin | JsonKyber | JsonPass;

export interface RecoveryPackageJSON {
  schema_version: number;
  group_id: string;
  threshold: number;
  total: number;
  vault_fp_hex: string;
  created_at: string;
  shares: JsonShare[];
}

function shareToJson(e: ShareEnvelope): JsonShare {
  const base = {
    index: e.index,
    kind: e.kind,
    nonce_hex: toHex(e.nonce),
    ciphertext_hex: toHex(e.ciphertext),
  };
  if (e.kind === "card_pin")
    return { ...base, kind: "card_pin", salt_hex: toHex(e.salt), kdf: e.kdf };
  if (e.kind === "passphrase")
    return { ...base, kind: "passphrase", salt_hex: toHex(e.salt), kdf: e.kdf };
  return {
    ...base,
    kind: "kyber_pk",
    recipient_fp_hex: toHex(e.recipientFp),
    kem_ciphertext_hex: toHex(e.kemCiphertext),
  };
}

function jsonToShare(j: JsonShare): ShareEnvelope {
  const common = {
    index: j.index,
    nonce: fromHex(j.nonce_hex),
    ciphertext: fromHex(j.ciphertext_hex),
  };
  if (j.kind === "card_pin")
    return {
      ...common,
      kind: "card_pin",
      salt: fromHex((j as JsonCardPin).salt_hex),
      kdf: (j as JsonCardPin).kdf,
    };
  if (j.kind === "passphrase")
    return {
      ...common,
      kind: "passphrase",
      salt: fromHex((j as JsonPass).salt_hex),
      kdf: (j as JsonPass).kdf,
    };
  if (j.kind === "kyber_pk")
    return {
      ...common,
      kind: "kyber_pk",
      recipientFp: fromHex((j as JsonKyber).recipient_fp_hex),
      kemCiphertext: fromHex((j as JsonKyber).kem_ciphertext_hex),
    };
  throw new Error(`unknown share kind: ${(j as { kind: string }).kind}`);
}

export function packageToJson(pkg: RecoveryPackage): RecoveryPackageJSON {
  return {
    schema_version: pkg.schemaVersion,
    group_id: pkg.groupId,
    threshold: pkg.threshold,
    total: pkg.total,
    vault_fp_hex: pkg.vaultFpHex,
    created_at: pkg.createdAt,
    shares: pkg.shares.map(shareToJson),
  };
}

export function packageFromJson(j: RecoveryPackageJSON): RecoveryPackage {
  if (j.schema_version !== SCHEMA_VERSION)
    throw new Error(`unsupported schema_version: ${j.schema_version}`);
  return {
    schemaVersion: j.schema_version,
    groupId: j.group_id,
    threshold: j.threshold,
    total: j.total,
    vaultFpHex: j.vault_fp_hex,
    createdAt: j.created_at,
    shares: j.shares.map(jsonToShare),
  };
}

// ---------------------------------------------------------------------------
// Per-share seal / open
// ---------------------------------------------------------------------------

function sealCardPin(
  shareBytes: Uint8Array,
  pin: string,
  ctx: { groupId: string; index: number; threshold: number; total: number;
         profile?: Argon2Profile },
): CardPinShareEnvelope {
  const params = argon2ParamsFor("card_pin", ctx.profile);
  const salt = randomBytes(SALT_LEN);
  const key = argon2id(utf8(pin), salt, params);
  const nonce = randomBytes(NONCE_LEN);
  const aad = aadForShare(ctx.groupId, ctx.index, "card_pin",
                           ctx.threshold, ctx.total);
  const ct = chacha20poly1305(key, nonce, aad).encrypt(shareBytes);
  return {
    index: ctx.index, kind: "card_pin",
    nonce, ciphertext: ct, salt, kdf: kdfParamsStr("card_pin", ctx.profile),
  };
}

function openCardPin(
  env: CardPinShareEnvelope,
  pin: string,
  ctx: { groupId: string; threshold: number; total: number },
): Uint8Array {
  const params = parseKdfParams(env.kdf, "card_pin");
  const key = argon2id(utf8(pin), env.salt, params);
  const aad = aadForShare(ctx.groupId, env.index, "card_pin",
                           ctx.threshold, ctx.total);
  return chacha20poly1305(key, env.nonce, aad).decrypt(env.ciphertext);
}

function sealKyber(
  shareBytes: Uint8Array,
  recipientPk: Uint8Array,
  ctx: { groupId: string; index: number; threshold: number; total: number },
): KyberShareEnvelope {
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(recipientPk);
  const key = kyberKdf(sharedSecret);
  const nonce = randomBytes(NONCE_LEN);
  const aad = aadForShare(ctx.groupId, ctx.index, "kyber_pk",
                           ctx.threshold, ctx.total);
  const ct = chacha20poly1305(key, nonce, aad).encrypt(shareBytes);
  return {
    index: ctx.index, kind: "kyber_pk",
    nonce, ciphertext: ct,
    recipientFp: sha3Fingerprint(recipientPk),
    kemCiphertext: cipherText,
  };
}

function openKyber(
  env: KyberShareEnvelope,
  recipientSk: Uint8Array,
  ctx: { groupId: string; threshold: number; total: number },
): Uint8Array {
  const ss = ml_kem1024.decapsulate(env.kemCiphertext, recipientSk);
  const key = kyberKdf(ss);
  const aad = aadForShare(ctx.groupId, env.index, "kyber_pk",
                           ctx.threshold, ctx.total);
  return chacha20poly1305(key, env.nonce, aad).decrypt(env.ciphertext);
}

function sealPassphrase(
  shareBytes: Uint8Array,
  passphrase: string,
  ctx: { groupId: string; index: number; threshold: number; total: number;
         profile?: Argon2Profile },
): PassphraseShareEnvelope {
  const params = argon2ParamsFor("passphrase", ctx.profile);
  const salt = randomBytes(SALT_LEN);
  const key = argon2id(utf8(passphrase), salt, params);
  const nonce = randomBytes(NONCE_LEN);
  const aad = aadForShare(ctx.groupId, ctx.index, "passphrase",
                           ctx.threshold, ctx.total);
  const ct = chacha20poly1305(key, nonce, aad).encrypt(shareBytes);
  return {
    index: ctx.index, kind: "passphrase",
    nonce, ciphertext: ct, salt, kdf: kdfParamsStr("passphrase", ctx.profile),
  };
}

function openPassphrase(
  env: PassphraseShareEnvelope,
  passphrase: string,
  ctx: { groupId: string; threshold: number; total: number },
): Uint8Array {
  const params = parseKdfParams(env.kdf, "passphrase");
  const key = argon2id(utf8(passphrase), env.salt, params);
  const aad = aadForShare(ctx.groupId, env.index, "passphrase",
                           ctx.threshold, ctx.total);
  return chacha20poly1305(key, env.nonce, aad).decrypt(env.ciphertext);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface SetupRecoveryInput {
  deviceEntropy: Uint8Array;
  cardPin: string;
  contactKyberPk: Uint8Array;     // required for MVP
  cloudPassphrase: string;        // required for MVP
  vaultFpHex: string;
  groupId?: string;
  threshold?: number;
  total?: number;
  randomCoeff?: (pos: number, j: number) => number; // tests only
  now?: () => Date;                                  // tests only
}

function randomGroupId(): string {
  // 32-char hex, matches Python uuid4().hex
  const buf = randomBytes(16);
  return toHex(buf);
}

export function setupRecovery(input: SetupRecoveryInput): RecoveryPackage {
  const {
    deviceEntropy, cardPin, contactKyberPk, cloudPassphrase, vaultFpHex,
    threshold = DEFAULT_THRESHOLD, total = DEFAULT_TOTAL,
  } = input;

  if (!(deviceEntropy instanceof Uint8Array) || deviceEntropy.length === 0)
    throw new Error("deviceEntropy must be non-empty bytes");
  if (threshold !== 2 || total !== 3)
    throw new Error("MVP supports 2-of-3 only");
  if (!cardPin || cardPin.length < 4)
    throw new Error("cardPin must be at least 4 characters");
  if (!contactKyberPk || contactKyberPk.length === 0)
    throw new Error("contactKyberPk is required in MVP");
  if (!cloudPassphrase)
    throw new Error("cloudPassphrase is required in MVP");

  const groupId = input.groupId ?? randomGroupId();
  const now = (input.now ?? (() => new Date()))();
  const createdAt = now.toISOString().replace(/\.\d{3}Z$/, "Z");

  const shares: Share[] = shamirSplit(deviceEntropy, threshold, total,
                                        input.randomCoeff);

  const env1 = sealCardPin(shares[0].bytes, cardPin,
                            { groupId, index: 1, threshold, total });
  const env2 = sealKyber(shares[1].bytes, contactKyberPk,
                          { groupId, index: 2, threshold, total });
  const env3 = sealPassphrase(shares[2].bytes, cloudPassphrase,
                                { groupId, index: 3, threshold, total });

  return {
    schemaVersion: SCHEMA_VERSION,
    groupId, threshold, total,
    vaultFpHex, createdAt,
    shares: [env1, env2, env3],
  };
}

export function recoverEntropy(
  pkg: RecoveryPackage,
  creds: RecoveryCredentials,
): Uint8Array {
  const opened: Share[] = [];
  const errors: string[] = [];
  for (const env of pkg.shares) {
    try {
      let pt: Uint8Array | null = null;
      if (env.kind === "card_pin" && creds.cardPin) {
        pt = openCardPin(env, creds.cardPin, {
          groupId: pkg.groupId,
          threshold: pkg.threshold, total: pkg.total,
        });
      } else if (env.kind === "kyber_pk" && creds.contactKyberSk) {
        pt = openKyber(env, creds.contactKyberSk, {
          groupId: pkg.groupId,
          threshold: pkg.threshold, total: pkg.total,
        });
      } else if (env.kind === "passphrase" && creds.cloudPassphrase) {
        pt = openPassphrase(env, creds.cloudPassphrase, {
          groupId: pkg.groupId,
          threshold: pkg.threshold, total: pkg.total,
        });
      }
      if (pt) {
        opened.push({ index: env.index, bytes: pt });
        if (opened.length >= pkg.threshold) break;
      }
    } catch (e) {
      errors.push(`share #${env.index} (${env.kind}): ${
        e instanceof Error ? e.message : String(e)}`);
    }
  }
  if (opened.length < pkg.threshold)
    throw new Error(
      `could not open enough shares: have ${opened.length}, ` +
        `need ${pkg.threshold}; errors: ${errors.join("; ")}`,
    );
  return shamirCombine(opened);
}

// ---------------------------------------------------------------------------
// Flexible k-of-n API (mirrors Python setup_recovery_flexible)
// ---------------------------------------------------------------------------

export interface ShareConfig {
  kind: ShareKind;
  /** For card_pin / passphrase: the secret string */
  secret?: string;
  /** For kyber_pk: recipient's ML-KEM-1024 public key */
  recipientPk?: Uint8Array;
}

export interface SetupRecoveryFlexibleInput {
  deviceEntropy: Uint8Array;
  shareConfigs: ShareConfig[];
  vaultFpHex: string;
  threshold: number;
  groupId?: string;
  randomCoeff?: (pos: number, j: number) => number;
  now?: () => Date;
}

export function setupRecoveryFlexible(
  input: SetupRecoveryFlexibleInput,
): RecoveryPackage {
  const { deviceEntropy, shareConfigs, vaultFpHex, threshold } = input;

  if (!(deviceEntropy instanceof Uint8Array) || deviceEntropy.length === 0)
    throw new Error("deviceEntropy must be non-empty bytes");
  const total = shareConfigs.length;
  if (total < 2) throw new Error("need at least 2 shares");
  if (threshold < 2) throw new Error("threshold must be at least 2");
  if (threshold > total)
    throw new Error(`threshold (${threshold}) > total (${total})`);

  const groupId = input.groupId ?? randomGroupId();
  const now = (input.now ?? (() => new Date()))();
  const createdAt = now.toISOString().replace(/\.\d{3}Z$/, "Z");

  const rawShares = shamirSplit(deviceEntropy, threshold, total,
                                  input.randomCoeff);

  const sealedShares: ShareEnvelope[] = [];
  for (let i = 0; i < shareConfigs.length; i++) {
    const cfg = shareConfigs[i];
    const shareIndex = i + 1;
    const shareBytes = rawShares[i].bytes;
    const ctx = { groupId, index: shareIndex, threshold, total };

    if (cfg.kind === "card_pin") {
      if (!cfg.secret || cfg.secret.length < 4)
        throw new Error(`share #${shareIndex}: card_pin must be >= 4 chars`);
      sealedShares.push(sealCardPin(shareBytes, cfg.secret, ctx));
    } else if (cfg.kind === "kyber_pk") {
      if (!cfg.recipientPk)
        throw new Error(`share #${shareIndex}: kyber_pk requires recipientPk`);
      sealedShares.push(sealKyber(shareBytes, cfg.recipientPk, ctx));
    } else if (cfg.kind === "passphrase") {
      if (!cfg.secret || cfg.secret.length < 8)
        throw new Error(`share #${shareIndex}: passphrase must be >= 8 chars`);
      sealedShares.push(sealPassphrase(shareBytes, cfg.secret, ctx));
    } else {
      throw new Error(`share #${shareIndex}: unknown kind '${cfg.kind}'`);
    }
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    groupId,
    threshold,
    total,
    vaultFpHex,
    createdAt,
    shares: sealedShares,
  };
}

export interface FlexibleCredentials {
  /** index -> PIN string */
  pins: Map<number, string>;
  /** index -> passphrase string */
  passphrases: Map<number, string>;
  /** index -> Kyber secret key */
  kyberSks: Map<number, Uint8Array>;
}

export function recoverEntropyFlexible(
  pkg: RecoveryPackage,
  creds: FlexibleCredentials,
): Uint8Array {
  const opened: Share[] = [];
  const errors: string[] = [];

  for (const env of pkg.shares) {
    try {
      let pt: Uint8Array | null = null;
      const ctx = { groupId: pkg.groupId, threshold: pkg.threshold, total: pkg.total };

      if (env.kind === "card_pin") {
        const pin = creds.pins.get(env.index);
        if (pin) pt = openCardPin(env, pin, ctx);
      } else if (env.kind === "kyber_pk") {
        const sk = creds.kyberSks.get(env.index);
        if (sk) pt = openKyber(env, sk, ctx);
      } else if (env.kind === "passphrase") {
        const pp = creds.passphrases.get(env.index);
        if (pp) pt = openPassphrase(env, pp, ctx);
      }

      if (pt) {
        opened.push({ index: env.index, bytes: pt });
        if (opened.length >= pkg.threshold) break;
      }
    } catch (e) {
      errors.push(`share #${env.index} (${env.kind}): ${
        e instanceof Error ? e.message : String(e)}`);
    }
  }

  if (opened.length < pkg.threshold)
    throw new Error(
      `could not open enough shares: have ${opened.length}, ` +
        `need ${pkg.threshold}; errors: ${errors.join("; ")}`,
    );
  return shamirCombine(opened);
}
