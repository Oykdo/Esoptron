import { useCallback, useEffect, useState } from "react";
import { CameraScanner } from "./components/CameraScanner";
import { RecoverySetup, RecoverySetupResult } from "./components/RecoverySetup";
import { RecoveryRestore, RecoveryRestoreResult } from "./components/RecoveryRestore";
import { EsoptronApi, EsoptronApiError } from "./lib/api";
import { enrollFromCard, toHexRecord } from "./lib/enrollment";
import { toHex } from "./lib/crypto";
import {
  clearStoredEnrollment,
  hasStoredEnrollment,
  loadEnrollment,
  storeEnrollment,
  StoredEnrollment,
} from "./lib/storage";

type Phase =
  | "loading"
  | "welcome"
  | "unlock"
  | "scan"
  | "scanning"
  | "recovery"
  | "restore"
  | "restore-rescan"
  | "passphrase"
  | "ready"
  | "error";

const api = new EsoptronApi();

interface EnrollmentSession {
  symbols: number[];
  cardFingerprintHex: string;
  deviceEntropy: Uint8Array;
  enrollmentHex: ReturnType<typeof toHexRecord>;
}

function randomEntropy(): Uint8Array {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return buf;
}

export default function App() {
  const [phase, setPhase] = useState<Phase>("loading");
  const [passphrase, setPassphrase] = useState("");
  const [passphraseConfirm, setPassphraseConfirm] = useState("");
  const [unlockPassphrase, setUnlockPassphrase] = useState("");
  const [errMsg, setErrMsg] = useState<string | null>(null);
  const [session, setSession] = useState<EnrollmentSession | null>(null);
  const [recovery, setRecovery] = useState<RecoverySetupResult | null>(null);
  const [restored, setRestored] = useState<RecoveryRestoreResult | null>(null);
  const [stored, setStored] = useState<StoredEnrollment | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        await api.health();
      } catch {
        setPhase("error");
        setErrMsg("Backend API unreachable. Start the server first.");
        return;
      }
      const has = await hasStoredEnrollment();
      setPhase(has ? "unlock" : "welcome");
    })();
  }, []);

  const onCapture = useCallback(async (blob: Blob) => {
    setPhase("scanning");
    setErrMsg(null);
    try {
      const ex = await api.extract(blob);
      if (!ex.success || !ex.symbols || !ex.card_fingerprint_hex) {
        setErrMsg(ex.errors.join("; ") || "scan failed");
        setPhase(restored ? "restore-rescan" : "scan");
        return;
      }
      // Two paths:
      //  - restore-rescan: device_entropy already recovered from package;
      //    we reuse it to reproduce the enrollment from the freshly
      //    scanned card.
      //  - fresh enroll: generate new entropy.
      const deviceEntropy = restored ? restored.deviceEntropy : randomEntropy();
      const rec = enrollFromCard(ex.symbols, deviceEntropy);
      const hex = toHexRecord(rec);

      if (restored && hex.vault_fp_hex !== restored.vaultFpHex) {
        setErrMsg(
          "Card does not match the recovery package. Expected vault " +
          restored.vaultFpHex.slice(0, 16) + "…",
        );
        setPhase("restore-rescan");
        return;
      }

      setSession({
        symbols: ex.symbols,
        cardFingerprintHex: ex.card_fingerprint_hex,
        deviceEntropy,
        enrollmentHex: hex,
      });
      // Recovered enrollment skips RecoverySetup (already configured)
      // and goes straight to local-store passphrase.
      setPhase(restored ? "passphrase" : "recovery");
    } catch (e) {
      const msg =
        e instanceof EsoptronApiError
          ? `API ${e.status}: ${e.message}`
          : e instanceof Error
            ? e.message
            : "scan request failed";
      setErrMsg(msg);
      setPhase("scan");
    }
  }, []);

  const onRecoveryComplete = useCallback((result: RecoverySetupResult) => {
    setRecovery(result);
    setPhase("passphrase");
  }, []);

  const onPassphraseSubmit = useCallback(async () => {
    if (!session) return;
    if (passphrase.length < 8) {
      setErrMsg("passphrase must be at least 8 characters");
      return;
    }
    if (passphrase !== passphraseConfirm) {
      setErrMsg("passphrases do not match");
      return;
    }
    // Fresh enrollment requires the recovery slot; restore-flow reuses
    // whatever metadata we could rebuild from the package (no new
    // self-contact sk; the user must rotate later).
    if (!recovery && !restored) return;
    const record: StoredEnrollment = {
      vault_fp_hex: session.enrollmentHex.vault_fp_hex,
      enrollment_fp_hex: session.enrollmentHex.enrollment_fp_hex,
      public_tag_hex: session.enrollmentHex.public_tag_hex,
      device_secret_hex: session.enrollmentHex.device_secret_hex,
      contact_kyber_sk_hex: recovery
        ? toHex(recovery.contactKyberSk)
        : undefined,
      recovery_group_id: recovery
        ? recovery.package.groupId
        : restored?.groupId,
      created_at: new Date().toISOString(),
    };
    await storeEnrollment(record, passphrase);
    setStored(record);
    setPhase("ready");
    setErrMsg(null);
  }, [passphrase, passphraseConfirm, session, recovery, restored]);

  const onUnlockSubmit = useCallback(async () => {
    try {
      const rec = await loadEnrollment(unlockPassphrase);
      if (!rec) {
        setErrMsg("no enrollment found");
        return;
      }
      setStored(rec);
      setPhase("ready");
      setErrMsg(null);
    } catch (e) {
      setErrMsg(e instanceof Error ? e.message : "unlock failed");
    }
  }, [unlockPassphrase]);

  const onReset = useCallback(async () => {
    await clearStoredEnrollment();
    setStored(null);
    setSession(null);
    setRecovery(null);
    setRestored(null);
    setPassphrase("");
    setPassphraseConfirm("");
    setUnlockPassphrase("");
    setPhase("welcome");
  }, []);

  const onRestoreRecovered = useCallback((r: RecoveryRestoreResult) => {
    setRestored(r);
    setPhase("restore-rescan");
  }, []);

  return (
    <div className="app">
      <header>
        <h1>Esoptron</h1>
        <p className="subtitle">Visual Vault Identity — Holographic Recovery</p>
      </header>

      {errMsg && <div className="error banner">{errMsg}</div>}

      {phase === "loading" && <p>Connecting to backend…</p>}

      {phase === "welcome" && (
        <section className="welcome">
          <h2>Welcome</h2>
          <p>
            Point your camera at a Metatron card to enroll. After
            scanning, your vault will be split into 3 encrypted shares
            with a 2-of-3 threshold — no 24-word phrase to write down,
            no single point of failure.
          </p>
          <button className="primary" onClick={() => setPhase("scan")}>
            New enrollment — scan a card
          </button>
          <button onClick={() => setPhase("restore")}>
            Restore — I have a recovery package
          </button>
        </section>
      )}

      {phase === "restore" && (
        <RecoveryRestore
          onRecovered={onRestoreRecovered}
          onCancel={() => setPhase("welcome")}
        />
      )}

      {phase === "restore-rescan" && (
        <section>
          <h2>Re-scan your card</h2>
          <p>
            Recovery shares are reconstructed. Now point the camera at
            your Metatron card so we can re-derive your enrollment
            locally.
          </p>
          <CameraScanner
            onCapture={onCapture}
            onBack={() => {
              setRestored(null);
              setPhase("restore");
            }}
          />
        </section>
      )}

      {phase === "unlock" && (
        <section>
          <h2>Unlock</h2>
          <p>Enter the passphrase you set when you enrolled.</p>
          <input
            type="password"
            value={unlockPassphrase}
            onChange={(e) => setUnlockPassphrase(e.target.value)}
            placeholder="passphrase"
          />
          <button className="primary" onClick={onUnlockSubmit}>
            Unlock
          </button>
          <button className="link" onClick={onReset}>
            Reset (lose this enrollment)
          </button>
        </section>
      )}

      {phase === "scan" && (
        <section>
          <h2>Scan a Metatron card</h2>
          <CameraScanner
            onCapture={onCapture}
            onBack={() => setPhase("welcome")}
          />
        </section>
      )}

      {phase === "scanning" && (
        <section>
          <h2>Decoding…</h2>
          <p>Extracting symbols, then deriving locally.</p>
        </section>
      )}

      {phase === "recovery" && session && (
        <RecoverySetup
          deviceEntropy={session.deviceEntropy}
          vaultFpHex={session.enrollmentHex.vault_fp_hex}
          onComplete={onRecoveryComplete}
        />
      )}

      {phase === "passphrase" && (
        <section>
          <h2>Protect your local store</h2>
          <p>
            This passphrase encrypts the local enrollment on this device
            (IndexedDB, AES-GCM). It is independent from the recovery
            credentials {restored ? "you just used" : "you just set up"}.
          </p>
          <input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="passphrase (≥ 8 chars)"
          />
          <input
            type="password"
            value={passphraseConfirm}
            onChange={(e) => setPassphraseConfirm(e.target.value)}
            placeholder="confirm passphrase"
          />
          <button className="primary" onClick={onPassphraseSubmit}>
            Save
          </button>
        </section>
      )}

      {phase === "ready" && stored && (
        <section className="ready">
          <h2>Enrolled</h2>
          <dl>
            <dt>Vault</dt>
            <dd>{stored.vault_fp_hex.slice(0, 16)}…</dd>
            <dt>Enrollment</dt>
            <dd>{stored.enrollment_fp_hex.slice(0, 16)}…</dd>
            <dt>Public tag</dt>
            <dd>{stored.public_tag_hex}</dd>
            <dt>Created</dt>
            <dd>{stored.created_at}</dd>
            {stored.recovery_group_id && (
              <>
                <dt>Recovery group</dt>
                <dd>{stored.recovery_group_id.slice(0, 16)}…</dd>
              </>
            )}
          </dl>
          <button className="link" onClick={onReset}>
            Sign out and wipe enrollment
          </button>
        </section>
      )}

      {phase === "error" && (
        <section>
          <h2>Backend unreachable</h2>
          <p>
            Start the Esoptron API with{" "}
            <code>py scripts/serve_pwa_api.py --cors http://localhost:5173</code>{" "}
            and reload this page.
          </p>
        </section>
      )}
    </div>
  );
}
