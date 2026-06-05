import { useCallback, useEffect, useState } from "react";
import { CameraScanner } from "./components/CameraScanner";
import { RecoverySetup, RecoverySetupResult } from "./components/RecoverySetup";
import { RecoveryRestore, RecoveryRestoreResult } from "./components/RecoveryRestore";
import { RelicsGallery } from "./components/RelicsGallery";
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
  | "codex"
  | "error";

const api = new EsoptronApi();

type Lang = "fr" | "en";

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
  const [lang, setLang] = useState<Lang>(
    () => (localStorage.getItem("eopx_lang") as Lang) || "fr",
  );
  const t = (fr: string, en: string) => (lang === "fr" ? fr : en);

  useEffect(() => {
    localStorage.setItem("eopx_lang", lang);
  }, [lang]);

  useEffect(() => {
    void (async () => {
      try {
        await api.health();
      } catch {
        setPhase("error");
        setErrMsg(t("Esoptron est injoignable pour le moment.",
          "Can't reach Esoptron right now."));
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
        <button
          className="link lang-toggle header-lang"
          onClick={() => setLang(lang === "fr" ? "en" : "fr")}
        >
          {lang === "fr" ? "EN" : "FR"}
        </button>
        <h1><span className="brand-dot" aria-hidden="true" />Esoptron</h1>
        <p className="subtitle">
          {t("Votre coffre, en image vivante.", "Your vault, as a living image.")}
        </p>
      </header>

      {errMsg && <div className="error banner">{errMsg}</div>}

      {phase === "loading" && (
        <p className="muted">{t("Connexion…", "Connecting…")}</p>
      )}

      {phase === "welcome" && (
        <section className="welcome">
          <p className="lead">
            {t("Votre coffre, en image.", "Your vault, as an image.")}
          </p>
          <p className="muted">
            {t("Esoptron transforme l'identité d'un coffre en carte Metatron scannable, signée post-quantique.",
              "Esoptron turns a vault identity into a scannable, post-quantum-signed Metatron card.")}
          </p>

          <details className="how">
            <summary>{t("Comment ça marche", "How it works")}</summary>
            <ol>
              <li>
                {t("Votre coffre Eidolon (.psnx + .blend_data) est la racine — votre vraie identité.",
                  "Your Eidolon vault (.psnx + .blend_data) is the root — your real identity.")}
              </li>
              <li>
                {t("Esoptron en fait un badge : la carte Metatron, vérifiable hors-ligne.",
                  "Esoptron makes it a badge: the Metatron card, verifiable offline.")}
              </li>
              <li>
                {t("Ici, vous scannez, vérifiez, et explorez le Codex et votre œuf.",
                  "Here you scan, verify, and explore the Codex and your egg.")}
              </li>
            </ol>
            <p className="muted how-note">
              {t("Pas encore de coffre Eidolon ? Scannez une carte pour créer une identité autonome.",
                "No Eidolon vault yet? Scan a card to create a standalone identity.")}
            </p>
          </details>

          <button className="primary" onClick={() => setPhase("scan")}>
            {t("Scanner une carte", "Scan a card")}
          </button>
          <button onClick={() => setPhase("restore")}>
            {t("Restaurer depuis un paquet", "Restore from a package")}
          </button>
          <button className="link" onClick={() => setPhase("codex")}>
            {t("✦ Explorer le Codex", "✦ Explore the Codex")}
          </button>
        </section>
      )}

      {phase === "codex" && (
        <RelicsGallery
          api={api}
          lang={lang}
          onLangChange={setLang}
          onBack={() => setPhase(stored ? "ready" : "welcome")}
          deviceSecretHex={stored?.device_secret_hex}
        />
      )}

      {phase === "restore" && (
        <RecoveryRestore
          lang={lang}
          onRecovered={onRestoreRecovered}
          onCancel={() => setPhase("welcome")}
        />
      )}

      {phase === "restore-rescan" && (
        <section>
          <h2>{t("Re-scannez votre carte", "Re-scan your card")}</h2>
          <p className="muted">
            {t("Vos parts de récupération sont reconstituées. Présentez votre carte Metatron pour re-dériver votre enrôlement, en local.",
              "Recovery shares reconstructed. Point the camera at your Metatron card to re-derive your enrollment locally.")}
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
          <h2>{t("Déverrouiller", "Unlock")}</h2>
          <p className="muted">{t("Entrez votre passphrase.", "Enter your passphrase.")}</p>
          <input
            type="password"
            value={unlockPassphrase}
            onChange={(e) => setUnlockPassphrase(e.target.value)}
            placeholder={t("passphrase", "passphrase")}
          />
          <button className="primary" onClick={onUnlockSubmit}>
            {t("Déverrouiller", "Unlock")}
          </button>
          <button className="link" onClick={onReset}>
            {t("Réinitialiser (perdre cet enrôlement)", "Reset (lose this enrollment)")}
          </button>
        </section>
      )}

      {phase === "scan" && (
        <section>
          <h2>{t("Scanner une carte Metatron", "Scan a Metatron card")}</h2>
          <CameraScanner
            onCapture={onCapture}
            onBack={() => setPhase("welcome")}
          />
        </section>
      )}

      {phase === "scanning" && (
        <section>
          <h2>{t("Lecture…", "Reading…")}</h2>
          <p className="muted">
            {t("Décodage des symboles, dérivation sur votre appareil.",
              "Decoding the symbols, deriving on your device.")}
          </p>
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
          <h2>{t("Verrouiller cet appareil", "Lock this device")}</h2>
          <p className="muted">
            {t("Une passphrase pour chiffrer votre enrôlement ici — indépendante de votre récupération.",
              "A passphrase to encrypt your enrollment here — separate from your recovery.")}
          </p>
          <input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder={t("passphrase (≥ 8 caractères)", "passphrase (≥ 8 chars)")}
          />
          <input
            type="password"
            value={passphraseConfirm}
            onChange={(e) => setPassphraseConfirm(e.target.value)}
            placeholder={t("confirmer la passphrase", "confirm passphrase")}
          />
          <button className="primary" onClick={onPassphraseSubmit}>
            {t("Enregistrer", "Save")}
          </button>
        </section>
      )}

      {phase === "ready" && stored && (
        <section className="ready">
          <h2>{t("Enrôlé", "Enrolled")}</h2>
          <dl>
            <dt>{t("Coffre", "Vault")}</dt>
            <dd>{stored.vault_fp_hex.slice(0, 16)}…</dd>
            <dt>{t("Enrôlement", "Enrollment")}</dt>
            <dd>{stored.enrollment_fp_hex.slice(0, 16)}…</dd>
            <dt>{t("Étiquette", "Public tag")}</dt>
            <dd>{stored.public_tag_hex}</dd>
            <dt>{t("Créé le", "Created")}</dt>
            <dd>{stored.created_at}</dd>
            {stored.recovery_group_id && (
              <>
                <dt>{t("Groupe de récup.", "Recovery group")}</dt>
                <dd>{stored.recovery_group_id.slice(0, 16)}…</dd>
              </>
            )}
          </dl>
          <button className="secondary" onClick={() => setPhase("codex")}>
            {t("✦ Explorer le Codex", "✦ Explore the Codex")}
          </button>
          <button className="link" onClick={onReset}>
            {t("Se déconnecter et effacer l'enrôlement", "Sign out and wipe enrollment")}
          </button>
        </section>
      )}

      {phase === "error" && (
        <section>
          <h2>{t("Esoptron est injoignable", "Can't reach Esoptron")}</h2>
          <p className="muted">
            {t("Le service ne répond pas. Vérifiez votre connexion et rechargez.",
              "The service isn't responding. Check your connection and reload.")}
          </p>
        </section>
      )}
    </div>
  );
}
