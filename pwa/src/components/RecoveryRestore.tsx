import { useCallback, useState } from "react";

import { fromHex } from "../lib/crypto";
import {
  packageFromJson,
  recoverEntropy,
  RecoveryPackage,
} from "../lib/recovery";

export interface RecoveryRestoreResult {
  deviceEntropy: Uint8Array;
  vaultFpHex: string;
  groupId: string;
}

interface Props {
  onRecovered: (r: RecoveryRestoreResult) => void;
  onCancel: () => void;
  lang: "fr" | "en";
}

type Step = "load" | "credentials" | "recovering" | "done";

export function RecoveryRestore({ onRecovered, onCancel, lang }: Props) {
  const t = (fr: string, en: string) => (lang === "fr" ? fr : en);
  const [step, setStep] = useState<Step>("load");
  const [pkg, setPkg] = useState<RecoveryPackage | null>(null);
  const [pin, setPin] = useState("");
  const [pass, setPass] = useState("");
  const [contactSkHex, setContactSkHex] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const onFile = useCallback(async (file: File) => {
    setErr(null);
    try {
      const text = await file.text();
      const json = JSON.parse(text);
      const built = packageFromJson(json);
      setPkg(built);
      setStep("credentials");
    } catch (e) {
      setErr(
        t("paquet de récupération invalide", "invalid recovery package") +
          (e instanceof Error ? `: ${e.message}` : ""),
      );
    }
  }, [lang]);

  const onSubmit = useCallback(async () => {
    if (!pkg) return;
    setErr(null);
    const provided = (pin ? 1 : 0) + (pass ? 1 : 0) + (contactSkHex ? 1 : 0);
    if (provided < pkg.threshold) {
      setErr(
        t(
          `fournissez au moins ${pkg.threshold} identifiants`,
          `provide at least ${pkg.threshold} credentials`,
        ),
      );
      return;
    }
    setStep("recovering");
    try {
      // Yield so the UI shows the spinner before Argon2id blocks.
      await new Promise((r) => setTimeout(r, 50));
      let sk: Uint8Array | undefined;
      if (contactSkHex) {
        try {
          sk = fromHex(contactSkHex.trim());
        } catch {
          throw new Error(
            t("la clé Kyber n'est pas un hex valide", "contact_sk_hex is not valid hex"),
          );
        }
      }
      const entropy = recoverEntropy(pkg, {
        cardPin: pin || undefined,
        cloudPassphrase: pass || undefined,
        contactKyberSk: sk,
      });
      setStep("done");
      onRecovered({
        deviceEntropy: entropy,
        vaultFpHex: pkg.vaultFpHex,
        groupId: pkg.groupId,
      });
    } catch (e) {
      setErr(e instanceof Error ? e.message : t("échec de la récupération", "recovery failed"));
      setStep("credentials");
    }
  }, [pkg, pin, pass, contactSkHex, onRecovered, lang]);

  return (
    <section className="recovery-restore">
      <h2>{t("Restaurer depuis une sauvegarde", "Restore from backup")}</h2>

      {err && <div className="error">{err}</div>}

      {step === "load" && (
        <>
          <p className="muted">
            {t(
              "Chargez le paquet de récupération (JSON) créé à la configuration. Il contient 3 parts scellées — 2 suffisent, avec leurs identifiants, pour restaurer votre coffre.",
              "Upload your recovery package (JSON). It holds 3 sealed shares — any 2, with their credentials, restore your vault.",
            )}
          </p>
          <label className="filepicker">
            <input
              type="file"
              accept="application/json,.json"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void onFile(f);
              }}
            />
            <span>{t("Choisir le JSON de récupération…", "Choose recovery JSON…")}</span>
          </label>
          <button className="link" onClick={onCancel}>
            {t("Annuler", "Cancel")}
          </button>
        </>
      )}

      {step === "credentials" && pkg && (
        <>
          <p className="muted">
            {t("Fournissez n'importe quels ", "Provide any ")}
            <strong>{pkg.threshold}</strong>
            {t(
              " identifiants parmi les 3. Laissez vide ce que vous n'avez pas — Argon2id est lent (~10 s par identifiant).",
              " of the 3 credentials. Leave blank what you don't have — Argon2id is slow (~10 s each).",
            )}
          </p>
          <dl className="meta">
            <dt>{t("Coffre", "Vault")}</dt>
            <dd>{pkg.vaultFpHex.slice(0, 16)}…</dd>
            <dt>{t("Groupe", "Group")}</dt>
            <dd>{pkg.groupId.slice(0, 16)}…</dd>
            <dt>{t("Seuil", "Threshold")}</dt>
            <dd>
              {pkg.threshold} {t("sur", "of")} {pkg.total}
            </dd>
          </dl>
          <div className="form">
            <label>
              {t("PIN de la carte", "Card PIN")}
              <input
                type="password"
                inputMode="numeric"
                autoComplete="off"
                value={pin}
                onChange={(e) => setPin(e.target.value)}
                placeholder={t("depuis la carte de récupération", "from the recovery card")}
              />
            </label>
            <label>
              {t("Passphrase cloud", "Cloud passphrase")}
              <input
                type="password"
                autoComplete="off"
                value={pass}
                onChange={(e) => setPass(e.target.value)}
                placeholder={t("depuis la sauvegarde JSON", "from the JSON backup")}
              />
            </label>
            <label>
              {t("Clé Kyber d'un contact (hex, optionnel)", "Contact Kyber sk (hex, optional)")}
              <input
                type="password"
                autoComplete="off"
                value={contactSkHex}
                onChange={(e) => setContactSkHex(e.target.value)}
                placeholder={t("3168 caractères hex (collez depuis le contact)", "3168 hex chars (paste from contact)")}
              />
            </label>
          </div>
          <button className="primary" onClick={onSubmit}>
            {t("Récupérer l'entropie", "Recover device entropy")}
          </button>
          <button className="link" onClick={onCancel}>
            {t("Annuler", "Cancel")}
          </button>
        </>
      )}

      {step === "recovering" && (
        <p className="muted">
          {t("Dérivation des clés et recombinaison des parts…", "Deriving keys and combining shares…")}
        </p>
      )}

      {step === "done" && pkg && (
        <p>
          {t("Restauré.", "Recovered.")} {t("Coffre", "Vault")}{" "}
          <code>{pkg.vaultFpHex.slice(0, 16)}…</code>
          {t(
            " — ressaisissez la passphrase locale pour continuer.",
            " — re-enter the local passphrase to resume.",
          )}
        </p>
      )}
    </section>
  );
}
