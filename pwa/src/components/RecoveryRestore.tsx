import { useCallback, useState } from "react";

import { fromHex, toHex } from "../lib/crypto";
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
}

type Step = "load" | "credentials" | "recovering" | "done";

export function RecoveryRestore({ onRecovered, onCancel }: Props) {
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
      setErr(e instanceof Error
        ? `invalid recovery package: ${e.message}`
        : "could not parse file");
    }
  }, []);

  const onSubmit = useCallback(async () => {
    if (!pkg) return;
    setErr(null);
    const provided =
      (pin ? 1 : 0) +
      (pass ? 1 : 0) +
      (contactSkHex ? 1 : 0);
    if (provided < pkg.threshold) {
      setErr(`provide at least ${pkg.threshold} credentials`);
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
          throw new Error("contact_sk_hex is not valid hex");
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
      setErr(e instanceof Error ? e.message : "recovery failed");
      setStep("credentials");
    }
  }, [pkg, pin, pass, contactSkHex, onRecovered]);

  return (
    <section className="recovery-restore">
      <h2>Recover from backup</h2>

      {err && <div className="error">{err}</div>}

      {step === "load" && (
        <>
          <p>
            Upload the recovery package JSON you saved at setup. The
            file holds 3 sealed shares — you only need any 2 of them
            plus the matching credentials to recover your vault.
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
            <span>Choose recovery JSON…</span>
          </label>
          <button className="link" onClick={onCancel}>
            Cancel
          </button>
        </>
      )}

      {step === "credentials" && pkg && (
        <>
          <p>
            Provide any <strong>{pkg.threshold}</strong> of the 3
            credentials below. Leave a field blank if you do not have
            that share. Argon2id derivations are slow — expect ~10 s
            per credential.
          </p>
          <dl className="meta">
            <dt>Vault</dt>
            <dd>{pkg.vaultFpHex.slice(0, 16)}…</dd>
            <dt>Group</dt>
            <dd>{pkg.groupId.slice(0, 16)}…</dd>
            <dt>Threshold</dt>
            <dd>{pkg.threshold} of {pkg.total}</dd>
          </dl>
          <div className="form">
            <label>
              Card PIN
              <input
                type="password"
                inputMode="numeric"
                autoComplete="off"
                value={pin}
                onChange={(e) => setPin(e.target.value)}
                placeholder="from the recovery card"
              />
            </label>
            <label>
              Cloud passphrase
              <input
                type="password"
                autoComplete="off"
                value={pass}
                onChange={(e) => setPass(e.target.value)}
                placeholder="from the JSON backup"
              />
            </label>
            <label>
              Contact Kyber sk (hex, optional)
              <input
                type="password"
                autoComplete="off"
                value={contactSkHex}
                onChange={(e) => setContactSkHex(e.target.value)}
                placeholder="3168 hex chars (paste from contact)"
              />
            </label>
          </div>
          <button className="primary" onClick={onSubmit}>
            Recover device entropy
          </button>
          <button className="link" onClick={onCancel}>
            Cancel
          </button>
        </>
      )}

      {step === "recovering" && (
        <p>Deriving keys and combining shares…</p>
      )}

      {step === "done" && pkg && (
        <p>
          Recovered. Vault <code>{toHex(new Uint8Array(0))}</code>
          {pkg.vaultFpHex.slice(0, 16)}… — re-enter the local
          passphrase to resume.
        </p>
      )}
    </section>
  );
}
