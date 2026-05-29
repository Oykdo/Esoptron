import { useCallback, useState } from "react";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem";

import {
  packageToJson,
  RecoveryPackage,
  setupRecovery,
} from "../lib/recovery";
import { downloadRecoveryCardPng } from "../lib/recoveryCard";

export interface RecoverySetupResult {
  package: RecoveryPackage;
  contactKyberSk: Uint8Array;
  cardPin: string;
  cloudPassphrase: string;
}

interface Props {
  deviceEntropy: Uint8Array;
  vaultFpHex: string;
  onComplete: (result: RecoverySetupResult) => void;
}

const PIN_MIN = 4;
const PASS_MIN = 12;

export function RecoverySetup({
  deviceEntropy,
  vaultFpHex,
  onComplete,
}: Props) {
  const [pin, setPin] = useState("");
  const [pinConfirm, setPinConfirm] = useState("");
  const [pass, setPass] = useState("");
  const [passConfirm, setPassConfirm] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [computing, setComputing] = useState(false);
  const [pkg, setPkg] = useState<RecoveryPackage | null>(null);
  const [contactSk, setContactSk] = useState<Uint8Array | null>(null);

  const onCreate = useCallback(async () => {
    setErr(null);
    if (pin.length < PIN_MIN) {
      setErr(`PIN must be at least ${PIN_MIN} digits`);
      return;
    }
    if (pin !== pinConfirm) {
      setErr("PIN confirmation does not match");
      return;
    }
    if (pass.length < PASS_MIN) {
      setErr(`cloud passphrase must be at least ${PASS_MIN} characters`);
      return;
    }
    if (pass !== passConfirm) {
      setErr("cloud passphrase confirmation does not match");
      return;
    }

    setComputing(true);
    try {
      // Self-contact for MVP: the device holds both keys until Phase 6
      // lets the user rotate share #2 to a real friend's Kyber pk.
      const kp = ml_kem1024.keygen();
      // Argon2id 64MB + 128MB is heavy on the main thread — yield to
      // the browser so the spinner paints before we block.
      await new Promise((r) => setTimeout(r, 50));
      const built = setupRecovery({
        deviceEntropy,
        cardPin: pin,
        contactKyberPk: kp.publicKey,
        cloudPassphrase: pass,
        vaultFpHex,
      });
      setPkg(built);
      setContactSk(kp.secretKey);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "recovery setup failed");
    } finally {
      setComputing(false);
    }
  }, [pin, pinConfirm, pass, passConfirm, deviceEntropy, vaultFpHex]);

  const [downloadedCard, setDownloadedCard] = useState(false);
  const [downloadedJson, setDownloadedJson] = useState(false);

  const onDownloadCard = useCallback(async () => {
    if (!pkg) return;
    try {
      await downloadRecoveryCardPng(pkg);
      setDownloadedCard(true);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "card render failed");
    }
  }, [pkg]);

  const onDownloadJson = useCallback(() => {
    if (!pkg) return;
    const blob = new Blob(
      [JSON.stringify(packageToJson(pkg), null, 2)],
      { type: "application/json" },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `esoptron-recovery-${pkg.groupId.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setDownloadedJson(true);
  }, [pkg]);

  const onContinue = useCallback(() => {
    if (!pkg || !contactSk) return;
    onComplete({
      package: pkg,
      contactKyberSk: contactSk,
      cardPin: pin,
      cloudPassphrase: pass,
    });
  }, [pkg, contactSk, pin, pass, onComplete]);

  if (!pkg) {
    return (
      <section className="recovery-setup">
        <h2>Holographic Recovery</h2>
        <p>
          Instead of writing down 24 words, your vault is split into 3
          encrypted shares with a 2-of-3 threshold. Any two of them
          recover your vault — losing one is recoverable, losing two
          requires re-enrolling.
        </p>
        <ol>
          <li>
            <strong>Card PIN</strong> — short secret you remember.
            Protects share #1 (the printable recovery card).
          </li>
          <li>
            <strong>Cloud passphrase</strong> — long secret you keep
            anywhere offline. Protects share #3 (the file backup).
          </li>
          <li>
            <strong>Contact</strong> — share #2 is encrypted for a
            future trusted contact (ML-KEM-1024). For now the device
            holds the contact key itself; this share is dormant until
            you rotate it to a real friend in a future release.
          </li>
        </ol>

        {err && <div className="error">{err}</div>}

        <div className="form">
          <label>
            Card PIN ({PIN_MIN}+ digits)
            <input
              type="password"
              inputMode="numeric"
              autoComplete="new-password"
              value={pin}
              onChange={(e) => setPin(e.target.value)}
              disabled={computing}
            />
          </label>
          <label>
            Confirm card PIN
            <input
              type="password"
              inputMode="numeric"
              autoComplete="new-password"
              value={pinConfirm}
              onChange={(e) => setPinConfirm(e.target.value)}
              disabled={computing}
            />
          </label>
          <label>
            Cloud passphrase ({PASS_MIN}+ chars)
            <input
              type="password"
              autoComplete="new-password"
              value={pass}
              onChange={(e) => setPass(e.target.value)}
              disabled={computing}
            />
          </label>
          <label>
            Confirm cloud passphrase
            <input
              type="password"
              autoComplete="new-password"
              value={passConfirm}
              onChange={(e) => setPassConfirm(e.target.value)}
              disabled={computing}
            />
          </label>
        </div>

        <button
          className="primary"
          onClick={onCreate}
          disabled={computing}
        >
          {computing ? "Deriving keys (Argon2id, ~30 s)…" : "Create recovery package"}
        </button>
        {computing && (
          <p className="hint">
            Two Argon2id derivations run on this device: one 64 MB / 3
            iterations for the PIN share, one 128 MB / 4 iterations for
            the cloud share. The slower it is, the harder it is for an
            attacker to brute-force your PIN.
          </p>
        )}
      </section>
    );
  }

  // Package ready — offer download + continue.
  return (
    <section className="recovery-setup ready">
      <h2>Recovery package ready</h2>
      <p>
        Your vault is split. The file below carries the 3 sealed shares
        and matches your local enrollment via group{" "}
        <code>{pkg.groupId.slice(0, 8)}…</code>.
      </p>
      <dl>
        <dt>Schema</dt>
        <dd>v{pkg.schemaVersion}</dd>
        <dt>Threshold</dt>
        <dd>{pkg.threshold} of {pkg.total}</dd>
        <dt>Shares</dt>
        <dd>{pkg.shares.map((s) => s.kind).join(", ")}</dd>
        <dt>Created</dt>
        <dd>{pkg.createdAt}</dd>
      </dl>
      <p className="warn">
        <strong>Save this card to several places</strong> — print the
        PNG on physical paper, archive the JSON offline, mail it to
        yourself. Without 2 of the 3 shares plus the matching
        credentials, no one can recover your vault, not even us.
      </p>
      <button className="primary" onClick={onDownloadCard}>
        {downloadedCard ? "Card downloaded ✓ — download again"
                          : "Download recovery card (PNG, printable)"}
      </button>
      <button onClick={onDownloadJson}>
        {downloadedJson ? "JSON downloaded ✓ — download again"
                          : "Download recovery package (JSON, full 3 shares)"}
      </button>
      <button
        className={downloadedCard || downloadedJson ? "primary" : ""}
        onClick={onContinue}
        disabled={!(downloadedCard || downloadedJson)}
      >
        I have saved it — continue
      </button>
    </section>
  );
}
