import { useCallback, useState } from "react";
import { CameraScanner } from "./CameraScanner";
import { CodexRelicDTO, EsoptronApi, EsoptronApiError } from "../lib/api";
import { deriveController, fromHex, makeClaimProof, toHex } from "../lib/voucher";
import { storeRelicClaim } from "../lib/storage";

interface Props {
  api: EsoptronApi;
  relics: CodexRelicDTO[];
  deviceSecretHex: string;
  lang: "en" | "fr";
  onClaimed: (key: string) => void;
  onCancel: () => void;
}

type Phase =
  | "scan"
  | "scanning"
  | "identified"
  | "claiming"
  | "done"
  | "error";

/**
 * The claim flow: scan a huntable relic's A4 sheet → identify the relic by
 * its card fingerprint → enter the printed claim secret → derive this vault's
 * controller and sign a ClaimProof → first valid claim wins at the anchor.
 */
export function ClaimRelic({
  api,
  relics,
  deviceSecretHex,
  lang,
  onClaimed,
  onCancel,
}: Props) {
  const [phase, setPhase] = useState<Phase>("scan");
  const [relic, setRelic] = useState<CodexRelicDTO | null>(null);
  const [secret, setSecret] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const t = (fr: string, en: string) => (lang === "fr" ? fr : en);

  const onCapture = useCallback(
    async (blob: Blob) => {
      setPhase("scanning");
      setErr(null);
      try {
        const ex = await api.extract(blob);
        if (!ex.success || !ex.card_fingerprint_hex) {
          setErr(ex.errors.join("; ") || t("scan échoué", "scan failed"));
          setPhase("scan");
          return;
        }
        const match = relics.find(
          (r) => r.card_fingerprint_hex === ex.card_fingerprint_hex,
        );
        if (!match || !match.artifact_id_hex) {
          setErr(
            t(
              "Carte non reconnue parmi les reliques du Codex.",
              "Card not recognised among the Codex relics.",
            ),
          );
          setPhase("scan");
          return;
        }
        setRelic(match);
        setPhase("identified");
      } catch (e) {
        setErr(
          e instanceof EsoptronApiError
            ? `API ${e.status}: ${e.message}`
            : e instanceof Error
              ? e.message
              : "scan error",
        );
        setPhase("scan");
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [api, relics, lang],
  );

  const onClaim = useCallback(async () => {
    if (!relic || !relic.artifact_id_hex) return;
    const cleaned = secret.replace(/\s+/g, "").toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(cleaned)) {
      setErr(
        t(
          "Le secret de claim doit faire 64 caractères hexadécimaux (32 octets).",
          "The claim secret must be 64 hex characters (32 bytes).",
        ),
      );
      return;
    }
    setPhase("claiming");
    setErr(null);
    try {
      const artifactId = fromHex(relic.artifact_id_hex);
      const controller = deriveController(fromHex(deviceSecretHex), artifactId);
      const proof = makeClaimProof(controller, artifactId, fromHex(cleaned));
      await api.claimRelic(relic.artifact_id_hex, proof);
      storeRelicClaim({
        key: relic.key,
        artifact_id_hex: relic.artifact_id_hex,
        controller_pub_hex: toHex(controller.dilithiumPub),
        claimed_at: new Date().toISOString(),
      });
      setPhase("done");
      onClaimed(relic.key);
    } catch (e) {
      // 409 = someone claimed first; 400 = wrong secret / not huntable.
      setErr(
        e instanceof EsoptronApiError
          ? e.status === 409
            ? t("Déjà réclamée — quelqu'un t'a devancé.", "Already claimed — someone beat you to it.")
            : `API ${e.status}: ${e.message}`
          : e instanceof Error
            ? e.message
            : "claim error",
      );
      setPhase("identified");
    }
  }, [relic, secret, deviceSecretHex, api, onClaimed, lang]);

  return (
    <section className="claim-relic">
      <h2>{t("Réclamer une relique", "Claim a relic")}</h2>
      {err && <div className="error">{err}</div>}

      {(phase === "scan" || phase === "scanning") && (
        <>
          <p className="small">
            {t(
              "Scanne la feuille A4 d'une relique pour l'identifier.",
              "Scan a relic's A4 sheet to identify it.",
            )}
          </p>
          {phase === "scanning" ? (
            <p>{t("Identification…", "Identifying…")}</p>
          ) : (
            <CameraScanner onCapture={onCapture} onBack={onCancel} />
          )}
        </>
      )}

      {(phase === "identified" || phase === "claiming") && relic && (
        <>
          <div className="claim-identified">
            <span className="relic-name">{relic.name}</span>
            <span className="relic-sub">
              {relic.title} · {relic.element}
            </span>
          </div>
          <p className="small">
            {t(
              "Saisis le SECRET DE CLAIM imprimé sur la feuille (sous le cache).",
              "Enter the CLAIM SECRET printed on the sheet (under the cover).",
            )}
          </p>
          <input
            type="text"
            value={secret}
            spellCheck={false}
            onChange={(e) => setSecret(e.target.value)}
            placeholder={t("secret (64 hex)", "secret (64 hex)")}
          />
          <button
            className="primary"
            disabled={phase === "claiming"}
            onClick={onClaim}
          >
            {phase === "claiming"
              ? t("Réclamation…", "Claiming…")
              : t("✦ Réclamer", "✦ Claim")}
          </button>
          <button className="link" onClick={onCancel}>
            {t("Annuler", "Cancel")}
          </button>
        </>
      )}

      {phase === "done" && relic && (
        <div className="claim-done">
          <p>
            {t("Relique réclamée :", "Relic claimed:")} <b>{relic.name}</b> ✦
          </p>
          <button className="secondary" onClick={onCancel}>
            {t("Retour au Codex", "Back to the Codex")}
          </button>
        </div>
      )}
    </section>
  );
}
