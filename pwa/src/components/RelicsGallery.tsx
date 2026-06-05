import { useEffect, useState } from "react";
import {
  CodexManifestDTO,
  CodexRelicDTO,
  EsoptronApi,
  EsoptronApiError,
} from "../lib/api";
import { loadRelicClaims } from "../lib/storage";
import { RelicCanvas } from "./RelicCanvas";
import { ClaimRelic } from "./ClaimRelic";
import { EggGate } from "./EggGate";
import { RelicGlyph } from "./RelicGlyph";

interface Props {
  api: EsoptronApi;
  onBack: () => void;
  lang: "fr" | "en";
  onLangChange: (lang: "fr" | "en") => void;
  /** Present when a vault is unlocked → enables claiming relics by scan. */
  deviceSecretHex?: string;
}

type Possession = "held" | "transferred" | "not_owned" | "unknown";

/**
 * Authentic possession: a string comparison of the controller this vault
 * holds (from its local claim) against the controller the anchor records
 * *now*. No secret leaves the device; this simply reflects the ledger's
 * truth. ``not_owned`` = never claimed; ``transferred`` = claimed once but
 * the ledger has moved on; ``unknown`` = anchor unreachable.
 */
function possessionOf(
  myControllerPub: string | undefined,
  ledgerControllerPub: string | null | undefined,
): Possession {
  if (ledgerControllerPub === null) return "unknown";
  if (!myControllerPub) return "not_owned";
  return myControllerPub === ledgerControllerPub ? "held" : "transferred";
}

/**
 * The Codex — a quiet gallery of the seven relics, with an honest
 * ownership state. It shows what each relic *is*, marks the ones this
 * vault actually holds (verified against the anchor, not merely assigned),
 * and shows the correct empty state when the vault holds none.
 */
export function RelicsGallery({
  api,
  onBack,
  lang,
  onLangChange,
  deviceSecretHex,
}: Props) {
  const [manifest, setManifest] = useState<CodexManifestDTO | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [possession, setPossession] = useState<Record<string, Possession>>({});
  const [ownershipResolved, setOwnershipResolved] = useState(false);
  const [open3d, setOpen3d] = useState<string | null>(null);
  const [claiming, setClaiming] = useState(false);
  const [eggOpen, setEggOpen] = useState(false);

  useEffect(() => {
    void (async () => {
      try {
        const m = await api.codex();
        setManifest(m);
        await resolveOwnership(m);
      } catch (e) {
        setErr(
          e instanceof EsoptronApiError
            ? `API ${e.status}: ${e.message}`
            : e instanceof Error
              ? e.message
              : "could not load the Codex",
        );
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api]);

  async function resolveOwnership(m: CodexManifestDTO) {
    const claims = loadRelicClaims();
    const byKey = new Map(claims.map((c) => [c.key, c]));
    const result: Record<string, Possession> = {};
    for (const relic of m.relics) {
      const claim = byKey.get(relic.key);
      if (!claim) {
        result[relic.key] = "not_owned";
        continue;
      }
      try {
        const state = await api.getArtifact(claim.artifact_id_hex);
        result[relic.key] = possessionOf(
          claim.controller_pub_hex,
          state.controller_pub_hex,
        );
      } catch {
        result[relic.key] = "unknown"; // anchor unreachable / not minted
      }
    }
    setPossession(result);
    setOwnershipResolved(true);
  }

  const heldCount = Object.values(possession).filter((p) => p === "held").length;

  const vaultFor = (relic: CodexRelicDTO): string | null => {
    const d = manifest?.distribution?.find((x) => x.key === relic.key);
    if (!d) return null;
    return `${t("Coffre", "Vault")} #${d.vault_sequence} · ${d.placement}`;
  };

  const t = (fr: string, en: string) => (lang === "fr" ? fr : en);

  if (eggOpen) {
    return <EggGate api={api} lang={lang} onCancel={() => setEggOpen(false)} />;
  }

  if (manifest && claiming && deviceSecretHex) {
    return (
      <ClaimRelic
        api={api}
        relics={manifest.relics}
        deviceSecretHex={deviceSecretHex}
        lang={lang}
        onClaimed={() => {
          void resolveOwnership(manifest);
        }}
        onCancel={() => setClaiming(false)}
      />
    );
  }

  return (
    <section className="relics">
      <div className="relics-head">
        <h2>{t("Le Codex", "The Codex")}</h2>
        <button
          className="link lang-toggle"
          onClick={() => onLangChange(lang === "fr" ? "en" : "fr")}
        >
          {lang === "fr" ? "EN" : "FR"}
        </button>
      </div>
      <p className="relics-intro">
        {t("Douze reliques. Les vôtres s'illuminent.", "Twelve relics. Yours light up.")}
      </p>

      {err && <div className="error">{err}</div>}
      {!manifest && !err && <p>{t("Ouverture du Codex…", "Opening the Codex…")}</p>}

      {manifest && (
        <>
          {/* Ownership banner — the authentic empty state lives here. */}
          {ownershipResolved && (
            <div
              className={`relics-owned${heldCount > 0 ? " has" : " empty"}`}
            >
              {heldCount > 0
                ? t(
                    `Vous détenez ${heldCount} relique${heldCount > 1 ? "s" : ""} du Codex.`,
                    `You hold ${heldCount} relic${heldCount > 1 ? "s" : ""} of the Codex.`,
                  )
                : t(
                    "Aucune relique ne répond encore à ce coffre. Le Codex ci-dessous est le lore partagé — une relique se vit, ne se liste pas.",
                    "No relic answers to this vault yet. The Codex below is the shared lore — a relic is lived, not listed.",
                  )}
            </div>
          )}

          {deviceSecretHex && (
            <button className="primary" onClick={() => setClaiming(true)}>
              {t("✦ Réclamer une relique (scanner)", "✦ Claim a relic (scan)")}
            </button>
          )}

          <button className="secondary" onClick={() => setEggOpen(true)}>
            {t("🥚 Ouvrir mon œuf (psnx + blend_data)", "🥚 Open my egg (psnx + blend_data)")}
          </button>

          <ul className="relic-list">
            {manifest.relics.map((r, i) => {
              const p = possession[r.key] ?? "not_owned";
              return (
                <li
                  key={r.key}
                  className={`relic-card${r.is_founder ? " founder" : ""}${
                    p === "held" ? " held" : ""
                  }`}
                  style={
                    {
                      ["--seal" as string]: `hsl(${r.seal_hue} 70% 55%)`,
                      animationDelay: `${Math.min(i, 8) * 55}ms`,
                    } as React.CSSProperties
                  }
                >
                  <div className="relic-top">
                    <RelicGlyph relic={r.key} />
                    <div className="relic-title">
                      <span className="relic-name">{r.name}</span>
                      <span className="relic-sub">{r.title}</span>
                    </div>
                    {p === "held" ? (
                      <span className="relic-held">{t("à vous", "yours")}</span>
                    ) : (
                      <span className="relic-rank">#{r.rank}</span>
                    )}
                  </div>

                  <div className="relic-tags">
                    <span className="tag element">{r.element}</span>
                    {r.is_founder ? (
                      <span className="tag founder-tag">founder</span>
                    ) : (
                      <span className="tag">derived</span>
                    )}
                    {vaultFor(r) && (
                      <span className="tag vault">{vaultFor(r)}</span>
                    )}
                    {p === "transferred" && (
                      <span className="tag moved">{t("transmise", "transferred")}</span>
                    )}
                  </div>

                  <p className="relic-lore">
                    {lang === "fr" ? r.lore_fr : r.lore}
                  </p>

                  <dl className="relic-meta">
                    <dt>{t("écho", "myth")}</dt>
                    <dd>{r.myth_echo}</dd>
                    <dt>{t("mécanique", "mechanism")}</dt>
                    <dd>{r.mechanism}</dd>
                  </dl>

                  <button
                    className="link relic-3d-toggle"
                    onClick={() =>
                      setOpen3d(open3d === r.key ? null : r.key)
                    }
                  >
                    {open3d === r.key
                      ? t("fermer", "close")
                      : t("✦ voir en 3D", "✦ view in 3D")}
                  </button>
                  {open3d === r.key && (
                    <div className="relic-3d">
                      <RelicCanvas relic={r} size={300} />
                    </div>
                  )}
                </li>
              );
            })}
          </ul>

          <p className="relics-commit">
            commitment{" "}
            <code>{manifest.catalog_commitment_hex.slice(0, 16)}…</code>
            {manifest.btc_block_height
              ? ` · BTC ${manifest.btc_block_height}`
              : ` · ${t("distribution non ancrée", "distribution not committed")}`}
          </p>
        </>
      )}

      <button className="secondary" onClick={onBack}>
        {t("Retour", "Back")}
      </button>
    </section>
  );
}
