import { useCallback, useState } from "react";
import { EggResponseDTO, EsoptronApi, EsoptronApiError } from "../lib/api";
import { EggViewer } from "./EggViewer";

interface Props {
  api: EsoptronApi;
  lang: "en" | "fr";
  /** Optional vault_id hint (e.g. from the local enrollment / bridge). */
  vaultHint?: string;
  onCancel: () => void;
}

type Phase = "gate" | "opening" | "open" | "error";

/**
 * The access window to a vault's golden egg: **both** the `.psnx` and the
 * `.blend_data` must be presented (the ecosystem's two-files-or-nothing
 * rule). The vault id is read from the `.psnx` (best-effort), then the egg
 * is fetched and revealed in 3D.
 *
 * Honest scope: this confirms *possession of both key files* + the vault
 * identity — it does NOT perform Eidolon's full cryptographic vault unlock
 * (that is Eidolon's Rust pipeline). It is the threshold to *view* the egg,
 * not to spend the vault.
 */
export function EggGate({ api, lang, vaultHint, onCancel }: Props) {
  const [phase, setPhase] = useState<Phase>("gate");
  const [psnxName, setPsnxName] = useState<string | null>(null);
  const [blendName, setBlendName] = useState<string | null>(null);
  const [vaultId, setVaultId] = useState(vaultHint ?? "");
  const [egg, setEgg] = useState<EggResponseDTO | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const t = (fr: string, en: string) => (lang === "fr" ? fr : en);

  // Best-effort extraction of a 64-hex vault id from a .psnx file.
  const onPsnx = useCallback(async (file: File) => {
    setPsnxName(file.name);
    try {
      const text = await file.text();
      let found = "";
      try {
        const j = JSON.parse(text);
        found = (j.vault_id || j.key_id || j.vaultId || "").toString();
      } catch {
        /* not plain JSON (may be compressed) — fall through to scan */
      }
      if (!/^[0-9a-f]{64}$/i.test(found)) {
        const m = text.match(/[0-9a-fA-F]{64}/);
        found = m ? m[0] : "";
      }
      if (/^[0-9a-f]{64}$/i.test(found)) setVaultId(found.toLowerCase());
    } catch {
      /* binary / unreadable — the user can paste the vault id manually */
    }
  }, []);

  const bothPresent = !!psnxName && !!blendName;
  const vaultOk = /^[0-9a-f]{64}$/i.test(vaultId);

  const open = useCallback(async () => {
    if (!bothPresent || !vaultOk) return;
    setPhase("opening");
    setErr(null);
    try {
      const res = await api.getEgg(vaultId.toLowerCase());
      setEgg(res);
      setPhase("open");
    } catch (e) {
      setErr(
        e instanceof EsoptronApiError
          ? `API ${e.status}: ${e.message}`
          : e instanceof Error
            ? e.message
            : "could not open the egg",
      );
      setPhase("gate");
    }
  }, [api, vaultId, bothPresent, vaultOk]);

  if (phase === "open" && egg) {
    return (
      <section className="egg-open">
        <h2>{egg.egg.name}</h2>
        <div className="egg-stage">
          <EggViewer egg={egg.egg} size={340} />
        </div>
        <dl className="egg-meta">
          <dt>{t("identifiant", "id")}</dt>
          <dd>{egg.egg.egg_id} · #{egg.egg.egg_number}/555</dd>
          <dt>{t("rareté", "tier")}</dt>
          <dd>{egg.egg.tier} {egg.egg.glyph}</dd>
          <dt>{t("empreinte", "hash")}</dt>
          <dd>
            <code>{egg.egg.egg_hash.slice(0, 24)}…</code>
          </dd>
          <dt>{t("position", "position")}</dt>
          <dd>{egg.egg.position.toLocaleString()}</dd>
        </dl>
        {!egg.committed && (
          <p className="egg-note">
            {t(
              "Bloc Genesis non encore committé — œuf dérivé d'un bloc de démonstration ; le sceau immuable définitif sera apposé par la clé de déploiement.",
              "Genesis block not yet committed — egg derived from a demo block; the final immutable seal is applied by the deployment key.",
            )}
          </p>
        )}
        <button className="secondary" onClick={onCancel}>
          {t("Refermer", "Close")}
        </button>
      </section>
    );
  }

  return (
    <section className="egg-gate">
      <h2>{t("Ouvrir mon œuf", "Open my egg")}</h2>
      <p className="muted">
        {t(
          "Vos deux fichiers de coffre — .psnx et .blend_data — pour franchir le seuil. Aucun ne suffit seul.",
          "Both your vault files — .psnx and .blend_data — to cross the threshold. Neither alone will do.",
        )}
      </p>
      {err && <div className="error">{err}</div>}

      <label className="filepicker">
        {psnxName ? `✓ ${psnxName}` : t("Choisir le .psnx", "Choose the .psnx")}
        <input
          type="file"
          accept=".psnx,application/octet-stream,application/json"
          onChange={(e) => e.target.files?.[0] && onPsnx(e.target.files[0])}
        />
      </label>
      <label className="filepicker">
        {blendName
          ? `✓ ${blendName}`
          : t("Choisir le .blend_data", "Choose the .blend_data")}
        <input
          type="file"
          accept=".blend_data,application/octet-stream"
          onChange={(e) =>
            e.target.files?.[0] && setBlendName(e.target.files[0].name)
          }
        />
      </label>

      <label className="egg-vaultid">
        {t("id du coffre (64 hex)", "vault id (64 hex)")}
        <input
          type="text"
          spellCheck={false}
          value={vaultId}
          placeholder={t("auto-détecté depuis le .psnx", "auto-detected from the .psnx")}
          onChange={(e) => setVaultId(e.target.value.trim())}
        />
      </label>

      <button
        className="primary"
        disabled={!bothPresent || !vaultOk || phase === "opening"}
        onClick={open}
      >
        {phase === "opening"
          ? t("Ouverture…", "Opening…")
          : t("✦ Franchir le seuil", "✦ Cross the threshold")}
      </button>
      <button className="link" onClick={onCancel}>
        {t("Annuler", "Cancel")}
      </button>
      <p className="egg-note">
        {t(
          "Confirme la possession des deux fichiers + l'identité du coffre — pas l'ouverture cryptographique complète (assurée par Eidolon).",
          "Confirms possession of both files + the vault identity — not the full cryptographic unlock (Eidolon's job).",
        )}
      </p>
    </section>
  );
}
