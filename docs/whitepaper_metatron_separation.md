# Whitepaper III — Théorème de séparation et bandeau de rôle

**Titre complet** : *Indistinguabilité perceptuelle, distinguabilité algébrique, et nécessité d'un marqueur de rôle explicite entre artefacts publics (`.eopx` Métatron) et inscriptions privées (Metatron Mnemonic / Recovery Plate).*

**Version** : 0.1 — *draft pour revue interne*
**Date** : 2026-05-26
**Auteurs** : équipe Logos (Eidolon / Esoptron)
**Statut** : pré-spécification, non normatif
**Prérequis** :
- *Whitepaper I — Le Cube de Métatron comme toile cryptographique* (`docs/whitepaper_metatron.md`)
- *Whitepaper II — Metatron Mnemonic & Recovery Plate* (`docs/whitepaper_metatron_mnemonic.md`)

**Mots-clés** : indistinguabilité computationnelle, code linéaire, sous-espace affine, marqueur de rôle, sécurité par confusion, plate-leurre, déni plausible, anti-coercition.

---

## Résumé

Les Whitepapers I et II construisent deux artefacts visuellement isomorphes — le rendu public `.eopx` Métatron et l'inscription privée Metatron Mnemonic/Recovery Plate — sur la **même grammaire géométrique** (graphe K₁₃, table OKLCH `metatron_oklch_v1`, alphabet de glyphes). Cette unification esthétique est un atout d'écosystème, mais ouvre une faille de **confusion sémantique** : un observateur humain non averti ne peut pas distinguer, à l'œil nu, un objet public sans valeur d'un objet privé catastrophique en cas de divulgation.

Le présent whitepaper :

1. **Formalise** la fonction de rendu commune R : 𝔽₁₃⁹¹ → 𝓘 et les deux distributions amont D<sub>pub</sub>, D<sub>priv</sub>.
2. **Démontre** que les deux distributions sont **perceptuellement indistinguables pour un humain casuel** (Théorème 1), mais **algébriquement distinguables pour un algorithme polynomial** connaissant la spec (Théorème 2). Cette asymétrie est désirée et exploitée comme garde-fou.
3. **Construit** le **bandeau de rôle** `metatron:role`, marqueur multi-couche (PNG chunk, glyphe visuel, motif d'arrière-plan, signature ML-DSA pour le cas public) qui rend obligatoire la déclaration de rôle de chaque artefact.
4. **Analyse** les attaques de confusion (publique → privé et privé → publique) et propose les contre-mesures normatives.
5. **Étend** la construction à un schéma de **plate-leurre** offrant un déni plausible sous contrainte physique (coercition).

Aucune nouvelle primitive cryptographique n'est introduite. La sécurité du marqueur de rôle repose, pour le cas public, sur ML-DSA déjà utilisé par `.eopx` ; pour le cas privé, sur une convention physique stricte gravée dans le substrat lui-même.

---

## 1. Problème : deux artefacts, une grammaire

### 1.1 Récapitulation

| Artefact                       | Source de bits                            | Sortie visuelle                       | Valeur de divulgation       |
| ------------------------------ | ----------------------------------------- | ------------------------------------- | --------------------------- |
| `.eopx` Métatron (Whitepaper I)| `spinor_hash(V)` (PRF de la voûte)        | PNG 512×512, K₁₃ teinté + glyphé       | **nulle** (déjà public)     |
| Metatron Mnemonic (WP II)      | RS-𝔽₁₃ d'un seed 256 bits uniforme        | PNG 1024×1024, K₁₃ teinté + glyphé     | **catastrophique** (seed entier) |
| Metatron Recovery Plate (WP II)| RS-𝔽₁₃ d'une part Shamir 2/3              | PNG 1024×1024 recto-verso, K₁₃        | **partielle** (1 plate seule = aucun bit utile ; 2 plates = seed) |

Les trois objets utilisent :

- Le **même graphe** K₁₃ dans son plongement de Métatron canonique.
- La **même table** `metatron_oklch_v1` de 13 teintes OKLCH.
- Le **même alphabet** de 13 glyphes.
- Le **même ordre canonique** de porteurs.

### 1.2 Conséquence brute

> Pour un œil non instruit, un cube de Métatron coloré est *un* cube de Métatron coloré. Il faut donc une signalisation **explicite, multi-couche, et non falsifiable** du rôle de l'artefact.

Le présent whitepaper formalise pourquoi cette signalisation est strictement nécessaire et comment la construire sans introduire de nouvelle primitive cryptographique.

---

## 2. Modèle formel

### 2.1 La fonction de rendu commune

Soit le triplet :

```
G = (V, A)         graphe complet K₁₃ avec son plongement de Métatron (Whitepaper I §2)
Σ = 𝔽₁₃            alphabet des symboles
Γ : Σ → OKLCH × Glyph    table de codage canonique (Whitepaper II §3)
```

On définit la fonction de rendu **commune aux deux artefacts** :

```
R : Σ⁹¹ → 𝓘
R(s₀, s₁, …, s₉₀) = PNG canonique où Γ(s_i) habille le i-ième porteur
                    de G dans l'ordre canonique.
```

### 2.2 Les deux distributions amont

**Distribution publique** D<sub>pub</sub> :

```
V ~ ValidVaults
h = spinor_hash(V)         ∈ {0,1}⁵¹²
k = HKDF-SHA3-512(h, info="esoptron.render.metatron.v1", L=91·log₂(13))
s_pub = base13_decode(k)   ∈ 𝔽₁₃⁹¹
                  ▼
            R(s_pub)
```

**Distribution privée** D<sub>priv</sub> :

```
seed ~ Uniform({0,1}²⁵⁶)
m = base13_encode(version ‖ seed)       ∈ 𝔽₁₃⁷⁰
s_priv = RS_encode(m)                    ∈ C ⊂ 𝔽₁₃⁹¹
                  ▼
            R(s_priv)
```

où C ⊂ 𝔽₁₃⁹¹ est le **sous-espace linéaire** de dimension 70 défini par l'entrelacement de 7 codes RS(13, 10) — code MDS de longueur 91 et distance minimale ≥ 4.

### 2.3 Adversaires

On considère deux classes d'observateurs :

| Classe          | Capacité                                   | Connaissance de la spec |
| --------------- | ------------------------------------------ | ----------------------- |
| 𝒜<sub>human</sub> | Inspection visuelle humaine casuelle         | Aucune ou marginale     |
| 𝒜<sub>algo</sub> | Algorithme polynomial                       | Spec complète           |

---

## 3. Théorème 1 — Indistinguabilité perceptuelle (humain)

### 3.1 Énoncé

**Théorème 1.** *Sans bandeau de rôle, et pour un adversaire 𝒜<sub>human</sub> sans entraînement spécifique :*

```
| Pr[𝒜_human(R(s)) = "public" | s ~ D_pub]
  − Pr[𝒜_human(R(s)) = "public" | s ~ D_priv] |  ≤  ε_human
```

*où ε<sub>human</sub> est négligeable et empiriquement mesurable. En d'autres termes, un humain casuel répond "public" ou "privé" avec une probabilité essentiellement indépendante du véritable rôle de l'artefact.*

### 3.2 Justification

L'œil humain perçoit deux propriétés agrégées d'un rendu K₁₃ coloré :

1. **Diversité chromatique globale** : approximation visuelle de l'entropie de la distribution des teintes.
2. **Structures saillantes locales** : présence de motifs réguliers (axe de symétrie, paire de teintes en miroir, etc.).

Pour D<sub>pub</sub> :
- Sous l'hypothèse PRF de HKDF-SHA3-512, les 91 symboles sont uniformément distribués sur 𝔽₁₃, à un biais cryptographique près négligeable.
- Diversité chromatique attendue : maximale.
- Structures saillantes : aléatoires, ni plus ni moins fréquentes que pour une suite uniforme.

Pour D<sub>priv</sub> :
- Le seed est uniforme par hypothèse de TRNG correct (Whitepaper II §7).
- L'image par RS d'une distribution uniforme sur 𝔽₁₃⁷⁰ est uniforme sur C ⊂ 𝔽₁₃⁹¹ (RS systématique, donc bijection sur le message ; les symboles de parité sont des combinaisons linéaires déterminées du message).
- **Sur l'ensemble C**, la distribution est uniforme ; mais la projection sur les 13 symboles d'un bloc RS(13, 10) donne une distribution uniforme sur 𝔽₁₃¹³ (puisque les évaluations en 13 points distincts d'un polynôme aléatoire de degré ≤ 9 sont uniformes, bien que non indépendantes).
- Localement, chaque sommet ou arête prise isolément a une distribution uniforme sur 𝔽₁₃.

**Conclusion** : à l'œil humain casuel, les marginales de premier ordre (couleur d'un sommet pris isolément) sont identiques entre D<sub>pub</sub> et D<sub>priv</sub>. La distinction nécessite la perception de **corrélations algébriques d'ordre 4** (la distance minimale du code), au-delà des capacités d'un observateur non entraîné.

Empiriquement, on conjecture ε<sub>human</sub> ≤ 0.05 sur une population non avertie (test à conduire dans une étude utilisateur dédiée).

### 3.3 Conséquence

> **Un humain qui voit un cube de Métatron coloré ne peut pas déduire de cette seule observation s'il s'agit d'un objet sans valeur (`.eopx` public) ou d'un secret catastrophique (Plate privée).**

Cette indistinguabilité, en l'absence de marqueur explicite, constitue la **vulnérabilité de confusion** que le bandeau de rôle (§5) doit éliminer.

---

## 4. Théorème 2 — Distinguabilité algébrique

### 4.1 Énoncé

**Théorème 2.** *Il existe un algorithme polynomial 𝒜<sub>algo</sub> tel que, pour tout s ∈ 𝔽₁₃⁹¹ :*

```
Pr[𝒜_algo(s) = "private" | s ~ D_priv]  ≥  1 − negl(λ)
Pr[𝒜_algo(s) = "private" | s ~ D_pub]   ≤  |C| / |𝔽₁₃⁹¹|  =  13⁷⁰ / 13⁹¹  =  13⁻²¹  ≈  2⁻⁷⁷.⁸
```

### 4.2 Construction de l'algorithme

```
algorithm IsPrivate(s ∈ F_13^91):
    désentrelacer s en 7 blocs c_0, ..., c_6 de 13 symboles
    for b in 0..6:
        tenter d'interpoler un polynôme P_b ∈ F_13[X] de degré ≤ 9
            tel que c_b[i] = P_b(α^i) pour tout i ∈ [0, 12]
        si interpolation impossible (système incohérent) :
            return "public"
    return "private"
```

L'interpolation de Lagrange à 13 points fixés détermine uniquement P si deg(P) ≤ 12 ; pour deg(P) ≤ 9, il faut vérifier que les 3 contraintes supplémentaires sont satisfaites. La probabilité qu'elles le soient pour un vecteur aléatoire est exactement 13⁻³ par bloc, soit 13⁻²¹ globalement.

### 4.3 Conséquence

> **Pour tout algorithme connaissant la spec, la distinction publique/privée est calculable en temps polynomial avec probabilité d'erreur négligeable.**

Cette asymétrie (humain ↔ algorithme) est **désirée** :

- L'humain ne peut pas distinguer ⇒ besoin d'un marqueur explicite.
- L'algorithme peut distinguer ⇒ un vérificateur logiciel peut détecter la fraude (par exemple, un attaquant qui prétend qu'une plate privée volée est un `.eopx` public sans valeur sera trahi par le test algébrique).

### 4.4 Limite de cette distinguabilité

L'algorithme distingue uniquement *avec connaissance de la spec*. Un adversaire qui ignore la structure du code RS-𝔽₁₃ employé ne peut pas distinguer. Mais la spec étant publique (open-source par construction de l'écosystème Logos), cet adversaire est de toute façon dans la classe 𝒜<sub>algo</sub>. La sécurité ne peut donc pas reposer sur l'obscurité du code.

---

## 5. Construction du bandeau de rôle

### 5.1 Cahier des charges

Le bandeau de rôle doit :

1. Être **machine-lisible** (parseable de manière fiable par tout logiciel implémentant la spec).
2. Être **humain-lisible** (compréhensible d'un coup d'œil sans logiciel).
3. Être **inscrit dans le substrat** pour le cas privé (gravé, pas ajouté au PNG).
4. Être **signé cryptographiquement** pour le cas public (ML-DSA déjà disponible dans `.eopx`).
5. Distinguer au moins **trois rôles** : `public_render`, `private_mnemonic`, `private_recovery_plate`.
6. Résister à des tentatives triviales de falsification (recouvrement, surimpression).

### 5.2 Construction multi-couche

Le bandeau combine quatre couches indépendantes :

#### Couche A — Chunk PNG `metatron:role` (machine-lisible numérique)

Chunk `tEXt` standard PNG :

```
metatron:role = "public_render" | "private_mnemonic" | "private_recovery_plate"
metatron:role_version = "v1"
metatron:role_sig = base64(ML-DSA(payload_hash ‖ metatron:role)) — pour public uniquement
```

Pour `public_render`, la signature ML-DSA déjà calculée sur `payload_hash` (Whitepaper I) inclut désormais le champ `metatron:role` dans le payload. Toute altération du rôle invalide la signature.

Pour `private_mnemonic` et `private_recovery_plate`, le chunk PNG est présent mais **non signé** : il n'existe pas de clé Dilithium à associer (la plate est précisément la *graine* de la clé). La protection vient des Couches B, C, D.

#### Couche B — Bandeau visuel (humain-lisible)

Sur le pourtour de l'image (gravure ou rendu), un **bandeau de 64 pixels** contient :

| Rôle                         | Style de bandeau         | Glyphes centraux       | Couleur dominante   |
| ---------------------------- | ------------------------ | ---------------------- | ------------------- |
| `public_render`              | Cadre ouvert, coins évidés | Ouroboros + "PUBLIC"   | Or (sym. 6)          |
| `private_mnemonic`           | Cadre fermé, coins pleins | Sceau + "PRIVÉ · SEED" | Vermillon (sym. 8)   |
| `private_recovery_plate`     | Cadre crénelé             | Sceau + "PRIVÉ · PLATE · {1, 2 ou 3}/3" | Magenta (sym. 9) |

Les styles de bandeau sont **mutuellement exclusifs et visuellement opposés** : un cadre ouvert ne peut pas être confondu avec un cadre fermé ; un crénelage est immédiatement repérable.

#### Couche C — Motif d'arrière-plan (filigrane perceptuel)

Sous le cube, un filigrane subtil mais reconnaissable :

- `public_render` : motif radial diffus (suggère l'émission, l'ouverture).
- `private_mnemonic` / `recovery_plate` : motif concentrique fermé (suggère le coffre, la rétention).

Le filigrane est tracé à faible contraste (ΔL ≈ 0.05) pour ne pas interférer avec la lecture des symboles, mais il est immédiatement perceptible une fois identifié.

#### Couche D — Encoche physique (Plate gravée uniquement)

Pour les substrats physiques (titane, acier, céramique), un **biseau directionnel** au coin supérieur gauche indique la face avant. Une **encoche en V** sur le bord droit marque les `private_*` (absente sur les `.eopx` *imprimés* pour exposition).

L'encoche est **mécanique**, donc impossible à falsifier par retouche photo a posteriori.

### 5.3 Règle de vérification stricte

Tout vérificateur (humain ou logiciel) doit appliquer la **disjonction de rejet** suivante :

```
SI metatron:role est absent OU non reconnu          → REJETER
SI metatron:role == public_render et signature ML-DSA absente/invalide → REJETER
SI metatron:role contradiction entre couches A, B, C, D → REJETER
SI test algébrique (§4.2) contredit metatron:role déclaré → REJETER
SINON                                                  → ACCEPTER avec rôle déclaré
```

La double vérification *role déclaré* + *test algébrique* élimine la classe d'attaques où un adversaire change uniquement le chunk PNG.

### 5.4 Hiérarchie de confiance

| Couche                | Confiance contre quelle menace ?              |
| --------------------- | --------------------------------------------- |
| A (chunk PNG signé)   | Falsification logicielle distante              |
| B (bandeau visuel)    | Confusion humaine au premier regard            |
| C (filigrane)         | Confusion humaine sous éclairage variable      |
| D (encoche mécanique) | Falsification photographique du substrat       |
| A + B + C + D         | Couplage robuste — falsification simultanée requise |

---

## 6. Attaques de confusion

### 6.1 Attaque A — `.eopx` public exposé comme une plate privée

**Scénario** : un attaquant retire le bandeau d'un `.eopx` public, le grave sur acier, le présente à la victime comme "votre Recovery Plate". La victime stocke l'objet en lieu sûr et croit avoir sauvegardé sa voûte.

**Conséquence** : lors d'un recovery, la "plate" est décodée mais ne donne aucun seed valide (le test algébrique §4.2 trahit immédiatement le rôle public). La victime découvre qu'elle n'a aucune sauvegarde — perte de la voûte.

**Mitigation** :

1. La cérémonie de génération (Whitepaper II §7) impose une **vérification end-to-end** par les témoins : décodage de la plate gravée + comparaison bit-à-bit au seed généré. Une fausse plate (non issue d'un RS valide) échoue cette vérification.
2. Les couches B, C, D du bandeau rendent l'usurpation visuellement détectable.

### 6.2 Attaque B — Plate privée exposée comme un `.eopx` public

**Scénario** : la victime expose publiquement sa Recovery Plate (sur les réseaux sociaux, en photo de profil, sur IPFS) en croyant qu'il s'agit du `.eopx` public.

**Conséquence** : l'attaquant exécute le test algébrique (§4.2), confirme que l'objet est une plate privée, applique le décodage RS-𝔽₁₃, extrait la part Shamir, croise avec une autre plate (volée par ailleurs) → reconstitue le seed → vide la voûte.

**Mitigation** :

1. Couche B : la plate porte la mention **"PRIVÉ"** en clair. Tout logiciel d'upload (Twitter, IPFS, Esoptron-share) doit refuser de publier un PNG dont `metatron:role` commence par `private_`.
2. Couche A : Esoptron CLI fournit `eopx publish <file>` qui vérifie explicitement le rôle avant tout envoi.
3. UX : tout artefact privé est rendu **avec une bordure rouge épaisse** au-delà du bandeau — visible même sur miniature.

### 6.3 Attaque C — Substitution silencieuse

**Scénario** : un attaquant ayant accès physique temporaire à une plate privée la **remplace** par une plate factice (même apparence, mais encodant un seed différent contrôlé par l'attaquant).

**Conséquence** : lors d'un futur recovery, la victime reconstitue un seed contrôlé par l'attaquant et établit une "nouvelle" voûte qui est en réalité celle de l'attaquant.

**Mitigation** :

1. **Cérémonie d'inscription du `vault_id`** dans l'en-tête de la plate (Whitepaper II §8.5). La victime peut, à tout moment, photographier sa plate, décoder l'en-tête, et vérifier que le `vault_id_truncated[64]` correspond à sa voûte connue.
2. **Marquage cryptographique du substrat** (hors scope de ce whitepaper) : numéro de série gravé en micro-pointes par le graveur, certifié hors-ligne.
3. **Audit périodique** : recommander à la victime de re-vérifier ses plates annuellement.

---

## 7. Plate-leurre et déni plausible

### 7.1 Modèle de coercition

Une menace souvent négligée : l'adversaire **physique** qui force la victime à révéler ses plates sous contrainte (rubber-hose attack). Le déni plausible exige que la victime puisse révéler quelque chose **sans révéler le vrai seed**.

### 7.2 Construction : plate-leurre par dérivation duale

Soit `passphrase_real` la phrase secrète véritable de la victime, et `passphrase_decoy` une phrase secrète secondaire utilisée uniquement sous coercition.

```
Cérémonie de génération étendue :

seed_real = HKDF(entropy, info="metatron.seed.real" ‖ passphrase_real)
seed_decoy = HKDF(entropy, info="metatron.seed.decoy" ‖ passphrase_decoy)

Plate physique unique contient les DEUX seeds en superposition :
    plate_payload = encrypt(seed_real, passphrase_real)
                  ⊕ encrypt(seed_decoy, passphrase_decoy)
                  ⊕ pad_uniforme
```

À la lecture, la phrase fournie sélectionne lequel des seeds émerge. Sous coercition, la victime révèle `passphrase_decoy` → le décodage donne `seed_decoy` qui contrôle une voûte-leurre contenant des actifs sacrifiables.

### 7.3 Limites du déni plausible

- Le schéma est **publiquement connu** : un adversaire informé sait que toute plate Métatron *peut* porter un leurre. Cela peut motiver l'adversaire à insister jusqu'à obtenir la *vraie* passphrase.
- Mitigation partielle : `n` leurres successifs (poupées russes) avec valeurs croissantes. L'adversaire ne peut pas savoir s'il est arrivé au "vrai" seed.
- Aucun déni plausible n'est cryptographiquement absolu sous menace illimitée. Le schéma offre une protection probabiliste contre la coercition opportuniste.

### 7.4 Intégration au bandeau

Une plate-leurre est, du point de vue du bandeau, identique à une plate standard. Sa nature duale n'est révélée que par la spec de génération. Le chunk PNG peut éventuellement signaler `metatron:dual = true` si l'utilisateur l'accepte (utile pour l'ergonomie de récupération, mais affaiblit le déni si lu sous coercition).

> **Recommandation** : ne pas inscrire `metatron:dual` publiquement. Le seul indice que la plate est duale doit résider dans la mémoire de la victime.

---

## 8. Intégration aux outils Esoptron

### 8.1 CLI

```
eopx render <vault.psnx> [--style=metatron] [--role=public_render]
    → produit vault.eopx avec bandeau, signature, chunk PNG.

eopx mnemonic gen --output=mnemonic.png [--profile=mnemonic_v1]
    → cérémonie interactive multi-source, sortie privée avec bandeau "PRIVÉ · SEED".

eopx recovery gen --output-dir=plates/ [--profile=recovery_v1] [--shares=2/3]
    → génère 3 plates avec bandeaux "PRIVÉ · PLATE · 1..3/3".

eopx verify-role <file.png>
    → exécute la disjonction §5.3 et affiche le rôle détecté + niveau de confiance.

eopx publish <file.png> --destination=ipfs|twitter|web
    → REFUSE si metatron:role commence par "private_".
```

### 8.2 SDK Python (`sdk/python/esoptron/eopx_verify.py`)

```python
def verify_role(png_path: str) -> RoleVerificationResult:
    """
    Exécute toutes les couches de vérification :
      A (chunk + signature), B (bandeau OCR), C (filigrane), D (encoche si scan haute déf.).
    Retourne le rôle détecté + score de confiance + liste d'avertissements.
    """
    ...
```

L'absence de cette fonction sur un artefact rejette l'ensemble du flux de traitement. Aucune route alternative n'est exposée.

### 8.3 Workflow Cipher (P4)

Lorsque deux pairs s'échangent leurs `.eopx` pour pairing (Whitepaper I §6.4), Cipher vérifie systématiquement `metatron:role == public_render`. Tout autre rôle déclenche un avertissement explicite : *"Votre interlocuteur tente de partager une plate privée. Avez-vous confiance ?"*

---

## 9. Théorèmes complémentaires

### 9.1 Engagement à l'image complète

**Théorème 3.** *Pour `.eopx` public, la signature ML-DSA couvre simultanément (a) le payload des chunks PNG, (b) le rôle déclaré, (c) un hash du rendu pixel-à-pixel. Toute modification d'un seul pixel, d'un seul chunk, ou du rôle invalide la signature.*

Justification : en intégrant `payload_hash = SHA3-512( chunks ‖ rendered_image_bytes ‖ role )` dans la signature ML-DSA, on couple les quatre éléments. La spec actuelle `.eopx` ne couvrait que `chunks` et `rendered_image_bytes` (implicitement via `payload_hash`) ; on étend pour inclure `role`.

### 9.2 Non-engagement pour les plates privées

**Théorème 4.** *Pour les plates privées, il n'existe aucune signature cryptographique attachée à la plate elle-même. Le seul mécanisme de vérification d'intégrité est (a) le code Reed–Solomon, (b) la concordance des couches B/C/D du bandeau.*

Conséquence : une plate privée est **vérifiable mais non authentifiable**. La distinction est importante : on peut prouver qu'une plate est intègre (RS décode sans erreur), mais on ne peut pas prouver qui l'a générée. C'est inhérent à la nature d'un seed : la plate *est* le secret, il n'y a pas de signataire externe.

Conséquence pratique : la plate doit être maintenue physiquement confidentielle. Pas de notarisation externe possible sans révéler le seed.

### 9.3 Limite de la sécurité par confusion

**Théorème 5 (négatif).** *Sans le bandeau de rôle, la sécurité de l'écosystème dépend strictement de l'attention de l'utilisateur. Avec le bandeau de rôle correctement vérifié, la sécurité dépend strictement des primitives cryptographiques sous-jacentes (ML-DSA pour le public, TRNG + RS-𝔽₁₃ pour le privé). Aucune configuration intermédiaire n'est sûre.*

Ce théorème normatif est la justification de l'**obligation** du bandeau dans toute implémentation conforme. Aucune dérogation, aucun mode "minimal", aucun rendu "sans bandeau".

---

## 10. Conclusion

La grammaire visuelle commune de Métatron — graphe K₁₃, 13 teintes OKLCH, 13 glyphes — est un atout d'écosystème (lisibilité, cohérence esthétique, vérification multimodale) mais ouvre une vulnérabilité de confusion entre artefacts publics et privés. Cette confusion est **perceptuellement inévitable** pour un humain casuel (Théorème 1) bien qu'elle soit **algébriquement triviale** à lever pour un algorithme connaissant la spec (Théorème 2). L'asymétrie entre ces deux capacités est exploitée comme garde-fou.

Le **bandeau de rôle** `metatron:role` est la construction qui rend obligatoire et infalsifiable la déclaration de rôle de chaque artefact. Il opère sur quatre couches indépendantes (chunk PNG signé, bandeau visuel, filigrane d'arrière-plan, encoche mécanique) couplées par une règle de vérification stricte qui rejette toute incohérence. Pour les `.eopx` publics, le rôle est verrouillé par la signature ML-DSA existante. Pour les plates privées, le rôle est verrouillé par l'inscription physique sur le substrat (gravure, encoche).

Les attaques de confusion sont caractérisées et mitigées (§6). Le déni plausible sous coercition est traité via les plates-leurres à dérivation duale (§7), avec discussion honnête de leurs limites.

Le présent whitepaper complète la trilogie :

| Whitepaper | Objet                                  | Rôle dans l'écosystème            |
| ---------- | -------------------------------------- | --------------------------------- |
| I          | Toile cryptographique publique         | Identité visuelle de voûte (`.eopx`) |
| II         | Inscription privée                     | Cold wallet PQ + Recovery Plate Shamir 2/3 |
| III        | Théorème de séparation + bandeau de rôle | Garde-fou contre confusion sémantique |

Ces trois documents constituent le **socle théorique** de l'extension Métatron de l'écosystème Logos. La phase suivante est la spec normative (`spec_metatron_v1.md`, `spec_metatron_mnemonic_v1.md`, `spec_metatron_role_v1.md`) — figeant chaque table, chaque algorithme, chaque tolérance — et son implémentation Rust dans `eidolon_crypto` et Python dans `esoptron`.

---

## Annexe A — Tableau de récapitulation des rôles

| Champ                       | `public_render`                     | `private_mnemonic`                | `private_recovery_plate`             |
| --------------------------- | ----------------------------------- | --------------------------------- | ------------------------------------ |
| Source de symboles          | PRF(spinor_hash)                    | RS(seed)                           | RS(Shamir_share)                     |
| Sous-espace algébrique      | 𝔽₁₃⁹¹ (uniforme)                    | C ⊂ 𝔽₁₃⁹¹ (dim 70)               | C ⊂ 𝔽₁₃⁹¹ (dim 70 ou 80)            |
| Distribuable publiquement   | **OUI**                             | **NON**                           | **NON**                              |
| Signature ML-DSA            | Obligatoire                          | Inapplicable                      | Inapplicable                          |
| Substrat recommandé         | Écran, PNG, IPFS, NFC                | Titane gravé recto-verso          | Titane gravé recto-verso             |
| Quantité d'artefacts        | 1                                   | 1                                 | 3 (Shamir 2/3)                       |
| Risque de divulgation       | Nul                                  | Catastrophique (seed entier)     | Partiel (1) / Catastrophique (≥2)    |
| Couche bandeau visuelle (B) | Cadre ouvert                        | Cadre fermé "PRIVÉ · SEED"        | Cadre crénelé "PRIVÉ · PLATE · i/3"  |
| Couche filigrane (C)        | Motif radial                        | Motif concentrique                | Motif concentrique                   |
| Couche encoche (D)          | Absente                              | Présente                          | Présente                              |
| Test algébrique attendu     | Non-membre de C (p ≈ 2⁻⁷⁸)          | Membre de C                       | Membre de C                          |
| Profil RS                   | (sans objet)                        | `mnemonic_v1` RS(91, 70)          | `recovery_v1` RS(91, 80) recto-verso |

## Annexe B — Vecteurs de test pour la vérification du bandeau

À constituer dans `tests/vectors/metatron/role/` :

- `public_valid.png` — `.eopx` correctement signé, rôle `public_render`, doit ACCEPTER.
- `public_role_tampered.png` — chunk `metatron:role` modifié post-signature, doit REJETER.
- `public_image_tampered.png` — un pixel modifié dans le cube, doit REJETER.
- `private_mnemonic_valid.png` — plate `mnemonic_v1` cohérente, doit ACCEPTER avec rôle privé.
- `private_role_mislabeled.png` — plate dont le chunk dit `public_render` mais test algébrique trahit appartenance à C, doit REJETER (incohérence A vs test §4.2).
- `private_decoy_pair.png` — plate à dérivation duale, deux passphrases produisent deux seeds distincts.
- `crosstalk_attack.png` — `.eopx` public regravé sur titane avec encoche ajoutée frauduleusement, doit REJETER si filigrane radial reste détectable (incohérence C vs D).

## Annexe C — Pseudo-code de vérification de rôle

```python
def verify_role(png_path: str) -> RoleVerificationResult:
    img, chunks = read_png(png_path)

    # Couche A
    role = chunks.get("metatron:role")
    if role is None:
        return REJECT("no_role_declared")
    if role == "public_render":
        sig = chunks.get("metatron:role_sig")
        payload_hash = chunks.get("eopx:payload_hash")
        pubkey = chunks.get("eopx:kyber_pk_fp_resolved")   # via registre
        if not mldsa_verify(pubkey, payload_hash + role.encode(), sig):
            return REJECT("signature_invalid")

    # Couche B
    detected_banner = detect_banner_style(img)
    if detected_banner != expected_banner_for(role):
        return REJECT(f"banner_mismatch: {detected_banner} vs {role}")

    # Couche C
    detected_filigrane = detect_filigrane_pattern(img)
    if detected_filigrane != expected_filigrane_for(role):
        return REJECT(f"filigrane_mismatch: {detected_filigrane}")

    # Couche D (si haute résolution / scan substrat physique)
    if image_resolution_implies_physical(img):
        if not detect_bevel_consistent_with(img, role):
            return REJECT("bevel_inconsistent")

    # Test algébrique §4.2
    symbols = extract_symbols_from_canonical_positions(img)
    algebraic_role = "private" if is_in_C(symbols) else "public"
    declared_role_class = "public" if role == "public_render" else "private"
    if algebraic_role != declared_role_class:
        return REJECT(f"algebraic_test_contradicts: {algebraic_role} vs {declared_role_class}")

    return ACCEPT(role=role, confidence=score_confidence(...))
```

---

*Fin du draft v0.1. Document à figer par hash dans une future spec normative `spec_metatron_role_v1.md`.*
