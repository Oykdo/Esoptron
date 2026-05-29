# Whitepaper — Le Cube de Métatron comme toile cryptographique pour Esoptron

**Titre complet** : *Architecture sémantique d'un rendu déterministe de `spinor_hash` sur le graphe complet K₁₃ dans son plongement de Métatron — application aux artefacts `.eopx` de l'écosystème Logos.*

**Version** : 0.1 — *draft pour revue interne*
**Date** : 2026-05-26
**Auteurs** : équipe Logos (Eidolon / Esoptron)
**Statut** : pré-spécification, non normatif
**Mots-clés** : engagement visuel, hash holographique, graphe complet, plongement de Métatron, dérivation déterministe, ML-DSA, vérification multimodale.

---

## Résumé

Esoptron transforme une voûte Eidolon en un artefact PNG nommé `.eopx`, simultanément empreinte visuelle reconnaissable et engagement cryptographique signé en post-quantique (ML-DSA / Dilithium5). La spécification actuelle ne fixe pas le moteur de rendu visuel : tout schéma déterministe lisant la sortie Phase 6 d'Eidolon (`spinor_hash ∈ {0,1}⁵¹²`) est admissible.

Ce whitepaper propose, justifie et formalise un moteur de rendu spécifique fondé sur le **Cube de Métatron**, identifié mathématiquement au graphe complet K₁₃ muni de son plongement euclidien canonique dans ℝ². Nous montrons que ce graphe possède exactement la structure algébrique, topologique et perceptuelle requise pour servir de *toile* à un engagement visuel : densité informationnelle suffisante pour absorber un haché de 512 bits avec marge, ordre canonique calculable à partir de la seule géométrie, décomposition orbitale alignable sur les champs sémantiques d'une voûte Eidolon, sous-structures internes utilisables comme registres adressables, et invariance perceptuelle à l'œil humain.

Le rendu proposé est strictement **déterministe** et n'introduit **aucune nouvelle hypothèse cryptographique** : la sécurité repose intégralement sur les primitives déjà utilisées par Eidolon. Le cube ne fournit pas d'entropie ; il fournit une **interface**.

---

## 1. Contexte et problème

### 1.1 L'écosystème Logos

| Composant  | Rôle                                              | Sortie pertinente                   |
| ---------- | ------------------------------------------------- | ----------------------------------- |
| Eidolon    | Dérivation holographique de clé à 9 phases        | `spinor_hash` (Phase 6), `merkle_root` (Phase 9) |
| Esoptron   | Empreinte visuelle signée d'une voûte             | Artefact `.eopx` 512×512 PNG        |
| Cipher     | Messagerie chiffrée entre voûtes                  | Sessions Kyber1024                  |

Le `.eopx` agit comme passeport public : on peut le diffuser sans révéler la voûte. La couche cryptographique (Dilithium5, Kyber1024, SHA3, Shamir, NIZK Schnorr) est entièrement déléguée au crate Rust `eidolon_crypto`.

### 1.2 Le problème du rendu

Le format `.eopx` exige :

1. **Déterminisme** : ∀ voûte V, ∀ environnement, render(spinor_hash(V)) produit *exactement* la même image, octet par octet.
2. **Distinguabilité visuelle** : pour deux voûtes V₁ ≠ V₂, un humain doit pouvoir distinguer render(V₁) de render(V₂) sans outil.
3. **Lisibilité algorithmique** : un vérificateur doit pouvoir comparer deux PNG par hash ou pixel à pixel.
4. **Tamper evidence multimodale** : toute altération doit être détectable à la fois par signature (`payload_hash`, ML-DSA) et, idéalement, à l'œil nu.
5. **Capacité informationnelle** ≥ 512 bits utiles, idéalement ≥ 1 kbit pour absorber métadonnées et marges d'erreur.

Les approches naïves (gradient procédural, randomart de type OpenSSH, mosaïques aléatoires) satisfont (1) et (3) mais échouent sur (2) et (4) : l'œil humain ne dispose d'aucune structure de référence pour comparer deux blobs visuels. Ce whitepaper propose une structure de référence sacrée, mathématiquement régulière, et déjà ancrée culturellement.

---

## 2. Le Cube de Métatron — définition formelle

### 2.1 Construction géométrique

Le Cube de Métatron est traditionnellement dérivé de la *Fruit of Life* : treize cercles disposés en arrangement hexagonal compact, dont on relie chaque paire de centres par une droite. Formellement :

Soient les treize points de ℝ² :

```
p₀  = (0, 0)                                                  [centre]
pₖ  = (cos(kπ/3), sin(kπ/3))         pour k ∈ {1,…,6}         [hexagone interne, rayon 1]
pₖ' = (√3 · cos((2k−1)π/6),
       √3 · sin((2k−1)π/6))          pour k ∈ {1,…,6}         [hexagone externe, rayon √3]
```

On définit alors :

| Objet                    | Définition                                      | Cardinalité |
| ------------------------ | ----------------------------------------------- | ----------- |
| V (sommets)              | { p₀, p₁,…,p₆, p₁',…,p₆' }                      | **13**      |
| A (arêtes)               | { {u,v} : u,v ∈ V, u ≠ v }                      | **78**      |

> **Observation cruciale** : `|A| = C(13,2) = 78`. Le graphe sous-jacent au Cube de Métatron est exactement le **graphe complet K₁₃**.

Ce point, rarement explicité dans la littérature ésotérique, est central pour notre architecture sémantique. Toute la rigueur mathématique qui suit en découle.

### 2.2 Groupe de symétrie

Le plongement euclidien G = (V, A) admet le groupe diédral

```
D₆ = ⟨ ρ, σ | ρ⁶ = σ² = e, σρσ = ρ⁻¹ ⟩,    |D₆| = 12
```

avec ρ = rotation de π/3 autour de p₀ et σ = réflexion par rapport à l'axe (p₀, p₁).

L'action de D₆ partitionne les sommets en trois **orbites** :

| Orbite      | Représentant | Cardinalité | Stabilisateur     |
| ----------- | ------------ | ----------- | ----------------- |
| O₀          | p₀           | 1           | D₆ entier         |
| O₁ (interne)| p₁           | 6           | ⟨σ⟩, ordre 2      |
| O₂ (externe)| p₁'          | 6           | ⟨σρ⟩, ordre 2     |

Cette décomposition fournit un **système naturel d'adresses hiérarchiques** : centre / couronne interne / couronne externe. Nous l'exploitons en §4 pour mapper les champs sémantiques d'une voûte.

### 2.3 Classes de longueur d'arêtes

Le groupe D₆ agit sur les arêtes en distinguant neuf orbites au sens strict (différenciées par paire d'orbites de sommets *et* phase angulaire). Plusieurs de ces orbites partagent toutefois la même **longueur euclidienne**, ce qui les fond, sous la stratification par longueur, en **six classes**. Comme l'ordre canonique d'écriture/lecture du rendu utilise la longueur (et non l'orbite stricte), ce sont ces six classes qui gouvernent la spécification.

| Classe | Longueur exacte | ≈     | Composition par sous-orbites D₆                                                                   | Cardinalité |
| ------ | --------------- | ----- | ------------------------------------------------------------------------------------------------- | ----------- |
| L₁     | 1               | 1.000 | centre ↔ interne (6) + interne ↔ interne adjacent (6) + interne ↔ externe phase π/6 (12)          | **24**      |
| L₂     | √3              | 1.732 | centre ↔ externe (6) + interne ↔ interne saut-2 (6) + externe ↔ externe adjacent (6)              | **18**      |
| L₃     | 2               | 2.000 | interne ↔ interne diamétral (3) + interne ↔ externe phase π/2 (12)                                | **15**      |
| L₄     | √7              | 2.646 | interne ↔ externe phase 5π/6 (12)                                                                  | **12**      |
| L₅     | 3               | 3.000 | externe ↔ externe saut-2 (6)                                                                       | **6**       |
| L₆     | 2√3             | 3.464 | externe ↔ externe diamétral (3)                                                                    | **3**       |

Total : 24 + 18 + 15 + 12 + 6 + 3 = **78** ✓

Cette stratification par longueur fournit **un ordre canonique calculable** : on trie les arêtes par (longueur, indices lexicographiques des sommets). Aucune information externe (graine, horloge, identifiant) n'est nécessaire — la géométrie suffit. Le test `tests/test_metatron_graph.py::test_length_class_cardinalities` du prototype vérifie automatiquement cette partition (24, 18, 15, 12, 6, 3).

### 2.4 Sous-structures remarquables

Le plongement contient, comme sous-graphes induits par certains sous-ensembles de sommets, plusieurs polytopes classiques projetés :

- **Hexagramme** (étoile à six branches) : sous-graphe sur O₁, deux triangles équilatéraux entrelacés.
- **Hexagone régulier** : cycles induits sur O₁ et sur O₂.
- **Octaèdre projeté** : six sommets de O₁ plus deux choix axiaux.
- **Tétraèdre, cube, dodécaèdre, icosaèdre** : sous-structures projetées (tradition géométrique des cinq solides de Platon).

Chacune de ces sous-structures forme un **registre adressable** dans notre architecture sémantique (§4.2).

---

## 3. Raisonnement mathématique : pourquoi *ce* graphe

Cette section justifie le choix de K₁₃ dans son plongement de Métatron, plutôt que tout autre graphe canonique candidat (K₅, grille n×n, graphe de Petersen, fullerène, etc.).

### 3.1 Critère de capacité informationnelle

Soit un graphe G = (V, A) muni d'un vocabulaire de β_v bits visuels par sommet et β_a bits visuels par arête. La capacité brute de la toile est :

```
C(G) = |V| · β_v + |A| · β_a   bits.
```

Pour Métatron avec β_v = 12 (8 bits teinte + 4 bits glyphe) et β_a = 10 (6 bits teinte + 2 bits épaisseur + 2 bits style) :

```
C(K₁₃ Métatron) = 13 · 12 + 78 · 10 = 156 + 780 = 936 bits.
```

Comparatifs :

| Graphe                          | β_v  | β_a  | Capacité brute |
| ------------------------------- | ---- | ---- | -------------- |
| K₅ (pentagone complet)          | 12   | 10   | 60 + 100 = **160** bits |
| Grille 4×4 (16 sommets, 24 arêtes) | 12 | 10  | 192 + 240 = **432** bits |
| Petersen (10 sommets, 15 arêtes)| 12   | 10   | 120 + 150 = **270** bits |
| **K₁₃ Métatron**                | 12   | 10   | **936** bits**  |
| K₁₅ hypothétique                | 12   | 10   | 180 + 1050 = 1230 bits (mais 105 arêtes — illisible) |

Métatron offre **un optimum local** : capacité ≥ 512 bits (`spinor_hash` complet) avec marge ×1.8, tout en restant en-dessous du seuil de surcharge visuelle (≈ 100 arêtes).

### 3.2 Critère de canonicité d'ordre

Pour qu'un rendu soit *déterministe*, il faut un ordre total sur V et sur A calculable sans référence externe. Le plongement de Métatron fournit :

- sur V : tri par (orbite ∈ {O₀ < O₁ < O₂}, angle polaire arg(p), …) — unique.
- sur A : tri par (longueur euclidienne, indices lex. de sommets) — unique.

Un graphe sans plongement géométrique privilégié (par exemple K₁₃ abstrait, ou un graphe expander aléatoire) **n'admet pas d'ordre canonique** sans graine externe, ce qui contredit l'exigence (1) de §1.2. Le caractère plongé du Cube de Métatron est donc nécessaire, pas accidentel.

### 3.3 Critère d'invariance perceptuelle

Soit Φ : 𝓘 → 𝓘 une transformation perceptive (rotation, mise à l'échelle, légère distorsion). On dit qu'un rendu R est *Φ-stable* si :

```
∀ s ∈ {0,1}⁵¹², ∀ Φ ∈ 𝒯,  HumanCompare(R(s), Φ(R(s))) = "même"
```

Le plongement de Métatron est invariant par D₆ (rotations multiples de π/3 + réflexions). L'œil humain reconnaît la figure du cube comme **la même** sous toute orientation hexagonale. Cette propriété permet, en pratique, qu'un `.eopx` photographié sous un angle modéré reste reconnaissable comme appartenant à la même voûte que la version d'origine. (Note : pour une comparaison machine, la photo est inutile — on compare les hash. L'invariance D₆ ne sert que la lecture humaine.)

### 3.4 Critère algébrique : 13 est premier

Le choix |V| = 13 confère à l'ensemble ℤ/13ℤ une structure de **corps fini** 𝔽₁₃. Conséquences :

- Toute permutation v ↦ a·v + b mod 13 avec a ∈ 𝔽₁₃* est une bijection canonique. Utile pour des schémas futurs de rotation de présentation sans collision.
- Les schémas de Reed-Solomon sur 𝔽₁₃ exploitables nativement (treize racines de l'unité) — utiles pour Phase 2 (Shamir sur GF(2⁸) reste séparé, mais une couche de codage RS-13 pour la robustesse photographique du Pivot A futur est ouverte).
- L'évaluation polynomiale en 13 points distincts d'un polynôme de degré ≤ 12 est une bijection 𝔽₁₃¹³ ↔ 𝔽₁₃[X]<sub>≤12</sub> — base mathématique d'un schéma de secret-sharing interne au cube si jamais nécessaire.

Aucun graphe à |V| non premier (K₁₂, K₁₄, etc.) n'offre cette propriété. Le mysticisme du chiffre 13 admet ici une justification algébrique stricte.

### 3.5 Critère de décomposition orbitale ↔ champs sémantiques

Une voûte Eidolon expose trois champs publics fondamentaux :

| Champ              | Taille  | Rôle                                       |
| ------------------ | ------- | ------------------------------------------ |
| `vault_id`         | 128 bits | UUID de la voûte                          |
| `merkle_root`      | 256 bits | Racine de Merkle (Phase 9)                |
| `kyber_pk_fp`      | 256 bits | Fingerprint SHA3-256 de la clé Kyber1024  |

Total : 640 bits — qui doit pouvoir être visuellement séparé en *régions* pour permettre la vérification ciblée (cf. §6.3 sur la migration de machine).

L'orbite O₀ ({p₀}) est un singleton à 12 bits — trop petit pour un champ. L'orbite O₁ porte 6 × 12 = 72 bits. L'orbite O₂ également 72 bits. Le sous-graphe induit par les arêtes E₁ ∪ E₂ (centre vers couronnes) porte 12 × 10 = 120 bits. Le sous-graphe E₈ (couronne externe) porte 150 bits.

En combinant orbites de sommets et orbites d'arêtes par hauteur dans la hiérarchie, on obtient un découpage naturel en **canaux d'engagement** que nous formalisons en §4.2. Aucun autre plongement ne fournit cette adéquation orbites ↔ champs.

---

## 4. Architecture sémantique du rendu

### 4.1 Pipeline déterministe

```
spinor_hash : {0,1}⁵¹²
        │
        │ HKDF-Expand-SHA3-512(info = "esoptron.render.metatron.v1")
        ▼
   k : {0,1}^N    avec N ≥ 936 (matériel de rendu)
        │
        │ partition canonique en blocs B₁, B₂, …, B₃₆ (voir §4.2)
        ▼
   attributs (nœuds, arêtes)
        │
        │ rastérisation 512×512, anti-aliasing déterministe (Wu)
        ▼
   .eopx PNG
```

Toute la non-déterminisme potentielle (anti-aliasing, ordre d'écriture des pixels, compression PNG) est **fixée** par le profil `metatron_v1` enregistré dans le chunk `eopx:render_style`.

### 4.2 Mapping canaux ↔ champs sémantiques

Nous distribuons les 936 bits de matériel de rendu en sept **canaux d'engagement**, alignés sur les champs publics d'une voûte :

| Canal | Support visuel                       | Bits  | Origine               |
| ----- | ------------------------------------ | ----- | --------------------- |
| C₀    | Glyphe central (sommet p₀)           | 12    | identifiant de profil + version |
| C₁    | Couronne interne (sommets O₁)        | 72    | `vault_id[0..72]`     |
| C₂    | Couronne externe (sommets O₂)        | 72    | `vault_id[72..128]` + drapeaux |
| C₃    | Arêtes centre↔interne (E₁)           | 60    | `merkle_root[0..60]`  |
| C₄    | Arêtes centre↔externe (E₂)           | 60    | `merkle_root[60..120]`|
| C₅    | Arêtes interne↔interne (E₃∪E₄∪E₅)    | 150   | `merkle_root[120..256]` + padding |
| C₆    | Arêtes interne↔externe + externes (E₆∪E₇∪E₈) | 510 | `kyber_pk_fp[0..256]` + `payload_hash[0..254]` |

Total adressé : 936 bits (avec léger padding HKDF).

Chaque canal est dérivé via HKDF séparé `HKDF(spinor_hash, info = f"esoptron.channel.{i}.metatron.v1")` puis xoré avec le champ sémantique correspondant. Cette construction garantit :

- **Indépendance des canaux** sous l'hypothèse PRF de SHA3.
- **Reproductibilité** sans information externe à la voûte.
- **Diagnostic visuel ciblé** : un changement de `machine_lock` (Phase 3) affecte uniquement les canaux dérivés de `merkle_root` *post-rebind*, donc C₃, C₄, C₅ — visuellement, la couronne extérieure (C₂, C₆) reste stable. Un humain *voit* qu'il s'agit de la même voûte sur une nouvelle machine.

### 4.3 Espace de couleurs

Toutes les teintes sont calculées en **OKLCH** (perceptuel) plutôt qu'en HSL/RGB, puis converties en sRGB pour le PNG. Justifications :

1. Distances perceptuelles uniformes → deux bits adjacents donnent deux teintes que l'œil distingue à parts égales.
2. Accessibilité daltonisme : la luminance est un canal indépendant ; on contraint L à varier avec un bit dédié pour garantir un contraste minimal même en monochromie.
3. Reproductibilité multi-écran : OKLCH minimise les dérives perceptuelles entre profils.

### 4.4 Glyphes aux sommets

Chaque sommet porte un glyphe codant 4 bits, choisi dans un alphabet de 16 symboles géométriquement simples (cercle plein, cercle vide, triangle haut, triangle bas, carré, losange, hexagone, pentagone, étoile 5, étoile 6, croix, X, sablier, double cercle, anneau, point). Ces glyphes sont **rotation-invariants** par D₆ pour préserver la symétrie du rendu.

### 4.5 Anti-collision et auto-stabilité

Pour deux voûtes V₁, V₂ avec spinor_hash s₁ ≠ s₂ :

- La probabilité qu'aucun bit de rendu ne diffère est exponentiellement petite (modèle PRF de HKDF).
- Par construction (HKDF Expand), tout flip d'un bit de s déclenche une avalanche complète sur ≥ ½ des 936 bits, donc sur tous les canaux. L'image est **complètement** différente même pour un changement d'un seul bit dans la voûte.

Cette propriété d'avalanche est désirée *parce que* le `.eopx` est lui-même signé : il n'est pas censé tolérer des perturbations partielles de la voûte. La toile reflète la voûte intégralement ou pas du tout.

---

## 5. Propriétés cryptographiques

### 5.1 Engagement par hachage

Le rendu R : {0,1}⁵¹² → {0,1}⁸·²⁶²¹⁴⁴ (PNG 512×512) est une fonction **injective** (modulo collisions de SHA3 jugées négligeables) et **déterministe**. Posons :

```
commit(V) = SHA3-512( PNG_bytes( R(spinor_hash(V)) ) )
```

Cette construction est un **engagement non interactif** : computationally binding (sécurité SHA3) et perfectly hiding tant que la voûte sous-jacente n'est pas publiée (puisque spinor_hash est une PRF de la voûte). C'est exactement le rôle joué actuellement par `payload_hash` dans `.eopx` — le rendu Métatron ne change pas cette propriété, il la **factorise** sur une structure géométrique lisible.

### 5.2 Signature ML-DSA inchangée

La signature Dilithium5 reste calculée sur `payload_hash = SHA3-512(payload)` exactement comme dans la spec `.eopx` actuelle. Le rendu Métatron est *à l'intérieur* de la frontière signée. Aucune nouvelle hypothèse cryptographique n'est introduite.

### 5.3 Vérification multimodale

Pour vérifier un `.eopx` Métatron, un agent dispose de deux voies :

1. **Voie machine** : lire le PNG, recalculer `payload_hash`, vérifier la signature ML-DSA, recalculer `R(spinor_hash)` et comparer pixel à pixel. C'est la procédure existante.
2. **Voie humaine** : ouvrir côte à côte le `.eopx` reçu et une référence connue (par exemple un poster imprimé du `.eopx` officiel de la voûte). Comparer canal par canal — un trait erroné dans un canal trahit un changement dans le champ correspondant.

La voie humaine n'a **pas** la sécurité cryptographique de la voie machine (un humain peut être trompé par un attaquant qui modifie *exactement* la signature ET le rendu cohérent — mais alors il faut posséder la clé privée Dilithium5, donc on revient à la voie machine). Elle joue le rôle de **première barrière** et de diagnostic.

### 5.4 Propriétés ce que le rendu ne fait *pas*

Pour éviter tout malentendu, listons explicitement :

- **Ne crée pas d'entropie**. Le rendu est une fonction publique de `spinor_hash` ; il n'augmente pas la sécurité de la voûte.
- **Ne prouve pas la possession** d'une voûte. Quiconque a vu le `.eopx` peut le copier. La preuve de possession repose sur la clé Dilithium5 privée + le challenge-response habituel.
- **N'autorise pas la reconstruction de la voûte** à partir de l'image. `spinor_hash` est une compression à perte de la voûte ; le rendu en est une simple visualisation.

---

## 6. Applications

### 6.1 Identité visuelle de voûte (Phase P1)

Cas d'usage le plus immédiat : le `.eopx` rendu en Métatron devient le visuel canonique d'une voûte, utilisable comme avatar, sceau de signature, illustration de profil, marqueur d'authenticité dans toute interface front-end. La nature symboliquement chargée du Cube de Métatron renforce le caractère cérémoniel et solennel d'une identité cryptographique.

### 6.2 Shamir Visual Sharding (Phase P2)

Lors d'un sharding k=3, n=5, chaque shard hérite d'un sous-graphe distinct mais cohérent du cube parent :

| Shard | Sous-graphe affiché                            |
| ----- | ---------------------------------------------- |
| 1     | p₀ + O₁ + arêtes E₁ + E₃                       |
| 2     | p₀ + O₁ + arêtes E₁ + E₄                       |
| 3     | p₀ + O₁ + O₂ + arêtes E₂ + E₆ (subset)         |
| 4     | p₀ + O₂ + arêtes E₂ + E₈ (subset)              |
| 5     | tous sommets + arêtes E₅ + E₇ (subset)         |
|         …                                              |

Lors de la cérémonie de reconstruction, les k shards présentés **se complètent visuellement** pour reformer un cube reconnaissable, fournissant une preuve cérémonielle de quorum. Aucun autre schéma de visual hash ne permet cette propriété.

### 6.3 Migration cross-machine (Phase P3)

Le rebind Phase 3 produit un nouveau `machine_lock`, qui affecte `merkle_root` et donc les canaux C₃–C₅ (arêtes internes). Les canaux C₁, C₂, C₆ (sommets et arêtes externes liées à `vault_id` + `kyber_pk_fp`) restent stables. Diagnostic visuel : *centre et couronne extérieure inchangés ⇒ même voûte ; arêtes internes redessinées ⇒ machine différente*. Le rebind devient vérifiable à l'œil nu, en plus de la preuve Schnorr NIZK.

### 6.4 SAS visuel pour pairing Cipher (Phase P4)

Lors d'un échange Kyber initiateur–répondeur dans Cipher, les deux pairs dérivent un secret partagé ss ∈ {0,1}⁵¹². Chaque pair affiche son propre `.eopx` Métatron *plus* une **arête de couplage** entre les deux cubes, dont les attributs visuels sont déterminés par `HKDF(ss, info = "cipher.pairing.v1")`. Les deux pairs voient deux arêtes de couplage identiques si et seulement si ils ont dérivé le même secret — c'est le SAS de Signal généralisé en cryptographie post-quantique, mais avec une représentation cérémonielle, géométrique et précise.

### 6.5 Familles et généalogies de voûtes

Une voûte enfant V' dérivée d'une voûte parent V (selon un schéma futur de child-vault) peut être conçue de sorte que ses canaux C₀, C₁ restent identiques au parent et que seuls C₂, C₆ varient. Visuellement, **la généalogie est lisible** : tous les enfants partagent le centre, divergent sur la périphérie.

### 6.6 Ancrage on-chain

Le hash du `.eopx` (déjà inclus dans `payload_hash`) peut être ancré sur un registre distribué (Bitcoin OP_RETURN, Arweave, IPFS pinning) pour notarisation temporelle. Un observateur public retrouve visuellement à quelle voûte correspond l'ancrage en comparant le hash on-chain au rendu local — l'aspect visuel du Cube devient une **clé secondaire de recherche** humaine sur un registre froid.

---

## 7. Limites et risques

### 7.1 Le cube n'est *pas* un secret

Le mapping canaux ↔ champs est public. Quiconque connaît la spec peut, à partir d'un `.eopx`, lire visuellement les bits de `vault_id`, `merkle_root`, `kyber_pk_fp`. Mais ces champs **sont déjà publics** dans les chunks `tEXt` du PNG. Le rendu ne fait que les exposer dans un médium alternatif. Aucune fuite n'est créée.

### 7.2 Charge symbolique

Le Cube de Métatron porte une charge ésotérique. La doc utilisateur doit présenter le choix avec sobriété : « graphe complet K₁₃ dans son plongement classique dit Cube de Métatron » plutôt que références mystiques explicites. La rigueur mathématique de §2–3 doit dominer la communication.

### 7.3 Anti-pattern : ne pas utiliser le rendu comme preuve

Un attaquant peut copier intégralement un `.eopx` Métatron. Le rendu n'est pas un certificat — la signature Dilithium5 l'est. Toute UX construite sur Esoptron doit afficher le statut de vérification cryptographique de manière au moins aussi visible que le rendu lui-même.

### 7.4 Évolution du standard

Le profil `metatron_v1` doit être figé par hash spec dès la première publication. Toute évolution donne `metatron_v2`, distingué par le chunk `eopx:render_style`. Les vérificateurs anciens doivent rejeter explicitement les versions inconnues.

### 7.5 Coût de rendu

Sur un mobile standard, le rendu complet (936 bits → 512×512 PNG anti-aliasé déterministe) coûte ~10–30 ms. Négligeable. Le décodage et la vérification pixel-à-pixel coûtent ~5 ms. Tout cela est inférieur d'un ordre de grandeur au coût ML-DSA (~ms aussi mais avec primitives natives) — pas de goulot.

---

## 8. Spécification minimale (esquisse non normative)

```
profile = "metatron_v1"
canvas  = 512 × 512 sRGB PNG, profile "sRGB IEC61966-2.1"
margin  = 32 px
center  = (256, 256)
unit    = (canvas_size − 2·margin) / (2·√3)  ; rayon hexagone externe
nodes   = 13 disques de rayon 18 px, positions §2.1 × unit
edges   = 78 segments tracés selon ordre canonique §2.3,
          rendus en passe alpha-blending dans l'ordre lex inverse
          pour garantir un compositing déterministe
```

Chunks `tEXt` ajoutés au PNG :

```
eopx:render_style = metatron_v1
eopx:render_spec_hash = SHA3-256(spec_metatron_v1.md)
```

La spec technique complète (algorithme de rastérisation, table glyphes, table OKLCH, ordre de compositing exact, paramètres anti-aliasing) fera l'objet d'un document séparé `spec_metatron_v1.md` à figer avant implémentation.

---

## 9. Conclusion

Le Cube de Métatron, identifié au plongement euclidien canonique du graphe complet K₁₃, fournit à Esoptron une toile cryptographique satisfaisant simultanément cinq propriétés rarement réunies dans un même objet : capacité informationnelle suffisante (≥ 512 bits avec marge × 1.8), ordre canonique calculable, invariance perceptuelle sous le groupe diédral D₆, décomposition orbitale alignable sur les champs sémantiques d'une voûte Eidolon, et lisibilité humaine cérémonielle.

Le rendu proposé est strictement déterministe, n'introduit aucune nouvelle hypothèse cryptographique, et s'insère dans le cadre `.eopx` existant comme une simple variante du moteur de rendu, signalée par le chunk `eopx:render_style = metatron_v1`. Toute la sécurité repose sur les primitives post-quantiques déjà éprouvées (ML-DSA, Kyber1024, SHA3, Shamir GF(2⁸), NIZK Schnorr).

Au-delà du gain esthétique et symbolique immédiat (Phase P1), le rendu Métatron débloque des cas d'usage qualitativement nouveaux dans les phases suivantes : Shamir Visual Sharding où la reconstruction est *visuellement* cérémonielle (P2), migration de machine vérifiable à l'œil par stabilité des canaux externes (P3), SAS visuel post-quantique pour le pairing Cipher (P4), et perspectives long terme en généalogie de voûtes et ancrage on-chain humainement adressable.

Cette proposition fait du `.eopx` non plus un fichier signé doté d'un visuel accessoire, mais une **interface cryptographique multimodale** où l'image *est* la vérification, à la fois pour la machine et pour l'humain. Elle achève la promesse étymologique d'Esoptron : ἔσοπτρον, *le miroir qui reflète sans révéler*.

---

## Annexe A — Notation

| Symbole          | Signification                                              |
| ---------------- | ---------------------------------------------------------- |
| K₁₃              | graphe complet à 13 sommets                                |
| G = (V, A)       | graphe sous-jacent au Cube de Métatron                     |
| O₀, O₁, O₂       | orbites de sommets sous D₆                                 |
| E₁, …, E₈        | orbites d'arêtes sous D₆                                   |
| D₆               | groupe diédral d'ordre 12                                  |
| 𝔽₁₃              | corps fini à 13 éléments                                   |
| `spinor_hash`    | sortie Phase 6 d'Eidolon, ∈ {0,1}⁵¹²                       |
| `merkle_root`    | sortie Phase 9 d'Eidolon, ∈ {0,1}²⁵⁶                       |
| `payload_hash`   | SHA3-512 du payload `.eopx`, signé en ML-DSA               |
| HKDF             | HMAC-based Key Derivation Function (RFC 5869) avec SHA3-512|
| OKLCH            | espace de couleurs perceptuel L·C·h                         |

## Annexe B — Références

- **Eidolon Whitepaper** (interne) — Holographic Key Derivation, Phases 1 à 9.
- **Esoptron README** — *Visual Vault Identity*, présent dépôt.
- **eopx_format_spec.docx**, **eopx_verify_spec.docx** — présent dépôt.
- **NIST FIPS 204** — ML-DSA (Dilithium5).
- **NIST FIPS 203** — ML-KEM (Kyber1024).
- **NIST FIPS 202** — SHA-3.
- **RFC 5869** — HKDF.
- **Björner, A.** — *Topological Methods in Combinatorics* (orbites de graphes).
- **Coxeter, H. S. M.** — *Regular Polytopes* (groupe diédral D₆, géométrie hexagonale).
- **Melchizedek, D.** — *The Ancient Secret of the Flower of Life* (origine traditionnelle du Cube de Métatron ; cité pour exhaustivité, non pour autorité mathématique).
- **Dodis, Reyzin, Smith** — *Fuzzy Extractors* (référence pour Pivot A/B futur, hors scope de ce whitepaper).

---

*Fin du draft v0.1. Document à figer par hash dans `eopx:render_spec_hash` lors de la publication de la spec normative `spec_metatron_v1.md`.*
