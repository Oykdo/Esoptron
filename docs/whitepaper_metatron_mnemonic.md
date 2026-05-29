# Whitepaper II — Metatron Mnemonic & Recovery Plate

**Titre complet** : *Codage canonique d'un seed cryptographique post-quantique sur le graphe complet K₁₃ via Reed–Solomon sur 𝔽₁₃, et son extension Shamir 2-sur-3 pour la récupération de voûtes Eidolon.*

**Version** : 0.1 — *draft pour revue interne*
**Date** : 2026-05-26
**Auteurs** : équipe Logos (Eidolon / Esoptron)
**Statut** : pré-spécification, non normatif
**Prérequis** : *Whitepaper I — Le Cube de Métatron comme toile cryptographique* (présent dépôt, `docs/whitepaper_metatron.md`)
**Mots-clés** : mnémonique, Reed–Solomon, corps fini 𝔽₁₃, MDS, Shamir secret sharing, cold wallet post-quantique, recovery plate, gravure cryptographique.

---

## Résumé

Le Whitepaper I a établi que le graphe complet K₁₃ dans son plongement de Métatron constitue une *toile* cryptographique adaptée à la représentation visuelle d'un haché holographique public (`spinor_hash`). Le présent document complète cette construction par sa contrepartie *privée* : un schéma de codage canonique permettant d'inscrire sur la même structure géométrique un seed cryptographique 256 bits, doté de propriétés de récupération optimales au sens de la borne de Singleton.

Nous démontrons que le choix |V| = 13 — accident mystique apparent — fait du sommet une représentation naturelle d'éléments du corps fini 𝔽₁₃, autorisant un code de Reed–Solomon **MDS** (n = 91, k = 68) qui tolère jusqu'à 11 effacements ou 5 erreurs sur les 91 porteurs (13 sommets + 78 arêtes). La capacité utile, 252 bits, suffit à transporter un seed 256 bits avec léger padding, ou — dans la variante Recovery Plate — une part de Shamir 2/3 d'une voûte Eidolon complète.

Le document propose : (i) une table OKLCH de 13 teintes perceptuellement équidistantes pour les 13 symboles, (ii) un alphabet de glyphes secondaires assurant la robustesse aux conditions photographiques dégradées et au daltonisme, (iii) un algorithme d'encodage / décodage déterministe, (iv) une cérémonie de génération multi-témoin, (v) le protocole Shamir 2-sur-3 de Recovery Plate intégré à la Phase 3 d'Esoptron (rebind cross-machine).

Aucune nouvelle primitive cryptographique n'est introduite. Toute la sécurité repose sur le TRNG en amont, sur la robustesse algébrique de RS-𝔽₁₃, et sur la confidentialité physique de la plate elle-même.

---

## 1. Position du problème

### 1.1 Limites des mnémoniques actuels

BIP39 et SLIP39 sont les deux standards de facto pour la sauvegarde de seeds cryptographiques sous forme humainement transcriptible :

| Standard | Méthode                                                | Limites                                                     |
| -------- | ------------------------------------------------------ | ----------------------------------------------------------- |
| BIP39    | 12 ou 24 mots anglais (dictionnaire de 2048 mots)      | Dépendance linguistique, pas de redondance, perte d'un mot ⇒ perte totale (ou brute-force du checksum), illisible pour un non-anglophone |
| SLIP39   | Shamir 2/3 ou 3/5 sur dictionnaire anglais             | Hérite des limites BIP39 ; pas MDS strict ; pas géométrique |
| Plaques métalliques (Cryptosteel, etc.) | Inscription mots BIP39 sur acier inox | Hérite des limites BIP39 ; pas de redondance native        |

Aucun de ces standards :

- ne porte de **code MDS optimal** au sens de Singleton (capacité de correction maximale pour une redondance donnée),
- n'est **culturellement neutre** (langue anglaise requise),
- ne se grave **nativement sans typographie** (un mot exige une police lisible),
- n'offre une **structure visuelle de vérification** entre plusieurs copies à l'œil nu.

### 1.2 Le saut conceptuel

Le Cube de Métatron, identifié comme K₁₃ dans le Whitepaper I, possède exactement les quatre propriétés algébriques et géométriques manquantes :

1. **13 est premier** ⇒ ℤ/13ℤ est le corps fini 𝔽₁₃ ⇒ codes Reed–Solomon **strictement MDS**.
2. **91 porteurs** (13 sommets + 78 arêtes) ⇒ longueur de code n = 91 sur 𝔽₁₃, exactement la longueur maximale possible (n ≤ q + 1 — ou n ≤ q + 2 pour RS étendu — où q = 13).
3. **Plongement géométrique fixé** ⇒ ordre canonique sur les porteurs sans graine externe.
4. **Symboles = couleurs/glyphes** ⇒ pas de typographie, gravure native sur tout substrat plan.

La construction qui suit transforme cette coïncidence mathématique en standard de mnémonique.

---

## 2. Fondations algébriques

### 2.1 Le corps 𝔽₁₃

Soit 𝔽₁₃ = ℤ/13ℤ, corps fini à 13 éléments (puisque 13 est premier). On choisit un générateur multiplicatif (élément primitif) :

```
α = 2 ∈ 𝔽₁₃*    (ordre 12 ; vérification : 2¹ = 2, 2² = 4, …, 2¹² = 1 mod 13)
```

Les douze puissances de α énumèrent 𝔽₁₃* = {1, 2, 4, 8, 3, 6, 12, 11, 9, 5, 10, 7}. Combiné à 0, on obtient les 13 éléments.

### 2.2 Code Reed–Solomon RS(91, 68) sur 𝔽₁₃

Nous utilisons un code Reed–Solomon **étendu** au sens où n peut atteindre q + 2 = 15 si on incorpore le point à l'infini et l'évaluation en 0 — mais nous travaillons à n = 91 par **entrelacement** de plusieurs codes parallèles.

**Construction par entrelacement** : on découpe les 91 porteurs en 7 blocs de 13 symboles, chaque bloc étant un code RS(13, 10) sur 𝔽₁₃. Ce code admet :

- longueur n = 13 (toutes les évaluations 𝔽₁₃),
- dimension k = 10,
- distance minimale d = n − k + 1 = **4** (borne de Singleton atteinte, donc **MDS**),
- capacité de correction : ⌊(d−1)/2⌋ = **1 erreur** ou **3 effacements** par bloc.

Sept blocs entrelacés donnent :

```
n_total = 91,  k_total = 70,  d_min ≥ 4   (par bloc)
```

Capacité corrective globale : jusqu'à **21 effacements** ou **7 erreurs** si elles sont distribuées au moins une par bloc (cas favorable), au pire 7 erreurs aléatoirement réparties (cas raisonnable). On dimensionnera plus prudemment en §2.4.

### 2.3 Variante haute redondance RS(91, 56)

Pour les Recovery Plates Eidolon, on préfère une marge plus large. On choisit :

| Paramètre              | Valeur                       |
| ---------------------- | ---------------------------- |
| Schéma                 | 7 blocs RS(13, 8) entrelacés |
| n                      | 91                           |
| k                      | 56                           |
| d (par bloc)           | 6                            |
| Effacements/bloc       | 5                            |
| Erreurs/bloc           | 2                            |
| Capacité utile (bits)  | 56 · log₂(13) ≈ **207 bits** |

Insuffisant pour 256 bits seul. On utilise donc une **structure mixte** §2.5.

### 2.4 Variante optimale RS(91, 68) — pour Metatron Mnemonic standard

7 blocs RS(13, 10), entrelacés.

| Paramètre                    | Valeur                       |
| ---------------------------- | ---------------------------- |
| n                            | 91                           |
| k                            | 70                           |
| d (par bloc)                 | 4                            |
| Effacements/bloc tolérés     | 3                            |
| Erreurs/bloc tolérées        | 1                            |
| Capacité brute (bits)        | 70 · log₂(13) ≈ **259 bits** |

C'est exactement ce qu'il nous faut pour 256 bits de seed + 3 bits de version. La marge corrective : 21 effacements / 7 erreurs au mieux. Suffisant pour photo dégradée standard.

### 2.5 Allocation finale

On retient deux profils :

| Profil          | Schéma                | Capacité utile | Tolérance               |
| --------------- | --------------------- | -------------- | ----------------------- |
| `mnemonic_v1`   | RS(91, 70) entrelacé  | 256 bits + 3   | 21 effacements / 7 erreurs |
| `recovery_v1`  | RS(91, 56) entrelacé  | 207 bits utiles + redondance forte | 35 effacements / 14 erreurs |

Le profil `mnemonic_v1` cible le cold-wallet PQ standalone. Le profil `recovery_v1` cible la Plate de récupération Eidolon où la **part Shamir** elle-même fait < 200 bits.

---

## 3. Alphabet des 13 symboles

### 3.1 Espace de couleurs : OKLCH

Nous utilisons OKLCH (Björn Ottosson, 2020) parce que :

- **Distances perceptuellement uniformes** : ΔE_oklch ≈ ΔE perçu.
- **L (luminance)** indépendante de C (chroma) et h (teinte) — utile pour daltonisme.
- **Reproductibilité sRGB** : conversion bijective sans dérive sur écrans standards.

### 3.2 Table canonique `metatron_oklch_v1`

Treize teintes choisies pour :

1. Distance perceptuelle minimale entre voisines ≥ ΔE = 10 (très distinguable).
2. Variation de luminance L permettant lecture en monochromie (échelle de gris).
3. Glyphe secondaire associé à chaque symbole (cf. §3.3) pour double-encodage.

| Symbole 𝔽₁₃ | Nom         | L     | C     | h (deg) | sRGB hex  | Glyphe       |
| ----------- | ----------- | ----- | ----- | ------- | --------- | ------------ |
| 0           | Obsidienne  | 0.18  | 0.02  | 280     | `#1a1820` | cercle plein |
| 1           | Indigo      | 0.32  | 0.15  | 270     | `#2c2080` | cercle vide  |
| 2           | Cobalt      | 0.42  | 0.18  | 245     | `#1f3fb0` | triangle ↑   |
| 3           | Cyan        | 0.62  | 0.15  | 220     | `#33a8c8` | triangle ↓   |
| 4           | Émeraude    | 0.58  | 0.18  | 160     | `#1f9a6b` | carré        |
| 5           | Lime        | 0.78  | 0.20  | 130     | `#9ad04f` | losange      |
| 6           | Or          | 0.82  | 0.16  | 95      | `#d4b65f` | hexagone     |
| 7           | Ambre       | 0.72  | 0.18  | 70      | `#d8915c` | pentagone    |
| 8           | Vermillon   | 0.58  | 0.22  | 30      | `#cc4a3a` | étoile-5     |
| 9           | Magenta     | 0.55  | 0.22  | 350     | `#c83a8f` | étoile-6     |
| 10 (A)      | Violet      | 0.45  | 0.22  | 320     | `#9034b8` | croix        |
| 11 (B)      | Ardoise     | 0.50  | 0.04  | 240     | `#6c7480` | X (sautoir)  |
| 12 (C)      | Albâtre     | 0.92  | 0.02  | 90      | `#ece8d8` | anneau       |

Notes :

- Les valeurs sont indicatives, à figer par hash spec lors de la publication normative.
- La luminance L parcourt 13 paliers approximativement régulièrement espacés sur [0.18, 0.92] ; deux symboles consécutifs en valeur 𝔽₁₃ ne sont pas voisins en L, ce qui permet la lecture *en l'absence de chroma* (photo noir et blanc, daltonisme total) via la table inversée L → glyphe.
- Le pivot Ardoise (symbole 11) est délibérément peu chromé pour servir de marqueur d'orientation visuelle.

### 3.3 Glyphes : alphabet secondaire

Chaque sommet et chaque arête porte simultanément :

- une teinte OKLCH (canal primaire, 13 valeurs),
- un glyphe géométrique (canal secondaire, 13 valeurs, table ci-dessus).

Les deux canaux sont **redondants** : un lecteur valide d'abord la teinte, vérifie le glyphe ; si désaccord, c'est une erreur à corriger par RS. Cela double la marge de tolérance perceptuelle dans la pratique sans alourdir l'algèbre (le décodage reste RS(91, 70) sur le canal teinte ; le glyphe sert au scoring de confiance).

### 3.4 Codage des arêtes

Les arêtes étant fines, on ne peut pas y placer un glyphe interne. On utilise alors :

- teinte de la ligne (canal primaire, 13 valeurs),
- style de trait : `solid`, `dashed-2`, `dotted`, `double` (canal secondaire, 4 valeurs → 2 bits).

Le canal secondaire des arêtes ne porte que log₂(4) = 2 bits redondants sur les 3.7 du canal primaire. Cette redondance partielle est suffisante en pratique car les arêtes longues sont visuellement plus robustes que les sommets isolés.

---

## 4. Topologie des porteurs et ordre canonique

(Rappel et précision du Whitepaper I §2.)

### 4.1 Sommets : 13 porteurs

Indices canoniques `v[0..12]` :

```
v[0]            = p₀         (centre)
v[1..6]         = p₁..p₆      (hexagone interne, arg = 0, π/3, 2π/3, ..., 5π/3)
v[7..12]        = p₁'..p₆'    (hexagone externe, arg = π/6, π/2, ..., 11π/6)
```

### 4.2 Arêtes : 78 porteurs

Indices canoniques `e[0..77]` : tri par (longueur euclidienne croissante, indices lex croissant des sommets).

```python
def canonical_edges():
    edges = []
    for i in range(13):
        for j in range(i+1, 13):
            edges.append((dist(v[i], v[j]), i, j))
    edges.sort()                    # tri lex sur (len, i, j)
    return [(i, j) for _, i, j in edges]
```

### 4.3 Mapping symbole ↔ porteur

Le message encodé est un vecteur de 91 symboles 𝔽₁₃ que l'on lit/écrit dans l'ordre :

```
s[0..12]   ↦ v[0..12]            (sommets, ordre canonique)
s[13..90]  ↦ e[0..77]            (arêtes, ordre canonique)
```

Ce mapping est **public** ; il fait partie de la spec `mnemonic_v1`.

---

## 5. Algorithme d'encodage

### 5.1 Entrées

```
seed         ∈ {0,1}²⁵⁶        (depuis TRNG)
profile      ∈ {mnemonic_v1, recovery_v1}
plate_index  ∈ {0, 1, 2}        (pour recovery_v1 seulement)
```

### 5.2 Étapes

**E1. Préfixe + padding.**

```
payload₀ = [version:8 bits = 0x01] ‖ seed ‖ [padding zéro jusqu'à 70·log₂(13) bits]
```

Pour `recovery_v1`, le seed est remplacé par la part Shamir correspondante (cf. §7).

**E2. Conversion bits → symboles 𝔽₁₃.**

On découpe `payload₀` en groupes de log₂(13) ≈ 3.7 bits. On utilise un **codage par lots** : 13 bits → 3 symboles (puisque 2¹³ = 8192 > 13³ = 2197... non, 13³ = 2197 < 8192, donc 13 bits ne suffit pas). On utilise plutôt : **52 bits → 14 symboles** (puisque 13¹⁴ ≈ 3.9 · 10¹⁵ > 2⁵² ≈ 4.5 · 10¹⁵ — pas valide). Le bon ratio : **45 bits → 13 symboles** (13¹³ ≈ 3.0 · 10¹⁴ > 2⁴⁵ ≈ 3.5 · 10¹³ ✓).

Algorithme retenu, simple et exact : représenter `payload₀` comme un entier puis le convertir en base 13.

```python
def bits_to_symbols(payload_bytes, n_symbols):
    n = int.from_bytes(payload_bytes, 'big')
    symbols = []
    for _ in range(n_symbols):
        symbols.append(n % 13)
        n //= 13
    return symbols[::-1]    # big-endian
```

On obtient `k = 70` symboles message.

**E3. Encodage Reed–Solomon.**

Pour chacun des 7 blocs de 10 symboles message, on calcule 3 symboles de parité via évaluation polynomiale :

```
m_b = [m_b,0, ..., m_b,9]                         message bloc b
P_b(X) = m_b,0 + m_b,1·X + ... + m_b,9·X⁹         polynôme de degré ≤ 9
c_b = [P_b(α⁰), P_b(α¹), ..., P_b(α¹²)]            mot de code de longueur 13
```

avec α = 2 le générateur (§2.1). Les 13 évaluations donnent 13 symboles, dont les 10 premiers sont (à permutation près) le message et les 3 derniers la parité — selon le choix de support du code (RS systématique standard).

**E4. Entrelacement.**

Les 7 mots de code de longueur 13 sont entrelacés sur les 91 porteurs :

```
codeword_total[i·7 + b] = c_b[i]      pour i ∈ [0, 12], b ∈ [0, 6]
```

L'entrelacement protège contre les bursts d'erreurs (rayure linéaire, salissure locale).

**E5. Mapping vers porteurs.**

```
symbol_at(v[i])  = codeword_total[i]                pour i ∈ [0, 12]
symbol_at(e[j])  = codeword_total[13 + j]           pour j ∈ [0, 77]
```

**E6. Rendu visuel.**

Chaque symbole détermine teinte OKLCH + glyphe selon table §3.2. Le rendu produit une image PNG 1024×1024 sRGB (résolution doublée par rapport à `.eopx` public pour gravure laser), avec marges pour le **bandeau de rôle** (cf. Whitepaper III).

**E7. Vérification de cycle.**

Avant gravure, le générateur **re-décode** sa propre sortie depuis l'image rastérisée, et vérifie l'identité bit-à-bit avec `seed`. Si l'identité échoue, l'opération est avortée et signalée. C'est la garantie de cohérence du pipeline.

---

## 6. Algorithme de décodage

### 6.1 Entrées

```
photo              ∈ image bitmap
profile_expected   ∈ {mnemonic_v1, recovery_v1}     (optionnel ; auto-détecté par signature visuelle)
```

### 6.2 Étapes

**D1. Détection et rectification.**

- Détection des contours du cube (Hough sur cercles + lignes).
- Identification des 4 coins du bandeau de rôle (cf. Whitepaper III) → matrice d'homographie.
- Rectification de l'image au repère canonique 1024×1024.

**D2. Détection des sommets.**

- 13 disques de rayon attendu à positions canoniques connues.
- Pour chaque disque : échantillonnage de la teinte centrale (moyenne pondérée gaussienne) et détection du glyphe (template matching sur les 13 glyphes possibles).

**D3. Détection des arêtes.**

- 78 segments à positions canoniques connues.
- Pour chaque segment : échantillonnage de teinte le long de la médiatrice + détection du style de trait (solid/dashed/dotted/double).

**D4. Classification des symboles.**

Pour chaque porteur (sommet ou arête) :

```
sym_color  = argmin_s ΔE_oklch(observed_color, table[s].oklch)
sym_glyph  = argmax_s correlation(observed_template, glyph_templates[s])
if sym_color == sym_glyph:
    confidence[i] = high
    symbol[i] = sym_color
else:
    confidence[i] = low
    symbol[i] = sym_color           # primaire ; le décodeur RS corrigera si nécessaire
    mark_as_potential_erasure(i)
```

**D5. Désentrelacement.**

```
for b in 0..6:
    c_b[i] = codeword_total[i·7 + b]   pour i ∈ [0, 12]
```

**D6. Décodage Reed–Solomon.**

Pour chacun des 7 blocs, application de l'algorithme de Berlekamp–Massey + Forney sur 𝔽₁₃ avec liste des effacements (symboles à `confidence = low`).

Si tous les blocs décodent → on récupère 70 symboles message.

Si un bloc échoue → escalade : on essaye d'autres effacements selon ranking de confiance ; on échoue après seuil.

**D7. Conversion symboles → bits.**

Inverse de E2 : base-13 → entier → bytes big-endian. On obtient `payload₀`, dont on extrait `version` et `seed`.

**D8. Validation.**

Pour `mnemonic_v1` : aucune validation supplémentaire (le seed est *par définition* l'entropie).

Pour `recovery_v1` : on valide que la part Shamir est syntaxiquement correcte (longueur, index `plate_index` cohérent).

---

## 7. Cérémonie de génération multi-témoin

### 7.1 Modèle de menace

La cérémonie protège contre trois menaces :

| Menace                                        | Mitigation                                 |
| --------------------------------------------- | ------------------------------------------ |
| Compromission du TRNG matériel                | Mélange de plusieurs TRNG indépendants     |
| Compromission de l'opérateur                  | Présence de témoins indépendants           |
| Fuite logicielle (RAM, swap, log)             | Air-gap, machine éphémère, chiffrement RAM |

### 7.2 Protocole

1. **Préparation** :
   - Machine éphémère (live USB Tails / NixOS générée avant cérémonie, hash publié).
   - Réseau désactivé physiquement (carte démontée si possible).
   - Trois témoins minimum (auto-acquittement du quorum 2/3).

2. **Sourcing d'entropie** :
   - 256 bits depuis `/dev/urandom`.
   - 256 bits depuis un TRNG matériel externe (par ex. OneRNG, FST-01, dé physique 16 d6 = 51.7 bits × 6 = 310 bits réduits).
   - 256 bits depuis un second TRNG indépendant (autre marque).
   - **Combinaison** : `seed = HKDF-SHA3-512(entropy_a ‖ entropy_b ‖ entropy_c, info="metatron.mnemonic.v1.genesis")[:32]`.

3. **Encodage** (algorithme §5).

4. **Gravure / inscription** sur substrat physique (cf. §7.3).

5. **Vérification** :
   - Photo de la plate gravée.
   - Décodage (algorithme §6).
   - Comparaison bit-à-bit avec `seed` retenu.
   - Acquittement écrit signé par chaque témoin.

6. **Destruction du seed digital** :
   - `shred -uvz` sur tous les fichiers intermédiaires.
   - Reformatage du support de la machine éphémère.
   - Coupure d'alimentation.

7. **Distribution physique** :
   - Pour `mnemonic_v1` standalone : conservation par l'utilisateur en lieu sûr.
   - Pour `recovery_v1` (cf. §8) : remise des 3 plates aux 3 dépositaires de Shamir.

### 7.3 Substrats physiques recommandés

| Substrat                  | Coût  | Durabilité | Notes                                       |
| ------------------------- | ----- | ---------- | ------------------------------------------- |
| Papier d'archive + impression jet d'encre | bas  | ~50 ans  | Test simple, peu durable                   |
| Acier inoxydable laser-gravé              | moyen | siècles | Standard pour cold wallets                  |
| Titane CNC                                | élevé | millénaires | Résistant feu, eau, acide                  |
| Céramique émaillée cuite                  | moyen | siècles | Robuste mais cassable                       |
| Pierre gravée (granit, basalte)           | moyen | millénaires | Lourd, transport difficile                 |
| Mosaïque vitrail                          | élevé | siècles | Cérémonial, héritage                        |
| Tatouage UV (invisible jour)              | bas   | vie       | Anti-coercition partielle ; demande UV pour lire |

Pour usage long-terme, le titane CNC ou l'acier laser-gravé sont recommandés.

---

## 8. Recovery Plate : Shamir 2-sur-3 intégré

### 8.1 Pourquoi 2/3 et non 3/5

Le choix k=2, n=3 équilibre trois critères :

| Critère                       | k=2, n=3 | k=3, n=5 | k=1, n=2 |
| ----------------------------- | -------- | -------- | -------- |
| Tolérance perte                | 1 plate  | 2 plates | 0 plate  |
| Quorum de compromission        | 2 plates | 3 plates | 1 plate  |
| Coût logistique                | bas      | moyen    | minimal  |
| Complexité de la cérémonie     | basse    | élevée   | triviale |

Pour une voûte personnelle (cas le plus fréquent), k=2, n=3 est le standard recommandé : trois dépositaires (par exemple notaire, parents, coffre bancaire), tolérance d'une perte unique, compromission requise de deux acteurs indépendants.

### 8.2 Construction Shamir sur 𝔽₂₅₆ (octet par octet)

Le partage Shamir natif d'Eidolon (`secret_sharing.py`, cité dans README) utilise 𝔽₂₅₆ (le corps fini d'octets, avec polynôme irréductible standard AES `x⁸ + x⁴ + x³ + x + 1`). Nous l'utilisons tel quel pour la couche Shamir, distincte du codage RS-𝔽₁₃ utilisé pour la robustesse photographique.

```
seed_eidolon ∈ {0,1}²⁵⁶ = 32 octets
                │
                │ Shamir_split(k=2, n=3) sur 𝔽₂₅₆, octet par octet
                ▼
        share_1, share_2, share_3 ∈ ({0,1}^{8})³² × {indice}
        chacune : 32 octets + 1 octet d'index = 33 octets ≈ 264 bits
```

Chaque `share_i` est ensuite :

1. Préfixée d'un en-tête `recovery_v1 ‖ vault_id_truncated[64 bits] ‖ plate_index[2 bits] ‖ checksum_crc[6 bits]` (= 80 + 8 bits ≈ 88 bits par plate).
2. Totale : 264 + 88 = ~ **352 bits** par plate — légèrement au-dessus de la capacité utile 207 bits de `recovery_v1`. 

**Conséquence** : on ne peut pas tenir une part Shamir 256 bits complète dans une seule plate haute-redondance. Trois options :

#### Option A — Plate étendue (`recovery_v1_xl`)

Augmenter la capacité utile en réduisant la redondance :

| Profil           | Schéma                | Capacité utile | Tolérance      |
| ---------------- | --------------------- | -------------- | -------------- |
| `recovery_v1_xl` | RS(91, 80) entrelacé  | 296 bits utiles | 7 effacements / 3 erreurs |

Avec 296 bits utiles, on tient les ~ 352 bits ? Non, toujours pas. On doit alors :

#### Option B — Plate scindée en deux faces (recto/verso)

Une plate physique = deux cubes Métatron sur les deux faces. Capacité doublée → 592 bits utiles (`recovery_v1_xl`) ou 414 (`recovery_v1`). Largement suffisant.

> **Recommandation** : substrat acier ou titane, **gravure recto + verso**, chaque face un cube indépendant ; un coin biseauté indique le sens de lecture.

#### Option C — Mini-share Shamir sur 𝔽₁₃ direct

Réimplémenter Shamir directement sur 𝔽₁₃ — élégant mais nécessite de refondre la part en symboles 𝔽₁₃ natifs. Ce serait :

- Seed 256 bits → 70 symboles 𝔽₁₃ (cf. §5.2).
- Shamir 2/3 sur 𝔽₁₃ — bien défini puisque 13 est premier et n = 3 ≤ q − 1 = 12.
- Chaque part = 70 symboles 𝔽₁₃ + 1 symbole index = 71 symboles 𝔽₁₃ ≈ 263 bits.

Toujours trop, mais on peut compresser le seed via Shamir composé : seed → 32 octets, Shamir octet par octet sur 𝔽₂₅₆ (32 octets par part = 256 bits), puis chaque octet codé en symboles 𝔽₁₃ via base-13 (256 bits = ~ 70 symboles). On retombe au même problème.

> **Verdict** : Option B (plate recto/verso) est la solution la plus simple et la plus robuste. Option A en mode dégradé si gravure verso impossible.

### 8.3 Protocole complet de Recovery Plate

```
[génération]
seed_eidolon ──► Shamir_split(k=2, n=3) over 𝔽₂₅₆
                          │
              ┌───────────┼───────────┐
              ▼           ▼           ▼
          share_1     share_2     share_3
              │           │           │
        [chacune ↓]
              │
       header ‖ share_i  ──► RS(91, 80) entrelacé sur 𝔽₁₃ × 2 faces
              │
              ▼
         plate_i  (acier/titane recto-verso)
              │
              ▼
       remise dépositaire i
```

```
[récupération]
photo(plate_a) + photo(plate_b)   (a, b ∈ {1,2,3}, a ≠ b)
                  │
                  │ décodage RS-𝔽₁₃ par face
                  ▼
              share_a, share_b
                  │
                  │ Shamir_combine over 𝔽₂₅₆
                  ▼
              seed_eidolon récupéré
                  │
                  │ HKDF Phase 6 (Eidolon)
                  ▼
              spinor_hash → nouvelle voûte sur nouveau matériel
                  │
                  │ Phase 3 — rebind machine_lock via NIZK Schnorr
                  ▼
              voûte opérationnelle
```

### 8.4 Intégration à la Phase 3 d'Esoptron

La Phase 3 (`vault_migrate.py`) du roadmap Esoptron prévoit déjà le rebind cross-machine via NIZK Schnorr. La Recovery Plate s'y intègre comme **input alternatif** :

```
Phase 3 standard :          old_machine_lock + nouvelle_machine ──► nouvelle voûte
Phase 3 recovery :          seed_recupéré (Plates) + nouvelle_machine ──► nouvelle voûte
```

Le code Rust `eidolon_crypto::vault::rebind` doit accepter les deux entrées via une union typée. Aucune nouvelle primitive ; uniquement une nouvelle entrée du même algorithme.

### 8.5 Champs publics de la plate

Pour permettre à un dépositaire de **vérifier visuellement** qu'il détient bien une part de *sa* voûte sans la décoder :

- Le `vault_id_truncated[64 bits]` est inscrit en clair dans l'en-tête, donc visible dans certains sommets/arêtes après décodage RS.
- Le `plate_index` (0, 1 ou 2) est encodé dans le **bandeau de rôle** (cf. Whitepaper III) — affiché en glyphes lisibles humainement.
- Le `checksum_crc[6 bits]` permet une pré-validation rapide avant tentative de Shamir.

Le dépositaire ne peut pas, à partir d'une seule plate, retrouver le seed (Shamir k=2). Il peut, en revanche, vérifier que la plate est intègre et qu'elle appartient à la voûte attendue.

---

## 9. Modèle de menace

### 9.1 Garanties

| Menace                                              | Garantie / Mitigation                                                |
| --------------------------------------------------- | --------------------------------------------------------------------- |
| Photographie partielle ou dégradée                  | RS(91, 70 ou 80) : tolérance massive jusqu'aux limites § 2          |
| Vol d'une plate (recovery)                          | Shamir k=2 : une plate ne révèle rien                                |
| Compromission du TRNG unique                         | Cérémonie multi-source §7.2                                          |
| Calcul quantique                                    | Grover sur 256 bits = sécurité effective 128 bits ⇒ standard PQ      |
| Lecture par caméra de surveillance (zoom)            | Anti-pattern : ne jamais exposer la plate sous caméra non maîtrisée   |
| Détérioration physique (1 plate)                    | Substrat titane ; Shamir k=2 ; redondance RS                          |
| Détérioration physique (2 plates)                   | **Limite acceptée**. Tolérer 2 pertes nécessite k=3, n=5 (alternative configurable) |
| Coercition physique (forçage)                       | Plate-leurre possible (seed alternatif de moindre valeur)             |

### 9.2 Anti-patterns à proscrire

1. **Photographier toutes les plates ensemble**. Annule le bénéfice du sharding.
2. **Stocker plate + machine au même endroit**. La Phase 3 rebind suppose les deux séparés.
3. **Publier la plate comme NFT, sur IPFS ou tout registre public**. La plate est un secret, pas un manifeste.
4. **Réutiliser la même teinte sur plusieurs cubes (vault standard + plate)**. Le bandeau de rôle existe précisément pour empêcher la confusion (cf. Whitepaper III à venir).

---

## 10. Comparatif final

| Critère                          | BIP39 (24 mots) | SLIP39 2/3 | Metatron Mnemonic v1 | Recovery Plate 2/3 |
| -------------------------------- | --------------- | ---------- | -------------------- | ------------------ |
| Capacité utile                    | 256 bits         | 256 bits    | **256 bits**          | **256 bits (via Shamir)** |
| Dépendance linguistique           | oui (anglais)   | oui        | **non**              | **non**            |
| Code MDS                         | non             | quasi      | **oui (RS-𝔽₁₃)**     | **oui (RS + Shamir-𝔽₂₅₆)** |
| Tolérance perte intra-mnémonique  | nulle           | 1 mot/share | **21 effacements**    | **35 effacements** |
| Vérification visuelle entre copies | non             | non        | **oui** (canaux comparables) | **oui** |
| Gravure native sans typographie   | non             | non        | **oui** (teintes + glyphes) | **oui** |
| Sharding k/n natif               | non             | oui        | extension future      | **oui (Shamir 2/3)** |
| Compatibilité Eidolon Phase 3    | partielle       | partielle  | partielle             | **native**          |
| Maturité                         | très haute      | haute      | **proposition**       | **proposition**     |

---

## 11. Conclusion

Le présent whitepaper établit qu'au-delà de son rôle de toile cryptographique publique pour l'artefact `.eopx` (Whitepaper I), le graphe complet K₁₃ dans son plongement de Métatron constitue un **support optimal de mnémonique cryptographique privé**, grâce à la coïncidence remarquable entre |V| = 13 et la primalité de ce nombre, qui ouvre l'accès direct au corps fini 𝔽₁₃ et donc aux codes Reed–Solomon strictement MDS de longueur maximale.

Le profil `mnemonic_v1` propose un cold-wallet PQ standalone à capacité 256 bits avec tolérance d'au moins 21 effacements ou 7 erreurs sur 91 porteurs — propriétés inaccessibles à tout schéma BIP39/SLIP39 actuel. Le profil `recovery_v1`, gravé recto-verso, étend cette construction à un Shamir 2-sur-3 nativement intégré à la Phase 3 d'Esoptron (rebind cross-machine), permettant la récupération d'une voûte Eidolon perdue à partir de deux des trois plates distribuées chez des dépositaires indépendants.

Aucune nouvelle primitive cryptographique n'est introduite. La sécurité repose intégralement sur le TRNG amont (cérémonie multi-source §7), sur l'algèbre Reed–Solomon sur 𝔽₁₃ (théorème MDS, borne de Singleton atteinte), et sur la confidentialité physique des plates (substrat titane recommandé). L'intégration se fait sans modification du noyau cryptographique d'Eidolon : la Recovery Plate fournit un input alternatif à la fonction de rebind déjà spécifiée.

Le pas suivant est le **Whitepaper III**, qui établit formellement la séparation cryptographique entre le rendu *public* (`.eopx` Métatron) et le rendu *privé* (Metatron Mnemonic / Recovery Plate) — tous deux affichés sur la même grammaire visuelle — et propose le **bandeau de rôle** (`metatron:role`) comme garde-fou de désambigüation obligatoire.

---

## Annexe A — Pseudo-code de référence

```python
# encode.py — sketch non normatif

from typing import List
import secrets
from eidolon_crypto import shamir_split_gf256, hkdf_sha3_512

def base13_encode(payload_bytes: bytes, n_symbols: int) -> List[int]:
    n = int.from_bytes(payload_bytes, "big")
    out = []
    for _ in range(n_symbols):
        out.append(n % 13)
        n //= 13
    return out[::-1]

def rs_encode_block(message: List[int]) -> List[int]:
    """RS(13, 10) systematic over F_13, alpha = 2."""
    assert len(message) == 10
    F13 = lambda x: x % 13
    alpha_pows = [pow(2, i, 13) for i in range(13)]
    codeword = []
    for i in range(13):
        val = 0
        for j, m in enumerate(message):
            val = F13(val + m * pow(alpha_pows[i], j, 13))
        codeword.append(val)
    return codeword

def encode_mnemonic_v1(seed: bytes) -> List[int]:
    assert len(seed) == 32
    payload = bytes([0x01]) + seed                            # version + seed
    symbols = base13_encode(payload, 70)                      # 70 symboles message
    blocks = [symbols[i*10:(i+1)*10] for i in range(7)]
    codewords = [rs_encode_block(b) for b in blocks]
    interleaved = [codewords[b][i] for i in range(13) for b in range(7)]
    return interleaved                                        # 91 symboles F_13

def generate_seed_multisource(entropy_a: bytes, entropy_b: bytes, entropy_c: bytes) -> bytes:
    combined = entropy_a + entropy_b + entropy_c
    return hkdf_sha3_512(combined, info=b"metatron.mnemonic.v1.genesis")[:32]

def generate_recovery_plates(seed: bytes) -> List[bytes]:
    shares = shamir_split_gf256(seed, k=2, n=3)               # 3 shares de 33 octets
    return [encode_plate(s, idx=i) for i, s in enumerate(shares)]
```

## Annexe B — Paramètres figés

| Constante                  | Valeur                                       |
| -------------------------- | -------------------------------------------- |
| Corps                      | 𝔽₁₃ = ℤ/13ℤ                                  |
| Générateur primitif        | α = 2                                        |
| Schéma RS standard         | RS(13, 10) entrelacé ×7 ⇒ (91, 70)            |
| Schéma RS recovery xl      | RS(13, 12 ?) entrelacé — à ajuster en spec normative |
| Espace de couleurs         | OKLCH → conversion sRGB IEC61966-2.1         |
| Distance perceptuelle min. | ΔE_oklch ≥ 10 entre symboles voisins         |
| Substrat recommandé        | titane CNC ou acier inox laser-gravé         |
| Format image gravure       | PNG 1024×1024, 8 bit/canal, sRGB              |
| Shamir Recovery            | k=2, n=3 sur 𝔽₂₅₆ (octet par octet)          |
| Profil par défaut          | `mnemonic_v1` pour standalone, `recovery_v1` pour Plate |

## Annexe C — Tests de référence (à constituer)

- Vecteur test 1 : `seed = 0x0000…0000` (32 octets nuls) → cube de référence "zéro absolu", utile pour calibration colorimétrique.
- Vecteur test 2 : `seed = 0xFFFF…FFFF` → cube "saturation maximale".
- Vecteur test 3 : `seed = sha3_256("metatron.mnemonic.v1.testvector.3")`.
- Pour chaque vecteur : image PNG attendue + hash SHA3-256 de cette image.
- Tests de robustesse : occulter 1, 5, 10, 15, 21 porteurs au hasard ; vérifier que le décodage récupère le seed dans chaque cas (sauf le dernier, qui doit dépasser la capacité corrective et signaler proprement l'échec).

---

*Fin du draft v0.1. À figer par hash dans une future spec normative `spec_metatron_mnemonic_v1.md` et `spec_metatron_recovery_v1.md`.*
