# Guide de test — Métatron × Esoptron (prototype v0)

Ce guide t'explique comment **valider en pratique** la chaîne photo → cryptographie sur ton propre matériel : un ordinateur Windows + Python 3.11, et n'importe quel téléphone récent. Aucun matériel spécialisé n'est requis pour le prototype.

> **Statut du prototype** : v0. La couche cryptographique (encodage/décodage Reed–Solomon + détection sur image canonique) est entièrement opérationnelle (48/48 tests passent). La détection photographique repose actuellement sur des **points fiduciaux fournis à la main** ; l'auto-détection Hough est prévue en v0.2.

---

## 0. Pré-requis (une seule fois)

```powershell
cd C:\Chimera\Esoptron
py -m pip install -e ".[dev]"
```

Vérifie que Python et les modules sont en place :

```powershell
py -c "import eopx.metatron, PIL, numpy; print('OK')"
```

---

## 1. Test 1 — Boucle locale (sans téléphone) — **OBLIGATOIRE**

Avant de toucher à une caméra, exécute la boucle locale qui valide tout le pipeline mathématique sur des images parfaites (sans la moindre photographie). Si elle échoue, inutile de continuer.

```powershell
py scripts/loopback_canonical.py
```

Sortie attendue :

```
PRIVATE  seed     = b30ec7faee8058c4...
         symbols rendered then re-detected: 91/91 match, in_C=True, max_dist=0.0000
         seed recovered : True

PUBLIC   spinor   = 141964e6cd03a3d6...
         symbols rendered then re-detected: 91/91 match, in_C=False, max_dist=0.0000

OK -- loopback succeeds on both private and public paths.
```

Ce que ça prouve :

- Encodage → rendu PNG → détection → décodage = identité bit-à-bit.
- Le **Théorème 2** se vérifie : un rendu public n'appartient pas au sous-espace C, un rendu privé y appartient.

Tu peux aussi exécuter la suite complète de tests :

```powershell
py -m pytest tests/ -v
```

48 tests doivent passer.

---

## 2. Test 2 — Génère un cube de test avec ta voûte fictive

Cette étape crée une "voûte de test" déterministe : un seed connu de 256 bits, gravé visuellement sur un cube de Métatron. Tu pourras ensuite le photographier et vérifier que ton téléphone (via la chaîne de détection) retrouve exactement ce seed.

```powershell
py scripts/make_test_vault.py
```

Sortie :

```
============================================================
  KNOWN TEST VAULT
============================================================
  passphrase   : metatron.test_vault.v1
  seed (hex)   : 7ef1eaa3173a693007a0e85d59b120883983da03dc2bac120564ea02b299f331
  sha3-256[:16]: 5f4a7bd742223df2

  wrote out\test_vault_private.png  (40957 bytes, 1024x1024)
  wrote out\test_vault_public.png   (19115 bytes,  512x512)
```

**Note bien la valeur hexadécimale du seed** — c'est ce que ta photo doit redonner.

> Le seed est dérivé d'une passphrase publique (`metatron.test_vault.v1`) ; il n'a aucune valeur cryptographique réelle. **Pour un vrai cold wallet, ne jamais utiliser une cérémonie reproductible.**

---

## 3. Test 3 — Photographier le cube

Tu as deux options.

### Option A — Affichage à l'écran (le plus simple)

1. Ouvre `out\test_vault_private.png` en plein écran sur ton **moniteur d'ordinateur**.
2. Avec ton téléphone (iOS ou Android, n'importe quel modèle ≥ 2019), photographie l'écran. Conseils :
   - Désactive le flash.
   - Tiens le téléphone parallèle à l'écran (évite les angles obliques).
   - Cadre le cube avec une marge confortable (10–15% de bords vides).
   - Évite les reflets visibles sur l'écran.
3. Transfère la photo sur ton ordinateur (AirDrop, e-mail à soi-même, câble USB).

### Option B — Impression papier

1. Imprime `out\test_vault_private.png` sur du papier blanc A4, idéalement à l'échelle maximale, en couleur, sans dégradé d'encre.
2. Pose la feuille à plat, sous éclairage diffus (lumière du jour indirecte, pas de spot direct).
3. Photographie au-dessus, perpendiculaire au papier.
4. Transfère.

> Le rendu à 1024×1024 imprimé sur une feuille A4 occupe ~18 cm de côté ; c'est largement suffisant pour que les pastilles de couleur (78 + 13 = 91) soient nettes.

---

## 4. Test 4 — Repérer les 6 points fiduciaux dans ta photo

C'est l'étape qui demande l'intervention humaine en v0. Tu dois identifier les **6 sommets de l'hexagone EXTÉRIEUR** dans ta photo et noter leurs coordonnées pixel.

Ordre canonique (issu de `eopx.metatron.graph.VERTICES[7..12]`) :

| Index | Angle (depuis le centre) | Position approximative dans la figure |
| ----- | ------------------------ | ------------------------------------- |
| V[7]  | 30°                       | en haut à droite                      |
| V[8]  | 90°                       | en haut                                |
| V[9]  | 150°                      | en haut à gauche                       |
| V[10] | 210°                      | en bas à gauche                        |
| V[11] | 270°                      | en bas                                 |
| V[12] | 330°                      | en bas à droite                        |

Pour mesurer les coordonnées pixel :

- **Windows** : ouvre la photo dans **Paint.NET** ou **GIMP**, place le curseur sur chaque sommet, lis la coordonnée en bas de la fenêtre (format `x, y`).
- **macOS** : `Aperçu` ne donne pas les pixels précis ; utilise plutôt **Photoshop**, **Preview > Outils > Inspecteur**, ou un site web comme `https://pixspy.com`.
- **iOS / Android** : la plupart des éditeurs natifs donnent les pixels en hover ; sinon installe une app type "Color Pix" ou "Pipette" qui affiche les coordonnées au tap.

Note les 6 paires `(x, y)` dans l'ordre V[7] → V[12].

---

## 5. Test 5 — Décoder

```powershell
py scripts/decode_from_photo.py "C:\path\to\photo.jpg" `
   --fiducials "1230,310 1820,500 1830,1110 1240,1300 650,1110 660,500" `
   --save-rectified "out\rectified.png"
```

(Remplace les coordonnées par les tiennes.)

Sortie attendue (résumé) :

```
Loaded: C:\path\to\photo.jpg (3024x4032)
Rectifying to 1024x1024...
Saved rectified image to out\rectified.png

Classification confidence:
  carriers with Oklab distance > 0.13: 4 / 91
  worst Oklab distance: 0.181

Algebraic test (Whitepaper III Theorem 2):
  symbols lie in code C: True
  inferred role: private_*
  symbol-vector fingerprint (sha3_256[:16]): a23f...

PRIVATE DECODE successful:
  seed (hex)       : 7ef1eaa3173a693007a0e85d59b120883983da03dc2bac120564ea02b299f331
  version          : 1
  sha3-256[:16]    : 5f4a7bd742223df2
```

**Le seed doit correspondre exactement à celui imprimé par `make_test_vault.py`.**

Le `--save-rectified` te laisse vérifier visuellement que la rectification est bonne : ouvre `out\rectified.png` ; tu dois y voir un cube de Métatron presque identique à `out\test_vault_private.png`.

---

## 6. Que faire si le décodage échoue ?

### Symptôme : `worst Oklab distance > 0.20` (beaucoup de classifications incertaines)

Probable : photo floue, éclairage faible, ou tag de couleur partiellement caché par un reflet.

- Refais la photo en lumière naturelle, mise au point sur le centre du cube.
- Tiens le téléphone plus stable (utilise les deux mains, ou un support).
- Si l'image affichée sur écran a un Moiré (vagues d'interférence), augmente la distance entre téléphone et écran de 20–30 cm.

### Symptôme : `inferred role: public_render` alors que c'est une plate privée

Le **Théorème 2** ne s'aligne pas : trop de symboles mal classés ⇒ les blocs RS échouent au test d'appartenance à C. Cause habituelle : rectification incorrecte.

- Vérifie que tu as bien donné les fiduciaux dans **l'ordre canonique V[7]..V[12]**, pas dans un ordre arbitraire.
- Ouvre `out\rectified.png` ; si le cube y est déformé, oblique, ou décentré, tes fiduciaux étaient mal placés.

### Symptôme : `PRIVATE DECODE failed: codeword inconsistent at position ...`

Plus de 3 carriers d'un bloc RS sont corrompus. Le profil `mnemonic_v1` ne tolère que 21 effacements répartis 3 par bloc. Si la photo a une zone fortement dégradée (reflet localisé sur une moitié du cube), plus de 3 carriers d'un même bloc peuvent être touchés.

- Refais la photo sans reflet.
- Augmente `--erasure-threshold 0.20` pour marquer plus de carriers comme incertains (le décodeur préfère savoir qu'un carrier est non-fiable plutôt que de tenter une lecture).

### Symptôme : message d'erreur de `numpy.linalg.inv`

Tes 6 fiduciaux sont colinéaires ou quasi-confondus (deux points presque au même endroit). Vérifie-les.

---

## 7. Tester avec ta VRAIE voûte Eidolon (pour plus tard)

Le prototype actuel **n'est pas connecté** au noyau cryptographique Eidolon. Pour ancrer une vraie voûte :

1. Calcule (ou récupère) ton `spinor_hash` Phase 6 d'Eidolon (64 octets).
2. Encode-le en public :

   ```python
   from eopx.metatron import encode_public, render
   spinor = bytes.fromhex("...64 octets...")
   syms = encode_public(spinor)
   render(syms, size=512).save("ma_voute_publique.png")
   ```

3. Affiche / partage / NFC `ma_voute_publique.png` — c'est ton `.eopx` Métatron public, sans valeur de divulgation.

4. Pour une plate privée à partir du seed maître d'Eidolon (256 bits) :

   ```python
   from eopx.metatron import encode_private, render
   seed = bytes.fromhex("...32 octets de seed maître...")
   syms = encode_private(seed)
   render(syms, size=1024).save("ma_plate_privee.png")
   ```

   **Avant** de graver sur métal, **photographie le PNG**, fais tourner `decode_from_photo.py`, et vérifie que tu retrouves bien ton seed octet par octet. Si oui, tu peux confier la gravure. Sinon, n'utilise pas cette plate.

> **Sécurité opérationnelle** : exécute toute manipulation de seed sur une machine air-gap (live USB, réseau coupé). Ne pousse jamais ces PNG sur GitHub, IPFS, ou cloud. Le prototype v0 n'a **pas** de protection FLAG_SECURE ni d'effacement RAM ; à toi de respecter les bonnes pratiques.

---

## 8. Mesurer la robustesse photographique

Tu peux faire varier des paramètres et regarder comment le système tient :

```powershell
# génère un cube
py scripts/make_test_vault.py

# fais 5 photos avec angle, éclairage, distance différents
# décode chacune et compare les seeds
foreach ($f in "photo1.jpg","photo2.jpg","photo3.jpg") {
    py scripts/decode_from_photo.py $f --fiducials "..."
}
```

Le seed récupéré doit être le **même** pour les 5 photos, tant que la rectification fournit une image canonique exploitable (la qualité du résultat ne dépend pas de l'angle de prise de vue, à condition que les fiduciaux soient corrects).

---

## 9. Limites connues du prototype v0

- Pas d'auto-détection des fiduciaux (utilisateur fournit 6 points).
- Pas de **bandeau de rôle** (Whitepaper III §5) — la distinction publique/privée passe uniquement par le test algébrique (Théorème 2).
- Pas d'intégration ML-DSA pour la vérification de signature sur les `.eopx` publics.
- Pas de Shamir 2/3 implémenté pour les Recovery Plates (Whitepaper II §8).
- Pas de correction d'erreurs RS au sens fort (Berlekamp-Massey) : uniquement les effacements à confiance basse.

Tous ces points sont planifiés pour v0.1 → v0.3. Le présent prototype prouve seulement que **la mathématique tient et que la détection canonique fonctionne avec un appareil photo standard**.

---

## 10. Aide & contact

Si quelque chose ne marche pas comme attendu, exécute d'abord :

```powershell
py -m pytest tests/ -v
py scripts/loopback_canonical.py
```

Si les 48 tests + le loopback passent mais ta photo échoue, c'est presque toujours :

1. Fiduciaux mal placés.
2. Photo floue/sous-exposée.
3. Mauvais ordre des 6 sommets.

Vérifie l'image `out/rectified.png` produite par `--save-rectified` : elle te dit si la rectification est OK avant tout problème de classification.
