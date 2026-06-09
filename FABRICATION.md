# Fabrication de la relique EPX-R (plan — pour plus tard)

Comment graver physiquement une plaque runique EPX-R sur un support durable.
Tu n'as pas le matériel aujourd'hui : ce document est le plan à suivre quand ce
sera le moment. Voir aussi `PRINT_TUTORIAL.md` (test papier + décodage) et
`docs/specs/EPX-R_runic_plate.md` (format).

## Principe

La relique = la plaque EPX-R (treillis runique + 4 marqueurs ArUco), gravée sur
un support qui survit au temps. Le fichier source est produit par
`scripts/epx_r_prototype.py` (PNG 300 dpi). Un export **SVG vectoriel** (TODO,
§5) donnera des bords plus nets au laser.

```
relic_key → mint_relic → relic_secret → encode EPX-R → fichier (PNG/SVG)
          → gravure → PHOTO → `detect` pour VÉRIFIER → seulement ensuite déployer
```

## 1. Option recommandée — laser fibre sur alu anodisé noir mat

- **Support** : aluminium **anodisé noir mat** (le marquage laser révèle un
  contraste clair sur fond noir). Étanche, anti-UV, résistant aux rayures.
- **Machine** : **laser fibre** (marquage métal) — en fablab ou via un service
  de gravure en ligne. Un CO₂ ne marque pas l'alu nu sans spray ; le fibre, si.
- **Cellule** : **2,5–3 mm** → lisible au téléphone, marge confortable.
  Plaque indicative : grille 43×69 ≈ **11×17 cm** + marges/marqueurs.
- **Réglages (point de départ, à affiner sur chute)** :
  - mode *gravure/raster* ou *marquage* selon la machine ;
  - contraste **maximal** entre rune et fond ; trait net (≥ 0,2 mm) ;
  - finition **mate** (pas de vernis brillant) pour éviter les reflets.
- **Fichier** : PNG 300 dpi aujourd'hui ; **SVG** dès que l'export existe (§5).

## 2. Contraintes impératives (sinon `detect` ne relit pas)

- [ ] **Contraste fort** rune/fond ; **les 4 marqueurs ArUco** = blocs pleins
      nets (c'est l'ancre de détection — un coin raté = échec).
- [ ] **Pas de cellule ≥ 2,5–3 mm** pour le téléphone (plus fin uniquement si
      lecture scanner/macro).
- [ ] **Surface plane et mate** (reflets = échec photo).
- [ ] **Zone de quiet** (marge vierge) conservée ; **ne pas rogner les coins**.
- [ ] Support qui ne perd pas **> ⅓** de surface en un incident (marge ECC).

## 3. Vérification (non négociable, avant déploiement)

1. Photographier la plaque gravée (lumière diffuse, sans reflet, 4 coins nets).
2. `py -3.11 scripts/epx_r_prototype.py detect ma_photo.jpg`
3. Attendu : `markers found [0,1,2,3]`, `block-fails=0`, `RECOVERED …`.
4. Si échec : ajuster contraste/finition/pas de cellule, re-graver sur chute.

## 4. Variantes epoch-scale (quand le budget/matériel suivent)

| Support | Procédé | Durabilité | Notes |
|---|---|---|---|
| **Céramique / porcelaine cuite** | décalque émaillé + cuisson, ou laser | archival (UV/gel/eau) | excellent rapport durée/accessibilité |
| **Inox / laiton** | **gravure photochimique** | très élevée, très fine | qualité industrielle, fin |
| **Pierre / granit** | CNC ou sablage | monumentale | cellules plus grosses (≥ 5 mm) |
| **Plaque nickel gravée** | type *Rosetta Disk* | **millénaire** | gold standard, overkill |

Pour les supports à faible résolution (pierre/sablage), **augmenter le pas de
cellule** (≥ 5 mm) et réduire le payload en conséquence.

## 5. TODO logiciel avant gravure

- **Export SVG vectoriel** du renderer (`epx_r_prototype.py`) : les runes sont
  des segments → vectorisables directement ; les marqueurs ArUco en rectangles
  vectoriels. Bords nets au laser, mise à l'échelle sans perte.
- (Optionnel) version **haute densité** (cellule < 1 mm) pour gravure fine +
  lecture scanner/macro, si on vise > 1 Ko de payload sur la plaque.

## 6. Rappel doctrine

La relique porte un **secret/clé**, jamais le contenu en clair (cf.
`docs/specs/EPX-L_hidden_layer.md` §6). Le contenu caché vit **chiffré** dans le
`blend_data` ; la relique ne fait que **déverrouiller**. Capacité ≠ sécurité.
