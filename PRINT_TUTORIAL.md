# Tutoriel d'impression — plaque runique EPX-R (prototype A4)

Comment **imprimer**, **photographier** et **décoder** le prototype de plaque
runique EPX-R. Le but : valider la chaîne physique (impression → photo
téléphone/webcam → récupération exacte du contenu).

> Contexte technique : `docs/specs/EPX-R_runic_plate.md` (format),
> `docs/research/EPX-R_HANDOVER.md` (état). Le décodage logiciel est déjà
> prouvé en simulation ; cette étape teste la **capture réelle**.

---

## 0. Ce qu'il te faut

- Le fichier à imprimer : **`epx_r_A4_prototype.png`** (ou `epx_r_A4_prototype.pdf`)
  à la racine d'Esoptron — 2480×3508 px à 300 dpi, prévu pour une feuille **A4**.
- Une **imprimante** (laser de préférence ; jet d'encre OK).
- Un **téléphone** (appareil photo) ou une **webcam** PC, ou un **scanner**.
- Le décodeur, qui tourne avec le **Python qui a numpy/OpenCV/Pillow** :
  `py -3.11` (le `python` par défaut n'a pas ces libs).

---

## 1. Imprimer (l'étape qui rate le plus souvent)

Réglages **impératifs** :

| Réglage | Valeur | Pourquoi |
|---|---|---|
| Échelle | **100 % / « Taille réelle »** — **PAS** « Ajuster à la page » | conserve le pas de cellule (~3,4 mm) et les marqueurs |
| Format | **A4** | la plaque est dimensionnée pour l'A4 |
| Qualité | **Maximale / 300 dpi+** | les runes font ~40 px, il faut des traits nets |
| Couleur | Noir & blanc / niveaux de gris | la plaque est monochrome |
| Marges | Minimales / « sans marge » si possible | garde les 4 coins (marqueurs ArUco) sur la feuille |

- Imprime de préférence le **PDF** en « Taille réelle (100 %) ».
- **Papier mat** plutôt que brillant (évite les reflets à la photo).
- Vérifie après impression : les **4 carrés noirs aux coins** (marqueurs) doivent
  être **entièrement présents et nets**. S'il en manque un, réimprime avec des
  marges plus petites.

---

## 2. Photographier

La perspective est corrigée automatiquement (les 4 marqueurs ArUco donnent
l'homographie), donc **pas besoin d'être parfaitement perpendiculaire** — mais :

- **Les 4 marqueurs de coin doivent être visibles et nets** dans la photo.
- **Lumière homogène, sans reflet ni ombre portée** (lumière du jour diffuse
  idéale ; évite le flash direct sur papier brillant).
- **Remplis le cadre** avec la feuille (le plus de pixels possible sur la plaque).
- **Mise au point** sur le centre, image **non floue**. Tiens le téléphone
  stable (ou pose la feuille à plat et photographie d'au-dessus).
- Enregistre en **JPG/PNG** et transfère le fichier sur le PC.

---

## 3. Décoder

Depuis le dossier `Esoptron`, lance le décodeur sur ta photo :

```bash
py -3.11 scripts/epx_r_prototype.py detect chemin/vers/ta_photo.jpg
```

Sortie attendue (exemple) :

```
[detect] ta_photo.jpg  (3024x4032)
[detect] markers found: [0, 1, 2, 3]
[detect] 18 symbol-erasures of 1275
[detect] block-fails=0/5
[detect] RECOVERED (99 B): 'ESOPTRON A4 PROTOTYPE // Logos Project // vault=#1 // ...'
```

`RECOVERED` = le contenu de la plaque, récupéré **exactement**. 🎉

---

## 4. Si ça ne marche pas

| Symptôme | Cause probable | Remède |
|---|---|---|
| `no ArUco markers found` / `missing markers` | un coin coupé, flou, ou reflet | recadrer pour inclure les 4 coins, refaire la photo nette, mieux éclairer |
| `block-fails > 0` puis `FAILED` | trop de runes illisibles (flou/résolution) | se rapprocher, augmenter la lumière, réimprimer en meilleure qualité |
| `frame magic not found` | classification massivement fausse | photo plus nette / plus grande ; vérifier l'impression à 100 % |
| `RECOVERED` mais texte faux | confusion de runes résiduelle | reprendre une photo plus nette ; voir la note runes ci-dessous |

Astuce : une photo **plus grande et plus nette** résout la grande majorité des cas
(plus de pixels par rune = moins d'erreurs de lecture).

---

## 5. Bon à savoir (attentes réalistes)

- Ce prototype porte **~99 octets** (capacité 845 o sur cette mise en page). Au
  **tier téléphone** (cellules ~3,4 mm), l'A4 plafonne à **~1 Ko** ; le mégabit
  exige un **scanner ≥ 1200 dpi** (voir la carte des tiers, brief §4.7).
- La grille fait **43×69 cellules**, chaque symbole = **2 runes** (F₁₆), protégé
  par un code **Reed-Solomon** entrelacé : la plaque tolère **rayures, déchirures
  de coin et taches** jusqu'à ~⅓ de dégâts répartis avant de devenir illisible.
- Le classifieur de runes est encore **celui du prototype** : en capture réelle,
  une photo médiocre peut produire des erreurs. C'est précisément ce que ce test
  sert à mesurer.

---

## 6. Générer ta propre plaque

Pour graver **ton** contenu (≤ ~832 octets) :

1. Ouvre `scripts/epx_r_prototype.py`, repère la variable `secret` dans le bloc
   `__main__`, remplace-la par ton texte/bytes.
2. Relance :
   ```bash
   py -3.11 scripts/epx_r_prototype.py
   ```
   → régénère `epx_r_A4_prototype.png` / `.pdf` (et auto-teste 3 captures
   simulées). Imprime, et reprends à l'étape 1.

> Rappel sécurité (doctrine `IP-BOUNDARY.md`) : **capacité ≠ sécurité**. La
> plaque est un *canal* ; pour un vrai secret, chiffre le contenu (AEAD sous la
> clé de vault) **avant** de le graver — la plaque ne protège rien par elle-même.
