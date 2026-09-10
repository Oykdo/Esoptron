#!/bin/sh
# Sauvegarde rotative du registre d'artefacts EPX-T (PostgreSQL).
#
# Ce registre porte les titres et l'economie EIDOLON : au 2026-09-10, la
# relique #1 Speculum Primum, sequence 1, reclamee et scellee. Il n'avait
# aucune sauvegarde -- et il a DEJA ete perdu une fois : la reclamation
# "PROVEN LIVE" de juin 2026 avait disparu avec la base precedente, sans que
# personne s'en apercoive pendant trois mois.
#
# Memes garanties que backup_vault_registry.sh cote Eidolon, pour les memes
# raisons :
#   1. on ne remplace jamais une sauvegarde valide par un dump vide ou
#      tronque : le dump est verifie AVANT d'etre conserve ;
#   2. les copies vivent ailleurs que la base ;
#   3. un dump identique au precedent n'est pas duplique, pour que la
#      retention garde 30 etats distincts et non 30 fois le meme.
#
# Usage :
#   backup_anchor_db.sh [fichier_env] [dossier_de_sauvegarde]
#
# Variables :
#   ANCHOR_ENV   defaut /opt/esoptron/anchor.env  (contient ESOPTRON_ANCHOR_DSN)
#   BACKUP_DIR   defaut /root/backups/esoptron-anchor
#   KEEP         nombre de copies conservees, defaut 30

set -eu

ANCHOR_ENV="${1:-${ANCHOR_ENV:-/opt/esoptron/anchor.env}}"
BACKUP_DIR="${2:-${BACKUP_DIR:-/root/backups/esoptron-anchor}}"
KEEP="${KEEP:-30}"

log() { printf '[backup-anchor] %s\n' "$1"; }

if [ ! -f "$ANCHOR_ENV" ]; then
    log "ABSENT : $ANCHOR_ENV -- DSN introuvable"
    exit 1
fi

DSN=$(sed -n 's/^ESOPTRON_ANCHOR_DSN=//p' "$ANCHOR_ENV" | head -1)
if [ -z "$DSN" ]; then
    log "ECHEC : ESOPTRON_ANCHOR_DSN absent de $ANCHOR_ENV"
    exit 1
fi

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
# $$ desambigue deux executions dans la meme seconde, qui produisaient
# sinon le meme nom -- la seconde ecrasant silencieusement la premiere.
TMP="$BACKUP_DIR/.anchor-$STAMP-$$.sql.tmp"

# --no-owner / --no-privileges : la restauration doit pouvoir viser une autre
# base Neon sans rejouer des roles qui n'y existent pas.
if ! pg_dump --no-owner --no-privileges --format=plain "$DSN" > "$TMP" 2>/dev/null; then
    rm -f "$TMP"
    log "ECHEC : pg_dump n'a pas abouti -- historique laisse intact"
    exit 1
fi

# Garde-fou 1 : un dump qui ne contient aucune table est un dump inutile qui
# aurait l'air d'une sauvegarde. On refuse plutot que de rassurer a tort.
if ! grep -q "CREATE TABLE" "$TMP"; then
    rm -f "$TMP"
    log "ECHEC : dump sans aucune table -- refuse"
    exit 1
fi

SUM=$(sha256sum "$TMP" | cut -d' ' -f1)
LAST=$(ls -1t "$BACKUP_DIR"/anchor-*.sql 2>/dev/null | head -1 || true)

# Garde-fou 3 : deduplication.
if [ -n "$LAST" ]; then
    # pg_dump n'est pas deterministe ligne a ligne : l'ordre des lignes de
    # donnees peut varier a contenu identique. On compare donc un contenu
    # normalise (sans commentaires ni lignes vides) ET trie, sinon aucune
    # copie ne serait jamais reconnue identique et la retention garderait
    # trente fois le meme etat.
    # pg_dump 16 encadre le dump de lignes \restrict / \unrestrict portant
    # un JETON ALEATOIRE regenere a chaque execution : sans les retirer, deux
    # dumps d'une base inchangee ne sont jamais egaux, et la retention garde
    # trente fois le meme etat en croyant garder trente etats.
    # Le motif utilise la classe [\] plutot qu'un backslash echappe :
    # selon les couches de quoting traversees, '^\\restrict' arrive a grep
    # ampute et ne filtre plus rien -- silencieusement.
    norm() {
        grep -v '^--' "$1" | grep -v '^[[:space:]]*$' \
            | grep -v '^[\]restrict ' | grep -v '^[\]unrestrict ' \
            | sort | sha256sum | cut -d' ' -f1
    }
    A=$(norm "$TMP")
    B=$(norm "$LAST")
    if [ "$A" = "$B" ]; then
        rm -f "$TMP"
        log "inchange depuis $(basename "$LAST") -- pas de copie"
        exit 0
    fi
fi

DEST="$BACKUP_DIR/anchor-$STAMP.sql"
# Sous set -e, un `[ test ] && affectation` fait SORTIR le script quand le
# test echoue -- c'est-a-dire dans le cas normal. D'ou le if explicite.
if [ -e "$DEST" ]; then
    DEST="$BACKUP_DIR/anchor-$STAMP-$$.sql"
fi
mv "$TMP" "$DEST"
chmod 600 "$DEST"

TABLES=$(grep -c "CREATE TABLE" "$DEST")
log "copie -> $DEST ($TABLES table(s), sha256 $(echo "$SUM" | cut -c1-16)...)"

TOTAL=$(ls -1 "$BACKUP_DIR"/anchor-*.sql 2>/dev/null | wc -l)
if [ "$TOTAL" -gt "$KEEP" ]; then
    ls -1t "$BACKUP_DIR"/anchor-*.sql | tail -n +$((KEEP + 1)) | while read -r old; do
        rm -f "$old"
        log "purge $(basename "$old")"
    done
fi

log "$(ls -1 "$BACKUP_DIR"/anchor-*.sql 2>/dev/null | wc -l) copie(s) conservee(s) sur $KEEP"
