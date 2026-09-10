#!/bin/sh
# Repetition de restauration du registre d'artefacts EPX-T.
#
# Une sauvegarde jamais restauree est une hypothese, pas une garantie. Ce
# script transforme l'hypothese en fait : il restaure le dernier dump dans une
# base JETABLE et locale, puis compare son contenu a la base vivante, table
# par table, avant de tout supprimer.
#
# Il ne touche JAMAIS la base de production : la restauration vise une base
# locale creee pour l'occasion, et la base vivante n'est interrogee qu'en
# lecture (SELECT count(*)).
#
# Usage :
#   verify_anchor_restore.sh [dump.sql]
#
# Sans argument, il prend le dump le plus recent de BACKUP_DIR.
#
# Sortie : 0 restauration conforme | 1 divergence | 2 execution impossible

set -eu

BACKUP_DIR="${BACKUP_DIR:-/root/backups/esoptron-anchor}"
ANCHOR_ENV="${ANCHOR_ENV:-/opt/esoptron/anchor.env}"
CHECK_DB="${CHECK_DB:-anchor_restore_check}"

log() { printf '[verify-restore] %s\n' "$1"; }
fail() { log "$1"; exit "${2:-2}"; }

DUMP="${1:-}"
if [ -z "$DUMP" ]; then
    DUMP=$(ls -1t "$BACKUP_DIR"/anchor-*.sql 2>/dev/null | head -1 || true)
fi
[ -n "$DUMP" ] && [ -f "$DUMP" ] || fail "aucun dump a verifier dans $BACKUP_DIR"

DSN=$(sed -n 's/^ESOPTRON_ANCHOR_DSN=//p' "$ANCHOR_ENV" | head -1)
[ -n "$DSN" ] || fail "ESOPTRON_ANCHOR_DSN absent de $ANCHOR_ENV"

log "dump   : $(basename "$DUMP")  $(stat -c%s "$DUMP") octets"
log "cible  : base locale jetable '$CHECK_DB' (la production n'est lue qu'en SELECT)"

# Table rase : une repetition precedente interrompue ne doit pas fausser
# celle-ci en laissant des lignes derriere elle.
sudo -u postgres dropdb --if-exists "$CHECK_DB" >/dev/null 2>&1 || true
sudo -u postgres createdb "$CHECK_DB" || fail "creation de $CHECK_DB impossible"

cleanup() { sudo -u postgres dropdb --if-exists "$CHECK_DB" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# psql -v ON_ERROR_STOP=1 : sans lui, psql avale les erreurs et rend 0 -- une
# restauration a moitie echouee passerait pour un succes.
# Le dump est en 0600 et appartient a root : psql, qui tourne sous
# l'utilisateur postgres, ne peut pas l'ouvrir. On le lui passe par
# l'entree standard plutot que d'assouplir les droits d'un fichier qui
# contient l'integralite du registre.
if ! cat "$DUMP" | sudo -u postgres psql -v ON_ERROR_STOP=1 -q -d "$CHECK_DB" >/tmp/restore.log 2>&1; then
    log "ECHEC de la restauration :"
    tail -5 /tmp/restore.log | sed 's/^/    /'
    exit 1
fi
log "restauration : OK"

TABLES="accounts artifact_history artifacts eidolon_grants eidolon_log"
DIVERGENCES=0

printf '\n  %-22s %10s %10s\n' "table" "restaure" "production"
printf '  %-22s %10s %10s\n' "----------------------" "--------" "----------"

for t in $TABLES; do
    R=$(sudo -u postgres psql -tAq -d "$CHECK_DB" -c "SELECT count(*) FROM public.$t" 2>/dev/null || echo "?")
    P=$(psql -tAq "$DSN" -c "SELECT count(*) FROM public.$t" 2>/dev/null || echo "?")
    MARK=""
    if [ "$R" != "$P" ]; then MARK="  <-- DIVERGENCE"; DIVERGENCES=$((DIVERGENCES + 1)); fi
    printf '  %-22s %10s %10s%s\n' "$t" "$R" "$P" "$MARK"
done

# Au-dela du comptage : le contenu doit etre identique. Un nombre de lignes
# egal ne dit rien de leur valeur.
#
# On compare `SELECT *` plutot que des colonnes nommees a la main. La premiere
# version visait artifact_id_hex / controller_pub_hex -- les noms de l'API,
# pas ceux de la base. psql echouait, l'erreur partait dans /dev/null, et les
# deux cotes rendaient l'empreinte de la chaine vide : le test se declarait
# conforme en comparant du vide a du vide. Un controle qui ne peut pas
# echouer n'est pas un controle.
hash_side() {   # $1 = "local"|"prod", $2 = table, $3 = fichier de sortie
    if [ "$1" = "local" ]; then
        sudo -u postgres psql -tAq -d "$CHECK_DB" -c "SELECT * FROM public.$2 ORDER BY 1" > "$3" 2>/dev/null
    else
        psql -tAq "$DSN" -c "SELECT * FROM public.$2 ORDER BY 1" > "$3" 2>/dev/null
    fi
}

printf '
'
for t in $TABLES; do
    LOCAL_OUT=/tmp/restore-local.$$
    PROD_OUT=/tmp/restore-prod.$$

    if ! hash_side local "$t" "$LOCAL_OUT" || ! hash_side prod "$t" "$PROD_OUT"; then
        log "ECHEC : lecture impossible de $t -- controle non concluant"
        rm -f "$LOCAL_OUT" "$PROD_OUT"
        DIVERGENCES=$((DIVERGENCES + 1))
        continue
    fi

    P=$(psql -tAq "$DSN" -c "SELECT count(*) FROM public.$t" 2>/dev/null || echo 0)
    if [ "$P" -gt 0 ] && [ ! -s "$PROD_OUT" ]; then
        log "ECHEC : $t compte $P ligne(s) mais la lecture ne rend rien -- controle degenere"
        rm -f "$LOCAL_OUT" "$PROD_OUT"
        DIVERGENCES=$((DIVERGENCES + 1))
        continue
    fi

    A=$(sha256sum < "$LOCAL_OUT" | cut -c1-16)
    B=$(sha256sum < "$PROD_OUT"  | cut -c1-16)
    rm -f "$LOCAL_OUT" "$PROD_OUT"

    if [ "$A" = "$B" ]; then
        printf '  contenu %-18s %s == %s
' "$t" "$A" "$B"
    else
        printf '  contenu %-18s %s != %s   <-- DIVERGENCE
' "$t" "$A" "$B"
        DIVERGENCES=$((DIVERGENCES + 1))
    fi
done

printf '
'
if [ "$DIVERGENCES" -eq 0 ]; then
    log "conforme : la sauvegarde restaure exactement l'etat de production"
    exit 0
fi

log "$DIVERGENCES divergence(s) -- la sauvegarde N'EST PAS fidele"
exit 1
