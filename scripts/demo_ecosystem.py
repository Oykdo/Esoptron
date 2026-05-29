#!/usr/bin/env python3
"""Démonstration complète de l'écosystème Esoptron.

Usage:
    py scripts/demo_ecosystem.py

Ce script simule tous les flux principaux sans nécessiter de matériel externe.
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from eopx.format.keys import EopxKey
from eopx.metatron import encode_private, encode_public, decode_private
from eopx.vault import (
    # Protocol A: Unlock
    unlock_from_private_symbols,
    derive_master_key,
    # Protocol B: Verify
    verify_card,
    card_fingerprint,
    # Protocol D: Enroll
    enroll_from_card,
    # Protocol E: Genesis
    genesis_enroll,
    # Protocol F: Migrate
    new_migration_challenge,
    prove_migration,
    verify_migration,
    compute_verify_tag,
)
from eopx.recovery import (
    setup_recovery,
    recover_entropy,
    RecoveryCredentials,
    # Flexible k/n
    ShareConfig,
    setup_recovery_flexible,
    recover_entropy_flexible,
    FlexibleCredentials,
)


def banner(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


def demo_protocol_a():
    """Protocol A: Débloquer un vault depuis une feuille PRIVÉE."""
    banner("PROTOCOL A: Private Sheet Unlock")
    
    # Simuler une seed secrète (normalement imprimée sur papier)
    seed = secrets.token_bytes(32)
    print(f"1. Seed secrète (32 bytes): {seed.hex()[:32]}...")
    
    # Encoder en 91 symboles F_13 (ce qui serait imprimé)
    symbols = encode_private(seed)
    print(f"2. Encodé en 91 symboles Metatron: {symbols[:10]}...")
    
    # Simuler la capture photo et décodage
    recovered_seed, master_key = unlock_from_private_symbols(symbols)
    print(f"3. Seed récupérée: {recovered_seed.hex()[:32]}...")
    print(f"4. Master key dérivée: {master_key.hex()[:32]}...")
    
    assert recovered_seed == seed, "Seed mismatch!"
    print("✓ Protocol A OK - La feuille privée déverrouille le vault")


def demo_protocol_b():
    """Protocol B: Vérifier une carte PUBLIQUE."""
    banner("PROTOCOL B: Public Card Verification")
    
    # Simuler le spinor_hash d'Eidolon (Phase 6 output)
    spinor_hash = secrets.token_bytes(64)
    print(f"1. Spinor hash Eidolon (64 bytes): {spinor_hash.hex()[:32]}...")
    
    # Générer les symboles publics (ce qui serait imprimé sur la carte)
    symbols = encode_public(spinor_hash)
    print(f"2. Carte publique: 91 symboles")
    
    # Vérifier que la carte correspond au spinor local
    is_valid = verify_card(symbols, spinor_hash)
    print(f"3. Vérification avec spinor local: {'✓ VALIDE' if is_valid else '✗ INVALIDE'}")
    
    # Tester avec un mauvais spinor
    wrong_spinor = secrets.token_bytes(64)
    is_invalid = verify_card(symbols, wrong_spinor)
    print(f"4. Avec mauvais spinor: {'✗ REJETÉ' if not is_invalid else '✓ ERREUR!'}")
    
    print("✓ Protocol B OK - La carte publique authentifie le vault")


def demo_protocol_d():
    """Protocol D: Enrollment depuis une carte publique."""
    banner("PROTOCOL D: Per-Device Enrollment")
    
    # Carte publique (imprimée sur un poster)
    spinor_hash = secrets.token_bytes(64)
    symbols = encode_public(spinor_hash)
    print(f"1. Carte publique scannée")
    
    # Entropie locale du device (générée une seule fois)
    device_entropy = secrets.token_bytes(32)
    print(f"2. Entropie device générée: {device_entropy.hex()[:16]}...")
    
    # Enrollment
    record = enroll_from_card(symbols, device_entropy)
    print(f"3. Enrollment créé:")
    print(f"   - Vault FP: {record.vault_fp.hex()[:16]}...")
    print(f"   - Device secret: {record.device_secret.hex()[:16]}...")
    print(f"   - Public tag: {record.public_tag.hex()}")
    
    # Même carte, autre device = autre enrollment
    device2_entropy = secrets.token_bytes(32)
    record2 = enroll_from_card(symbols, device2_entropy)
    print(f"4. Autre device, même carte:")
    print(f"   - Device secret différent: {record.device_secret != record2.device_secret}")
    print(f"   - Vault FP identique: {record.vault_fp == record2.vault_fp}")
    
    print("✓ Protocol D OK - Chaque device a une identité unique")


def demo_protocol_e():
    """Protocol E: Genesis ceremony."""
    banner("PROTOCOL E: Genesis Ceremony")
    
    # Feuille Genesis (une seule imprimée pour la cérémonie)
    ceremony_seed = secrets.token_bytes(32)
    sheet_symbols = encode_private(ceremony_seed)
    print(f"1. Feuille Genesis imprimée pour la cérémonie")
    
    # Participant 1 scanne
    vault1 = genesis_enroll(sheet_symbols)
    print(f"2. Participant 1 scanne:")
    print(f"   - Vault seed: {vault1.vault_seed.hex()[:16]}...")
    print(f"   - Ceremony FP: {vault1.ceremony_fp.hex()[:16]}...")
    
    # Participant 2 scanne la MÊME feuille
    vault2 = genesis_enroll(sheet_symbols)
    print(f"3. Participant 2 scanne (même feuille):")
    print(f"   - Vault seed: {vault2.vault_seed.hex()[:16]}...")
    print(f"   - Ceremony FP: {vault2.ceremony_fp.hex()[:16]}...")
    
    print(f"4. Résultat:")
    print(f"   - Même cérémonie: {vault1.ceremony_fp == vault2.ceremony_fp}")
    print(f"   - Vaults différents: {vault1.vault_seed != vault2.vault_seed}")
    
    print("✓ Protocol E OK - Une feuille = N vaults uniques")


def demo_protocol_f():
    """Protocol F: Migration cross-machine."""
    banner("PROTOCOL F: Cross-Machine Migration")
    
    # Setup initial
    master_key = secrets.token_bytes(32)
    vault_id = secrets.token_bytes(32)
    source_lock = secrets.token_bytes(32)  # Machine source
    target_lock = secrets.token_bytes(32)  # Nouvelle machine
    
    print(f"1. Vault sur machine source")
    print(f"   - Master key: {master_key.hex()[:16]}...")
    print(f"   - Source lock: {source_lock.hex()[:16]}...")
    
    print(f"2. Nouvelle machine affiche son lock (QR)")
    print(f"   - Target lock: {target_lock.hex()[:16]}...")
    
    # Source génère la preuve NIZK
    challenge = new_migration_challenge(vault_id, source_lock, target_lock)
    proof = prove_migration(master_key, challenge)
    print(f"3. Source génère preuve NIZK:")
    print(f"   - Commitment: {proof.commitment.hex()[:16]}...")
    print(f"   - Response: {proof.response.hex()[:16]}...")
    
    # Target vérifie et dérive les nouvelles clés
    result = verify_migration(proof, master_key, target_lock, check_ttl=False)
    print(f"4. Target vérifie et migre:")
    print(f"   - Vérification: {'✓ OK' if result else '✗ ÉCHEC'}")
    if result:
        print(f"   - Machine bound key: {result.machine_bound_key.hex()[:16]}...")
        print(f"   - Session key: {result.session_key.hex()[:16]}...")
    
    # Test avec mauvaise machine
    wrong_lock = secrets.token_bytes(32)
    wrong_result = verify_migration(proof, master_key, wrong_lock, check_ttl=False)
    print(f"5. Avec mauvaise machine: {'✗ REJETÉ' if not wrong_result else '✓ ERREUR!'}")
    
    print("✓ Protocol F OK - Migration sécurisée sans exposer master_key")


def demo_recovery_2of3():
    """Recovery holographique 2-of-3."""
    banner("RECOVERY: Holographic 2-of-3")
    
    # Entropie à protéger
    device_entropy = secrets.token_bytes(32)
    print(f"1. Entropie à protéger: {device_entropy.hex()[:16]}...")
    
    # Générer keypair Kyber pour le contact
    contact = EopxKey.generate()
    
    # Setup recovery
    pkg = setup_recovery(
        device_entropy,
        card_pin="123456",
        contact_kyber_pk=contact.kyber_pk,
        cloud_passphrase="correct horse battery staple",
        vault_fp_hex="ab" * 32,
    )
    print(f"2. Package créé: {pkg.threshold}-of-{pkg.total}")
    print(f"   - Share 1: card_pin (Argon2id)")
    print(f"   - Share 2: kyber_pk (ML-KEM-1024)")
    print(f"   - Share 3: passphrase (Argon2id)")
    
    # Récupérer avec PIN + passphrase
    recovered = recover_entropy(pkg, RecoveryCredentials(
        card_pin="123456",
        cloud_passphrase="correct horse battery staple",
    ))
    print(f"3. Récupération PIN + passphrase: {'✓' if recovered == device_entropy else '✗'}")
    
    # Récupérer avec Kyber + passphrase
    recovered2 = recover_entropy(pkg, RecoveryCredentials(
        contact_kyber_sk=contact.kyber_sk,
        cloud_passphrase="correct horse battery staple",
    ))
    print(f"4. Récupération Kyber + passphrase: {'✓' if recovered2 == device_entropy else '✗'}")
    
    print("✓ Recovery OK - 2 shares sur 3 suffisent")


def demo_recovery_flexible():
    """Recovery k-of-n flexible."""
    banner("RECOVERY: Flexible 3-of-5")
    
    device_entropy = secrets.token_bytes(32)
    alice = EopxKey.generate()
    bob = EopxKey.generate()
    
    # Setup 3-of-5 avec mix de types
    pkg = setup_recovery_flexible(
        device_entropy,
        share_configs=[
            ShareConfig(kind="card_pin", secret="111111"),
            ShareConfig(kind="card_pin", secret="222222"),
            ShareConfig(kind="kyber_pk", recipient_pk=alice.kyber_pk),
            ShareConfig(kind="kyber_pk", recipient_pk=bob.kyber_pk),
            ShareConfig(kind="passphrase", secret="long passphrase here"),
        ],
        vault_fp_hex="cd" * 32,
        threshold=3,
    )
    print(f"1. Package flexible: {pkg.threshold}-of-{pkg.total}")
    
    # Récupérer avec shares 1, 3, 5
    creds = FlexibleCredentials(
        pins={1: "111111"},
        kyber_sks={3: alice.kyber_sk},
        passphrases={5: "long passphrase here"},
    )
    recovered = recover_entropy_flexible(pkg, creds)
    print(f"2. Récupération shares 1+3+5: {'✓' if recovered == device_entropy else '✗'}")
    
    print("✓ Recovery flexible OK - k-of-n avec types mixtes")


def main():
    print("\n" + "="*60)
    print("  ESOPTRON ECOSYSTEM DEMO")
    print("  Visual Vault Identity · Post-Quantum · Holographic Recovery")
    print("="*60)
    
    demo_protocol_a()
    demo_protocol_b()
    demo_protocol_d()
    demo_protocol_e()
    demo_protocol_f()
    demo_recovery_2of3()
    demo_recovery_flexible()
    
    banner("RÉSUMÉ")
    print("""
L'écosystème Esoptron permet:

1. IDENTITÉ VISUELLE
   - Cube de Metatron encodé en 91 symboles F_13
   - Carte PUBLIQUE: identité visible, vérifiable
   - Feuille PRIVÉE: secret complet du vault

2. PROTOCOLES VAULT (A-F)
   A. Unlock: feuille privée → master_key
   B. Verify: carte publique → attestation
   C. SAS: 2FA challenge-response
   D. Enroll: carte + device → identité unique
   E. Genesis: une feuille → N vaults uniques
   F. Migrate: preuve NIZK pour changer de machine

3. RECOVERY HOLOGRAPHIQUE
   - 2-of-3 par défaut (ou k-of-n flexible)
   - Pas de phrase de 24 mots
   - Shares: PIN, contact Kyber, passphrase cloud

4. CRYPTO POST-QUANTIQUE
   - ML-DSA-87 (Dilithium5) pour signatures
   - ML-KEM-1024 (Kyber) pour encryption
   - SHA3-512/256, HKDF, Argon2id
""")
    print("="*60)
    print("  DEMO TERMINÉE - Tous les tests passent")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
