package org.c02e.jpgpj;

/**
 * AEAD packet layout version used when {@link EncryptionProtection#Aead} is selected.
 *
 * @since 2.1.0
 */
public enum AeadPacketStyle {
    /** OpenPGP v5 AEAD packet layout. */
    V5,
    /** OpenPGP v6 AEAD packet layout (GnuPG 2.4+ default for modern keys). */
    V6
}
