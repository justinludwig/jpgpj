package org.c02e.jpgpj;

/**
 * How the symmetric session key protects the encrypted payload.
 *
 * @since 2.1.0
 */
public enum EncryptionProtection {
    /** RFC 4880 modification detection code (MDC). */
    Mdc,
    /** RFC 9580 AEAD-protected symmetric encryption. */
    Aead
}
