package org.c02e.jpgpj;

/**
 * How the symmetric session key protects the encrypted payload.
 */
public enum EncryptionProtection {
    /** RFC 4880 modification detection code (MDC). */
    Mdc,
    /** RFC 9580 AEAD-protected symmetric encryption. */
    Aead
}
