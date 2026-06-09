package org.c02e.jpgpj;

/**
 * High-level interop preset analogous to GnuPG defaults for a given era.
 * Individual algorithm setters override profile defaults.
 */
public enum OpenPgpProfile {
    /**
     * RFC 4880 / gpg 2.2 era: AES128, MDC, SHA256 signing,
     * SHA512 iterated+salted S2K, ZLIB compression.
     */
    Classic,
    /**
     * RFC 9580 / gpg 2.4+ era: AES256, AEAD-OCB v6, SHA256 signing,
     * Argon2 S2K when passphrase-encrypting, ZLIB compression.
     */
    Modern
}
