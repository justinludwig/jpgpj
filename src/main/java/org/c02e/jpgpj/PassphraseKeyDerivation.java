package org.c02e.jpgpj;

/**
 * How a symmetric passphrase is stretched into a session key for encryption.
 */
public enum PassphraseKeyDerivation {
    /** Iterated+salted S2K with a hash algorithm and work factor (classic gpg). */
    IteratedSalted,
    /** Argon2 S2K (RFC 9580 / GnuPG 2.4+). */
    Argon2
}
