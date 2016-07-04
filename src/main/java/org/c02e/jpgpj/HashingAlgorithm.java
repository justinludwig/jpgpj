package org.c02e.jpgpj;

/**
 * Available hash algorithms for signing message content,
 * and for deriving a symmetric key from a passphrase.
 */
public enum HashingAlgorithm {
    Unsigned,
    MD5,
    SHA1,
    RIPEMD160,
    Reserved4,
    Reserved5,
    Reserved6,
    Reserved7,
    SHA256,
    SHA384,
    SHA512,
    SHA224;
}
